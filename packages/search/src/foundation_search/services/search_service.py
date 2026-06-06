"""Search service — OpenSearch double-write + ACL-filtered query.

Architecture:
  - Postgres: source of truth (SoT). Always written first.
  - OpenSearch: search backend. Written after PG flush. Read for all queries.
  - Authz: ACL pre-filter via list_accessible_ids. fail-close on error.
  - OS unavailable → raise 503 (fail-close). Never fall back to PG ILIKE.
  - ACL: always enforced. all_in_tenant=True → tenant-only filter.
         otherwise: bool.should(owner/acl_user_ids/PUBLIC/acl_team_ids).
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

import ulid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_search.adapters.authz_client import AccessibleIds, AuthzClient, get_authz_client
from foundation_search.adapters.opensearch_client import OpenSearchClient, get_opensearch_client
from foundation_search.domain.models import Outbox, SearchIndex, SearchQueryLog
from foundation_search.errors import SEARCH_BACKEND_UNAVAILABLE, FoundationError
from foundation_search.observability import get_logger

log = get_logger(__name__)


class SearchService:
    """Search with automatic tenant isolation and ACL filtering."""

    def __init__(
        self,
        os_client: OpenSearchClient | None = None,
        authz_client: AuthzClient | None = None,
    ) -> None:
        self._os = os_client or get_opensearch_client()
        self._authz = authz_client or get_authz_client()

    # ------------------------------------------------------------------
    # index_resource — PG write (SoT) + OS double-write
    # ------------------------------------------------------------------

    async def index_resource(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        resource_type: str,
        resource_id: str,
        title: str,
        content: str,
        tags: list[str] | None,
        acl_user_ids: list[str] | None,
        acl_team_ids: list[str] | None = None,
        owner_id: str | None = None,
        visibility: str | None = None,
        metadata: dict[str, Any] | None,
        request_id: str,
    ) -> SearchIndex:
        """Index a resource.  PG is SoT; OS gets double-written after PG flush."""
        assert tenant_id, "tenant_id is required"

        content_hash = hashlib.sha256(content.encode()).hexdigest()[:32]
        idx = SearchIndex(
            id=f"idx_{ulid.new()!s}",
            tenant_id=tenant_id,
            resource_type=resource_type,
            resource_id=resource_id,
            title=title,
            content=content,
            content_hash=content_hash,
            tags=tags or [],
            acl_user_ids=acl_user_ids or [],
            acl_team_ids=acl_team_ids or [],
            owner_id=owner_id,
            visibility=visibility,
            metadata_json=metadata or {},
        )
        session.add(idx)
        self._emit(
            session, tenant_id, "foundation.search.indexed",
            {"resource_type": resource_type, "resource_id": resource_id}, request_id
        )
        # PG flush — establishes SoT before OS write
        await session.flush()

        # OS double-write — failure does NOT roll back PG.
        # Outbox already records the event; compensating relay is a future concern.
        # For now we propagate the error to make double-write failures visible.
        doc = {
            "tenant_id": tenant_id,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "title": title,
            "content": content,
            "tags": tags or [],
            "acl_user_ids": acl_user_ids or [],
            "acl_team_ids": acl_team_ids or [],
            "owner_id": owner_id,
            "visibility": visibility or "PRIVATE",
            "indexed_at": datetime.now(UTC).isoformat(),
        }
        try:
            await self._os.index_doc(
                tenant_id=tenant_id,
                resource_id=resource_id,
                doc=doc,
            )
        except FoundationError as e:
            log.error(
                "opensearch.index_failed.pg_ok",
                resource_id=resource_id,
                tenant_id=tenant_id,
                error=str(e),
            )
            raise

        return idx

    # ------------------------------------------------------------------
    # query — OS search with mandatory tenant + ACL filters
    # ------------------------------------------------------------------

    async def query(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        q: str,
        resource_types: list[str] | None,
        tags: list[str] | None,
        user_id: str | None,
        cursor: str | None = None,
        limit: int = 20,
    ) -> dict[str, Any]:
        """Full-text search via OpenSearch with tenant isolation + ACL pre-filter.

        OS unavailable → 503.  ACL authz unavailable → fail-close (narrow).
        """
        assert tenant_id, "tenant_id is required — cross-tenant leakage guard"

        # ------------------------------------------------------------------
        # 1. Build ACL filter clause
        # ------------------------------------------------------------------
        acl_filter = await self._build_acl_filter(
            tenant_id=tenant_id,
            user_id=user_id,
            resource_types=resource_types,
        )

        # ------------------------------------------------------------------
        # 2. Assemble OS bool query
        # ------------------------------------------------------------------
        filters: list[dict[str, Any]] = [
            {"term": {"tenant_id": tenant_id}},  # MANDATORY — never omitted
        ]

        if resource_types:
            filters.append({"terms": {"resource_type": resource_types}})

        if tags:
            filters.append({"terms": {"tags": tags}})

        if acl_filter is not None:
            filters.append(acl_filter)

        must: list[dict[str, Any]] = []
        if q:
            must.append({
                "multi_match": {
                    "query": q,
                    "fields": ["title^2", "content"],
                    "type": "best_fields",
                    "fuzziness": "AUTO",
                }
            })
        else:
            must.append({"match_all": {}})

        query_body: dict[str, Any] = {
            "query": {
                "bool": {
                    "must": must,
                    "filter": filters,
                }
            },
            "highlight": {
                "fields": {"title": {}, "content": {"fragment_size": 150, "number_of_fragments": 2}},
                "pre_tags": ["<mark>"],
                "post_tags": ["</mark>"],
            },
            "size": limit,
            "_source": ["resource_type", "resource_id", "title", "tags", "visibility", "indexed_at"],
        }

        # search_after pagination
        if cursor:
            try:
                import json as _json
                query_body["search_after"] = _json.loads(cursor)
            except Exception:
                pass  # invalid cursor → start from beginning

        # score-based sort + indexed_at for deterministic pagination
        query_body["sort"] = [{"_score": {"order": "desc"}}, {"indexed_at": {"order": "desc"}}]

        # ------------------------------------------------------------------
        # 3. Execute — fail-close on OS unavailability
        # ------------------------------------------------------------------
        try:
            result = await self._os.search(tenant_id=tenant_id, query_body=query_body)
        except FoundationError as e:
            if e.error_code == SEARCH_BACKEND_UNAVAILABLE:
                log.warning("search.os_unavailable", tenant_id=tenant_id, q=q)
                raise  # propagate 503 — no PG fallback
            raise

        # ------------------------------------------------------------------
        # 4. Build response + log query
        # ------------------------------------------------------------------
        items = []
        for hit in result.hits:
            src = hit.source
            item: dict[str, Any] = {
                "resource_type": src.get("resource_type"),
                "resource_id": src.get("resource_id"),
                "title": src.get("title"),
                "tags": src.get("tags", []),
                "indexed_at": src.get("indexed_at"),
                "score": hit.score,
            }
            if hit.highlight:
                item["highlight"] = hit.highlight
            items.append(item)

        next_cursor: str | None = None
        if result.search_after and len(result.hits) == limit:
            import json as _json
            next_cursor = _json.dumps(result.search_after)

        session.add(SearchQueryLog(
            id=f"sql_{ulid.new()!s}",
            tenant_id=tenant_id,
            query=q,
            user_id=user_id,
            result_count=result.total,
        ))

        return {
            "items": items,
            "next_cursor": next_cursor,
            "total_estimate": result.total,
        }

    # ------------------------------------------------------------------
    # deindex — PG soft-delete + OS hard-delete
    # ------------------------------------------------------------------

    async def deindex(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        resource_id: str,
        request_id: str,
    ) -> int:
        """Soft-delete in PG (SoT) + hard-delete in OS."""
        assert tenant_id, "tenant_id is required"

        rows = list((await session.scalars(
            select(SearchIndex).where(
                SearchIndex.tenant_id == tenant_id,
                SearchIndex.resource_id == resource_id,
                SearchIndex.deleted_at.is_(None),
            )
        )).all())

        now = datetime.now(UTC)
        for row in rows:
            row.deleted_at = now

        self._emit(
            session, tenant_id, "foundation.search.deindexed",
            {"resource_id": resource_id}, request_id
        )

        # OS delete — tolerate 404 (idempotent), propagate other errors
        try:
            await self._os.delete_doc(tenant_id=tenant_id, resource_id=resource_id)
        except FoundationError as e:
            log.error(
                "opensearch.delete_failed.pg_ok",
                resource_id=resource_id,
                tenant_id=tenant_id,
                error=str(e),
            )
            raise

        return len(rows)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _build_acl_filter(
        self,
        *,
        tenant_id: str,
        user_id: str | None,
        resource_types: list[str] | None,
    ) -> dict[str, Any] | None:
        """Build the ACL bool.filter clause.

        - user_id is None → no ACL filter (service-to-service call, trusted).
        - all_in_tenant=True → user has tenant-wide access, no ACL filter needed.
        - otherwise → inject should(visibility/owner/acl_user_ids/acl_team_ids).
        - fail-close: authz error or complete=False → narrow to user-only ACL,
          no team ids (never widen on failure).
        """
        if not user_id:
            # Trusted service call — no ACL restriction beyond tenant
            return None

        # Use the first resource_type for ACL lookup (or generic if multiple/none)
        resource_type = (resource_types[0] if resource_types and len(resource_types) == 1
                         else "document")

        acl: AccessibleIds = await self._authz.list_accessible_ids(
            tenant_id=tenant_id,
            user_id=user_id,
            resource_type=resource_type,
        )

        if acl.all_in_tenant:
            # User has tenant-wide visibility — only the tenant filter is needed
            log.debug("acl.all_in_tenant", user_id=user_id, tenant_id=tenant_id)
            return None

        # Build should clauses.
        # On fail-close (complete=False) we omit team_ids to never over-grant.
        should: list[dict[str, Any]] = [
            {"term": {"visibility": "PUBLIC_IN_TENANT"}},
            {"term": {"acl_user_ids": user_id}},
            {"term": {"owner_id": user_id}},
        ]

        if acl.complete and acl.ids:
            # Authz returned a complete set of team IDs → safe to add
            should.append({"terms": {"acl_team_ids": acl.ids}})
        elif not acl.complete:
            log.warning(
                "acl.incomplete.fail_close",
                user_id=user_id,
                tenant_id=tenant_id,
                ids_count=len(acl.ids),
            )
            # Intentionally NOT adding team ACL filter — fail-close means narrow

        return {
            "bool": {
                "should": should,
                "minimum_should_match": 1,
            }
        }

    def _emit(
        self,
        session: AsyncSession,
        tenant_id: str,
        event_type: str,
        payload: dict[str, Any],
        request_id: str,
    ) -> None:
        session.add(Outbox(
            tenant_id=tenant_id,
            event_type=event_type,
            aggregate_id=payload.get("resource_id", ""),
            payload=payload,
            request_id=request_id,
        ))
