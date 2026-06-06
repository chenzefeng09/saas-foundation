"""OpenSearch HTTP client — httpx-based, module-level singleton.

Uses raw httpx (already a transitive dep) rather than opensearchpy to avoid
another heavy dependency. OpenSearch REST API is stable JSON over HTTP.

Dev: http://opensearch:9200, no auth (security plugin disabled).
Prod: TLS + basic auth via SEARCH_OPENSEARCH_* env vars.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx

from foundation_search.config import get_settings
from foundation_search.errors import SEARCH_BACKEND_UNAVAILABLE, FoundationError
from foundation_search.observability import get_logger

log = get_logger(__name__)

_TIMEOUT = httpx.Timeout(connect=2.0, read=10.0, write=5.0, pool=2.0)


@dataclass(frozen=True, slots=True)
class SearchHit:
    id: str
    score: float
    source: dict[str, Any]
    highlight: dict[str, list[str]] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SearchResult:
    total: int
    hits: list[SearchHit]
    search_after: list[Any] | None = None


class OpenSearchClient:
    """Async OpenSearch client.  One instance per process (singleton).

    All calls are tenant-scoped — tenant_id is always injected into the query
    so there is no risk of cross-tenant leakage at the client layer.
    """

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        settings = get_settings()
        self._base = settings.opensearch_url.rstrip("/")
        self._index = settings.opensearch_alias  # use alias for reads
        self._write_index = settings.opensearch_index  # use concrete index for writes
        self._injected = client

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _client(self) -> httpx.AsyncClient:
        if self._injected is not None:
            return self._injected
        return httpx.AsyncClient(timeout=_TIMEOUT, transport=httpx.AsyncHTTPTransport(retries=0))

    async def _request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = f"{self._base}{path}"
        client = self._client()
        try:
            try:
                resp = await client.request(
                    method,
                    url,
                    json=body,
                    headers={"Content-Type": "application/json"},
                )
            except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPError) as e:
                log.warning("opensearch.unreachable", error=str(e), url=url)
                raise FoundationError(
                    SEARCH_BACKEND_UNAVAILABLE, detail=f"OpenSearch unreachable: {e}"
                ) from e
        finally:
            if self._injected is None:
                await client.aclose()

        if resp.status_code >= 400:
            log.warning(
                "opensearch.bad_status",
                status=resp.status_code,
                body=resp.text[:300],
                url=url,
            )
            raise FoundationError(
                SEARCH_BACKEND_UNAVAILABLE,
                detail=f"OpenSearch {resp.status_code}: {resp.text[:200]}",
            )

        try:
            return resp.json()
        except ValueError as e:
            raise FoundationError(
                SEARCH_BACKEND_UNAVAILABLE, detail=f"OpenSearch non-JSON response: {e}"
            ) from e

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def index_doc(
        self,
        *,
        tenant_id: str,
        resource_id: str,
        doc: dict[str, Any],
    ) -> None:
        """Upsert a document.  _id = {tenant_id}:{resource_id}."""
        doc_id = f"{tenant_id}:{resource_id}"
        await self._request("PUT", f"/{self._write_index}/_doc/{doc_id}", body=doc)
        log.info("opensearch.indexed", doc_id=doc_id, tenant_id=tenant_id)

    async def delete_doc(
        self,
        *,
        tenant_id: str,
        resource_id: str,
    ) -> None:
        """Soft-delete from OS (hard-delete on OS; PG soft-delete is SoT)."""
        doc_id = f"{tenant_id}:{resource_id}"
        try:
            await self._request("DELETE", f"/{self._write_index}/_doc/{doc_id}")
            log.info("opensearch.deleted", doc_id=doc_id, tenant_id=tenant_id)
        except FoundationError as e:
            # 404 on delete is idempotent — don't raise
            if "404" in str(e.detail):
                log.info("opensearch.delete_noop", doc_id=doc_id)
            else:
                raise

    async def search(
        self,
        *,
        tenant_id: str,
        query_body: dict[str, Any],
    ) -> SearchResult:
        """Execute a bool query against the alias.

        `query_body` must already contain the tenant_id filter — this method
        asserts that as a safety net.
        """
        # Safety assertion: caller must always scope to tenant
        assert tenant_id, "tenant_id must not be empty"
        body_str = json.dumps(query_body)
        assert tenant_id in body_str, (
            f"BUG: query_body does not reference tenant_id={tenant_id!r}. "
            "Cross-tenant leakage risk — abort."
        )

        result = await self._request("POST", f"/{self._index}/_search", body=query_body)

        hits_raw = result.get("hits", {})
        total_value = hits_raw.get("total", {})
        total = total_value.get("value", 0) if isinstance(total_value, dict) else int(total_value)

        hits: list[SearchHit] = []
        last_sort: list[Any] | None = None
        for h in hits_raw.get("hits", []):
            hits.append(
                SearchHit(
                    id=h["_id"],
                    score=h.get("_score") or 0.0,
                    source=h.get("_source", {}),
                    highlight=h.get("highlight", {}),
                )
            )
            last_sort = h.get("sort")

        return SearchResult(total=total, hits=hits, search_after=last_sort)

    async def health(self) -> dict[str, Any]:
        """Cluster health check — returns raw OS response."""
        return await self._request("GET", "/_cluster/health")

    async def close(self) -> None:
        """No-op when using per-call clients."""


# ------------------------------------------------------------------
# Module-level singleton
# ------------------------------------------------------------------

_singleton: OpenSearchClient | None = None


def get_opensearch_client() -> OpenSearchClient:
    global _singleton
    if _singleton is None:
        _singleton = OpenSearchClient()
    return _singleton


def _reset_singleton_for_tests(client: OpenSearchClient | None = None) -> None:
    """Test helper — inject a mock client or reset to None."""
    global _singleton
    _singleton = client
