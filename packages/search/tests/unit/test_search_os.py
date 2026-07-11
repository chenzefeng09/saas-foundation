"""Unit tests for M2 OpenSearch + ACL integration.

Tests:
  - query_body always contains term tenant_id
  - ACL should-clause injection (user-scoped)
  - all_in_tenant=True → no ACL filter beyond tenant
  - fail-close: authz down → narrow (no team ACL, still user/owner/PUBLIC)
  - fail-close: OS down → 503
  - index double-write: PG row created + OS index_doc called
  - deindex: PG soft-delete + OS delete_doc called
  - resource_types filter injected
  - tags filter injected
  - search_after cursor round-trip
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from foundation_search.adapters.authz_client import AccessibleIds
from foundation_search.adapters.opensearch_client import SearchHit, SearchResult
from foundation_search.domain.models import SearchIndex, SearchQueryLog
from foundation_search.errors import ACCESS_DENIED, SEARCH_BACKEND_UNAVAILABLE, FoundationError
from foundation_search.services.search_service import SearchService


TENANT_A = "tnt_AAAAAAAAAAAAAAAAAAAAAAAAA1"
TENANT_B = "tnt_BBBBBBBBBBBBBBBBBBBBBBBBB2"
USER_ALICE = "usr_AAAAAAAAAAAAAAAAAAAAAAAAA1"
USER_BOB = "usr_BBBBBBBBBBBBBBBBBBBBBBBBB2"
TEAM_ENG = "team_ENG0000000000000000000001"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_svc(
    os_result: SearchResult | None = None,
    os_raises: Exception | None = None,
    authz_result: AccessibleIds | None = None,
    authz_raises: Exception | None = None,
    user_clearance: str = "L3",
    resource_sensitivity: str = "L3",
) -> tuple[SearchService, AsyncMock, AsyncMock]:
    """Return (svc, mock_os, mock_authz)."""
    mock_os = MagicMock()
    mock_authz = MagicMock()
    mock_security = MagicMock()
    mock_security.get_resource_sensitivity = AsyncMock(return_value=resource_sensitivity)
    mock_security.get_user_clearance = AsyncMock(return_value=user_clearance)

    if os_raises is not None:
        mock_os.search = AsyncMock(side_effect=os_raises)
    else:
        mock_os.search = AsyncMock(return_value=os_result or _empty_result())

    mock_os.index_doc = AsyncMock(return_value=None)
    mock_os.delete_doc = AsyncMock(return_value=None)

    if authz_raises is not None:
        mock_authz.list_accessible_ids = AsyncMock(side_effect=authz_raises)
    else:
        mock_authz.list_accessible_ids = AsyncMock(
            return_value=authz_result or AccessibleIds(ids=[], complete=True, all_in_tenant=False)
        )

    svc = SearchService(
        os_client=mock_os,
        authz_client=mock_authz,
        security_attributes_client=mock_security,
    )
    return svc, mock_os, mock_authz


def _empty_result(total: int = 0) -> SearchResult:
    return SearchResult(total=total, hits=[], search_after=None)


def _hit(resource_id: str, score: float = 1.0, **src_extra: Any) -> SearchHit:
    src = {
        "resource_type": "document",
        "resource_id": resource_id,
        "title": f"Title {resource_id}",
        "tags": [],
        "indexed_at": "2026-06-05T00:00:00+00:00",
        **src_extra,
    }
    return SearchHit(id=f"{TENANT_A}:document:{resource_id}", score=score, source=src)


def _stage_sot_rows(
    session: FakeAsyncSession,
    hits: list[SearchHit],
    *,
    visibility: str = "PUBLIC_IN_TENANT",
    owner_id: str | None = None,
    acl_user_ids: list[str] | None = None,
    acl_team_ids: list[str] | None = None,
) -> list[SearchIndex]:
    rows = [
        SearchIndex(
            id=f"idx_sot_{position}",
            tenant_id=TENANT_A,
            resource_type=hit.source["resource_type"],
            resource_id=hit.source["resource_id"],
            title=hit.source["title"],
            content="current content",
            content_hash="hash",
            tags=hit.source.get("tags", []),
            acl_user_ids=acl_user_ids or [],
            acl_team_ids=acl_team_ids or [],
            owner_id=owner_id,
            visibility=visibility,
            metadata_json={},
        )
        for position, hit in enumerate(hits)
    ]
    session.queue_scalars(rows)
    return rows


# ---------------------------------------------------------------------------
# FakeAsyncSession (reuse from conftest, but self-contained here for clarity)
# ---------------------------------------------------------------------------

from tests.conftest import FakeAsyncSession  # noqa: E402


# ---------------------------------------------------------------------------
# P2: index_resource double-write
# ---------------------------------------------------------------------------


class TestIndexDoubleWrite:
    async def test_pg_row_created(self, fake_session: FakeAsyncSession) -> None:
        svc, mock_os, _ = _make_svc()
        idx = await svc.index_resource(
            fake_session,
            tenant_id=TENANT_A,
            resource_type="document",
            resource_id="doc_001",
            title="Privacy Policy",
            content="This is the privacy policy.",
            tags=["legal"],
            acl_user_ids=[USER_ALICE],
            acl_team_ids=[TEAM_ENG],
            owner_id=USER_ALICE,
            visibility="PRIVATE",
            metadata={"version": "1"},
            request_id="req_001",
        )
        assert isinstance(idx, SearchIndex)
        assert idx.tenant_id == TENANT_A
        assert idx.resource_id == "doc_001"
        assert fake_session.flush_calls == 1

    async def test_os_index_doc_called(self, fake_session: FakeAsyncSession) -> None:
        svc, mock_os, _ = _make_svc()
        await svc.index_resource(
            fake_session,
            tenant_id=TENANT_A,
            resource_type="document",
            resource_id="doc_002",
            title="T",
            content="C",
            tags=None,
            acl_user_ids=None,
            metadata=None,
            request_id="req_002",
        )
        mock_os.index_doc.assert_called_once()
        call_kwargs = mock_os.index_doc.call_args.kwargs
        assert call_kwargs["tenant_id"] == TENANT_A
        assert call_kwargs["resource_id"] == "doc_002"
        doc = call_kwargs["doc"]
        assert doc["tenant_id"] == TENANT_A
        assert doc["resource_id"] == "doc_002"

    async def test_os_doc_contains_acl_fields(self, fake_session: FakeAsyncSession) -> None:
        svc, mock_os, _ = _make_svc()
        await svc.index_resource(
            fake_session,
            tenant_id=TENANT_A,
            resource_type="doc",
            resource_id="doc_acl",
            title="ACL Doc",
            content="content",
            tags=["t1"],
            acl_user_ids=[USER_ALICE],
            acl_team_ids=[TEAM_ENG],
            owner_id=USER_BOB,
            visibility="PUBLIC_IN_TENANT",
            metadata=None,
            request_id="r1",
        )
        doc = mock_os.index_doc.call_args.kwargs["doc"]
        assert doc["acl_user_ids"] == [USER_ALICE]
        assert doc["acl_team_ids"] == [TEAM_ENG]
        assert doc["owner_id"] == USER_BOB
        assert doc["visibility"] == "PUBLIC_IN_TENANT"
        assert doc["sensitivity"] == "L3"
        assert doc["sensitivity_rank"] == 3

    async def test_os_failure_propagates(self, fake_session: FakeAsyncSession) -> None:
        """OS write failure after PG flush raises — PG row already committed."""
        svc, mock_os, _ = _make_svc()
        mock_os.index_doc = AsyncMock(
            side_effect=FoundationError(SEARCH_BACKEND_UNAVAILABLE, "OS down")
        )
        with pytest.raises(FoundationError) as exc_info:
            await svc.index_resource(
                fake_session,
                tenant_id=TENANT_A,
                resource_type="doc",
                resource_id="doc_fail",
                title="X",
                content="Y",
                tags=None,
                acl_user_ids=None,
                metadata=None,
                request_id="r2",
            )
        assert exc_info.value.error_code == SEARCH_BACKEND_UNAVAILABLE
        # PG flush still happened
        assert fake_session.flush_calls == 1


# ---------------------------------------------------------------------------
# P2: query body construction
# ---------------------------------------------------------------------------


class TestQueryBody:
    async def test_tenant_id_always_in_filters(self, fake_session: FakeAsyncSession) -> None:
        svc, mock_os, _ = _make_svc(
            authz_result=AccessibleIds(ids=[], complete=True, all_in_tenant=True),
        )
        await svc.query(
            fake_session,
            tenant_id=TENANT_A,
            q="hello",
            resource_types=None,
            tags=None,
            user_id=USER_ALICE,
            actor="USER",
        )
        body = mock_os.search.call_args.kwargs["query_body"]
        filters = body["query"]["bool"]["filter"]
        tenant_filter = [f for f in filters if f.get("term", {}).get("tenant_id") == TENANT_A]
        assert len(tenant_filter) == 1, "tenant_id filter must always be present"

    async def test_clearance_filter_always_injected(self, fake_session: FakeAsyncSession) -> None:
        svc, mock_os, _ = _make_svc(
            authz_result=AccessibleIds(ids=[], complete=True, all_in_tenant=True),
        )
        await svc.query(
            fake_session,
            tenant_id=TENANT_A,
            q="classified",
            resource_types=None,
            tags=None,
            user_id=USER_ALICE,
            actor="USER",
        )
        filters = mock_os.search.call_args.kwargs["query_body"]["query"]["bool"]["filter"]
        assert {"range": {"sensitivity_rank": {"lte": 3}}} in filters

    async def test_live_dlp_recheck_blocks_stale_index_hit(
        self, fake_session: FakeAsyncSession
    ) -> None:
        stale_hit = _hit("doc_reclassified", sensitivity="L3", sensitivity_rank=3)
        svc, _, _ = _make_svc(
            os_result=SearchResult(total=1, hits=[stale_hit], search_after=None),
            authz_result=AccessibleIds(ids=[], complete=True, all_in_tenant=True),
            user_clearance="L3",
            resource_sensitivity="L4",
        )
        _stage_sot_rows(fake_session, [stale_hit])
        result = await svc.query(
            fake_session,
            tenant_id=TENANT_A,
            q="secret",
            resource_types=None,
            tags=None,
            user_id=USER_ALICE,
            actor="USER",
        )
        assert result["items"] == []
        assert result["total_estimate"] == 0

    async def test_resource_types_filter(self, fake_session: FakeAsyncSession) -> None:
        svc, mock_os, _ = _make_svc(
            authz_result=AccessibleIds(ids=[], complete=True, all_in_tenant=True),
        )
        await svc.query(
            fake_session,
            tenant_id=TENANT_A,
            q="x",
            resource_types=["document", "note"],
            tags=None,
            user_id=USER_ALICE,
            actor="USER",
        )
        body = mock_os.search.call_args.kwargs["query_body"]
        filters = body["query"]["bool"]["filter"]
        type_filter = [f for f in filters if "terms" in f and "resource_type" in f["terms"]]
        assert len(type_filter) == 1
        assert set(type_filter[0]["terms"]["resource_type"]) == {"document", "note"}

    async def test_tags_filter(self, fake_session: FakeAsyncSession) -> None:
        svc, mock_os, _ = _make_svc(
            authz_result=AccessibleIds(ids=[], complete=True, all_in_tenant=True),
        )
        await svc.query(
            fake_session,
            tenant_id=TENANT_A,
            q="",
            resource_types=None,
            tags=["legal", "finance"],
            user_id=USER_ALICE,
            actor="USER",
        )
        body = mock_os.search.call_args.kwargs["query_body"]
        filters = body["query"]["bool"]["filter"]
        tag_filter = [f for f in filters if "terms" in f and "tags" in f["terms"]]
        assert len(tag_filter) == 1
        assert set(tag_filter[0]["terms"]["tags"]) == {"legal", "finance"}

    async def test_multi_match_on_nonempty_q(self, fake_session: FakeAsyncSession) -> None:
        svc, mock_os, _ = _make_svc(
            authz_result=AccessibleIds(ids=[], complete=True, all_in_tenant=True),
        )
        await svc.query(
            fake_session,
            tenant_id=TENANT_A,
            q="policy",
            resource_types=None,
            tags=None,
            user_id=USER_ALICE,
            actor="USER",
        )
        body = mock_os.search.call_args.kwargs["query_body"]
        must = body["query"]["bool"]["must"]
        mm = [m for m in must if "multi_match" in m]
        assert len(mm) == 1
        assert mm[0]["multi_match"]["query"] == "policy"
        assert "title^2" in mm[0]["multi_match"]["fields"]

    async def test_search_after_cursor_parsed(self, fake_session: FakeAsyncSession) -> None:
        svc, mock_os, _ = _make_svc(
            authz_result=AccessibleIds(ids=[], complete=True, all_in_tenant=True),
        )
        cursor = json.dumps([0.9, "2026-06-05T00:00:00+00:00"])
        await svc.query(
            fake_session,
            tenant_id=TENANT_A,
            q="",
            resource_types=None,
            tags=None,
            user_id=USER_ALICE,
            actor="USER",
            cursor=cursor,
        )
        body = mock_os.search.call_args.kwargs["query_body"]
        assert body.get("search_after") == [0.9, "2026-06-05T00:00:00+00:00"]

    async def test_next_cursor_returned_when_full_page(self, fake_session: FakeAsyncSession) -> None:
        hits = [_hit(f"doc_{i}") for i in range(5)]
        svc, mock_os, _ = _make_svc(
            os_result=SearchResult(total=100, hits=hits, search_after=[0.5, "2026-01-01T00:00:00"]),
            authz_result=AccessibleIds(ids=[], complete=True, all_in_tenant=True),
        )
        _stage_sot_rows(fake_session, hits)
        result = await svc.query(
            fake_session,
            tenant_id=TENANT_A,
            q="",
            resource_types=None,
            tags=None,
            user_id=USER_ALICE,
            actor="USER",
            limit=5,
        )
        assert result["next_cursor"] is not None
        # cursor should be a valid JSON list
        parsed = json.loads(result["next_cursor"])
        assert isinstance(parsed, list)

    async def test_no_next_cursor_when_partial_page(self, fake_session: FakeAsyncSession) -> None:
        hits = [_hit("doc_1")]
        svc, mock_os, _ = _make_svc(
            os_result=SearchResult(total=1, hits=hits, search_after=None),
            authz_result=AccessibleIds(ids=[], complete=True, all_in_tenant=True),
        )
        _stage_sot_rows(fake_session, hits)
        result = await svc.query(
            fake_session,
            tenant_id=TENANT_A,
            q="",
            resource_types=None,
            tags=None,
            user_id=USER_ALICE,
            actor="USER",
            limit=20,
        )
        assert result["next_cursor"] is None


# ---------------------------------------------------------------------------
# P3: ACL filter injection
# ---------------------------------------------------------------------------


class TestACLFilter:
    async def test_all_in_tenant_no_acl_filter(self, fake_session: FakeAsyncSession) -> None:
        """all_in_tenant=True → no ACL should-clause beyond tenant filter."""
        svc, mock_os, _ = _make_svc(
            authz_result=AccessibleIds(ids=[], complete=True, all_in_tenant=True),
        )
        await svc.query(
            fake_session, tenant_id=TENANT_A, q="x",
            resource_types=None, tags=None, user_id=USER_ALICE,
            actor="USER",
        )
        body = mock_os.search.call_args.kwargs["query_body"]
        filters = body["query"]["bool"]["filter"]
        # Should have tenant filter only (no should-clause filter)
        bool_should_filters = [f for f in filters if "bool" in f and "should" in f["bool"]]
        assert len(bool_should_filters) == 0

    async def test_regular_user_acl_filter_injected(self, fake_session: FakeAsyncSession) -> None:
        """Regular user: should-clause with visibility/owner/acl_user_ids."""
        svc, mock_os, _ = _make_svc(
            authz_result=AccessibleIds(ids=[TEAM_ENG], complete=True, all_in_tenant=False),
        )
        await svc.query(
            fake_session, tenant_id=TENANT_A, q="x",
            resource_types=None, tags=None, user_id=USER_ALICE,
            actor="USER",
        )
        body = mock_os.search.call_args.kwargs["query_body"]
        filters = body["query"]["bool"]["filter"]
        bool_should_filters = [f for f in filters if "bool" in f and "should" in f["bool"]]
        assert len(bool_should_filters) == 1
        should = bool_should_filters[0]["bool"]["should"]

        # Must include visibility=PUBLIC_IN_TENANT
        public_clauses = [s for s in should if s.get("term", {}).get("visibility") == "PUBLIC_IN_TENANT"]
        assert len(public_clauses) == 1

        # Must include acl_user_ids=user_id
        user_clauses = [s for s in should if s.get("term", {}).get("acl_user_ids") == USER_ALICE]
        assert len(user_clauses) == 1

        # Must include owner_id=user_id
        owner_clauses = [s for s in should if s.get("term", {}).get("owner_id") == USER_ALICE]
        assert len(owner_clauses) == 1

        # Must include team_ids when complete=True
        team_clauses = [s for s in should if "terms" in s and "acl_team_ids" in s["terms"]]
        assert len(team_clauses) == 1
        assert TEAM_ENG in team_clauses[0]["terms"]["acl_team_ids"]

    async def test_fail_close_authz_down(self, fake_session: FakeAsyncSession) -> None:
        """authz unreachable → fail-close: no team ACL, but visibility/owner/user still present."""
        svc, mock_os, _ = _make_svc(
            authz_result=AccessibleIds(ids=[], complete=False, all_in_tenant=False),
        )
        await svc.query(
            fake_session, tenant_id=TENANT_A, q="x",
            resource_types=None, tags=None, user_id=USER_ALICE,
            actor="USER",
        )
        body = mock_os.search.call_args.kwargs["query_body"]
        filters = body["query"]["bool"]["filter"]
        bool_should_filters = [f for f in filters if "bool" in f and "should" in f["bool"]]
        assert len(bool_should_filters) == 1
        should = bool_should_filters[0]["bool"]["should"]

        # visibility + owner + acl_user_ids still present
        public_clauses = [s for s in should if s.get("term", {}).get("visibility") == "PUBLIC_IN_TENANT"]
        assert len(public_clauses) == 1

        # NO team ACL on fail-close
        team_clauses = [s for s in should if "terms" in s and "acl_team_ids" in s["terms"]]
        assert len(team_clauses) == 0, "fail-close must NOT add team ACL filter"

    async def test_no_user_id_no_acl_filter(self, fake_session: FakeAsyncSession) -> None:
        """Service-to-service call (no user_id) → no ACL filter beyond tenant."""
        svc, mock_os, mock_authz = _make_svc(
            authz_result=AccessibleIds(ids=[], complete=True, all_in_tenant=False),
        )
        await svc.query(
            fake_session, tenant_id=TENANT_A, q="x",
            resource_types=None, tags=None, user_id=None,
            actor="SERVICE",
        )
        # authz must NOT be called for service-to-service
        mock_authz.list_accessible_ids.assert_not_called()
        body = mock_os.search.call_args.kwargs["query_body"]
        filters = body["query"]["bool"]["filter"]
        bool_should_filters = [f for f in filters if "bool" in f and "should" in f["bool"]]
        assert len(bool_should_filters) == 0

    async def test_fail_close_os_unavailable_raises_503(self, fake_session: FakeAsyncSession) -> None:
        """OS unreachable → FoundationError with 503 status, never falls back to PG."""
        svc, mock_os, _ = _make_svc(
            os_raises=FoundationError(SEARCH_BACKEND_UNAVAILABLE, "OS down"),
            authz_result=AccessibleIds(ids=[], complete=True, all_in_tenant=True),
        )
        with pytest.raises(FoundationError) as exc_info:
            await svc.query(
                fake_session, tenant_id=TENANT_A, q="test",
                resource_types=None, tags=None, user_id=USER_ALICE,
                actor="USER",
            )
        assert exc_info.value.error_code.http_status == 503
        assert exc_info.value.error_code == SEARCH_BACKEND_UNAVAILABLE

    async def test_query_logs_search(self, fake_session: FakeAsyncSession) -> None:
        """query() always adds a SearchQueryLog entry."""
        hits = [_hit("doc_1")]
        svc, _, _ = _make_svc(
            os_result=SearchResult(total=1, hits=hits, search_after=None),
            authz_result=AccessibleIds(ids=[], complete=True, all_in_tenant=True),
        )
        _stage_sot_rows(fake_session, hits)
        await svc.query(
            fake_session, tenant_id=TENANT_A, q="test",
            resource_types=None, tags=None, user_id=USER_ALICE,
            actor="USER",
        )
        log_entries = [a for a in fake_session.added if isinstance(a, SearchQueryLog)]
        assert len(log_entries) == 1
        assert log_entries[0].query == "test"
        assert log_entries[0].result_count == 1

    async def test_items_contain_score(self, fake_session: FakeAsyncSession) -> None:
        """Response items must include score (from OS)."""
        hits = [_hit("doc_1", score=0.98)]
        svc, _, _ = _make_svc(
            os_result=SearchResult(total=1, hits=hits, search_after=None),
            authz_result=AccessibleIds(ids=[], complete=True, all_in_tenant=True),
        )
        _stage_sot_rows(fake_session, hits)
        result = await svc.query(
            fake_session, tenant_id=TENANT_A, q="test",
            resource_types=None, tags=None, user_id=USER_ALICE,
            actor="USER",
        )
        assert result["items"][0]["score"] == pytest.approx(0.98)

    async def test_minimum_should_match_1(self, fake_session: FakeAsyncSession) -> None:
        """ACL should-clause must have minimum_should_match=1."""
        svc, mock_os, _ = _make_svc(
            authz_result=AccessibleIds(ids=[], complete=True, all_in_tenant=False),
        )
        await svc.query(
            fake_session, tenant_id=TENANT_A, q="x",
            resource_types=None, tags=None, user_id=USER_ALICE,
            actor="USER",
        )
        body = mock_os.search.call_args.kwargs["query_body"]
        filters = body["query"]["bool"]["filter"]
        bool_should_filters = [f for f in filters if "bool" in f and "should" in f["bool"]]
        acl_clause = bool_should_filters[0]["bool"]
        assert acl_clause.get("minimum_should_match") == 1


# ---------------------------------------------------------------------------
# P2: deindex
# ---------------------------------------------------------------------------


class TestDeindex:
    async def test_pg_soft_delete_and_os_delete(self, fake_session: FakeAsyncSession) -> None:
        row = SearchIndex(
            id="idx_1", tenant_id=TENANT_A,
            resource_type="document", resource_id="doc_del",
            title="T", content="C", content_hash="x",
            tags=[], acl_user_ids=[], acl_team_ids=[],
            metadata_json={},
        )
        fake_session.queue_scalars([row])

        svc, mock_os, _ = _make_svc()
        count = await svc.deindex(
            fake_session,
            tenant_id=TENANT_A,
            resource_id="doc_del",
            request_id="r_del",
        )
        assert count == 1
        assert row.deleted_at is not None
        mock_os.delete_doc.assert_called_once_with(tenant_id=TENANT_A, resource_id="doc_del")

    async def test_os_delete_failure_propagates(self, fake_session: FakeAsyncSession) -> None:
        row = SearchIndex(
            id="idx_2", tenant_id=TENANT_A,
            resource_type="document", resource_id="doc_fail",
            title="T", content="C", content_hash="x",
            tags=[], acl_user_ids=[], acl_team_ids=[],
            metadata_json={},
        )
        fake_session.queue_scalars([row])

        svc, mock_os, _ = _make_svc()
        mock_os.delete_doc = AsyncMock(
            side_effect=FoundationError(SEARCH_BACKEND_UNAVAILABLE, "OS down")
        )
        with pytest.raises(FoundationError):
            await svc.deindex(
                fake_session,
                tenant_id=TENANT_A,
                resource_id="doc_fail",
                request_id="r_fail",
            )
        # PG soft-delete still happened
        assert row.deleted_at is not None


# ---------------------------------------------------------------------------
# OpenSearch client assertion test (tenant in body)
# ---------------------------------------------------------------------------


class TestOpenSearchClientTenantAssertion:
    async def test_search_without_tenant_in_body_raises(self) -> None:
        """OS client must assert tenant_id is in query body."""
        from foundation_search.adapters.opensearch_client import OpenSearchClient

        mock_http = AsyncMock()
        # Patch _request to avoid real HTTP
        with patch.object(OpenSearchClient, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {"hits": {"total": {"value": 0}, "hits": []}}
            client = OpenSearchClient()
            client._injected = MagicMock()  # prevent real http

            # Body that does NOT reference the tenant_id
            bad_body = {"query": {"match_all": {}}}
            with pytest.raises(AssertionError, match="BUG"):
                await client.search(tenant_id=TENANT_A, query_body=bad_body)

    async def test_empty_tenant_id_raises(self) -> None:
        from foundation_search.adapters.opensearch_client import OpenSearchClient
        client = OpenSearchClient()
        with pytest.raises(AssertionError):
            await client.search(tenant_id="", query_body={})
