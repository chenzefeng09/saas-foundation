"""Tests for Search service — index, query, ACL filtering.

Updated for M2: SearchService now requires os_client + authz_client.
Tests verify PG-level behavior (row creation, hash, fields).
OS/ACL behavior is covered in test_search_os.py.
"""

import hashlib
from unittest.mock import AsyncMock, MagicMock

import pytest

from foundation_search.adapters.authz_client import AccessibleIds
from foundation_search.adapters.opensearch_client import SearchHit, SearchResult
from foundation_search.domain.models import SearchIndex, SearchQueryLog
from foundation_search.services.search_service import SearchService


def _make_svc(
    total: int = 0,
    hits: list[SearchHit] | None = None,
    all_in_tenant: bool = True,
) -> SearchService:
    mock_os = MagicMock()
    mock_os.index_doc = AsyncMock(return_value=None)
    mock_os.delete_doc = AsyncMock(return_value=None)
    mock_os.search = AsyncMock(
        return_value=SearchResult(total=total, hits=hits or [], search_after=None)
    )
    mock_authz = MagicMock()
    mock_authz.list_accessible_ids = AsyncMock(
        return_value=AccessibleIds(ids=[], complete=True, all_in_tenant=all_in_tenant)
    )
    return SearchService(os_client=mock_os, authz_client=mock_authz)


def _hit(resource_id: str, title: str, score: float = 1.0) -> SearchHit:
    return SearchHit(
        id=f"tnt:{resource_id}",
        score=score,
        source={
            "resource_type": "document",
            "resource_id": resource_id,
            "title": title,
            "tags": [],
            "indexed_at": "2026-06-05T00:00:00+00:00",
        },
    )


class TestSearchIndex:
    async def test_index_resource(self, fake_session, tenant_id, request_id):
        svc = _make_svc()
        idx = await svc.index_resource(
            fake_session, tenant_id=tenant_id, resource_type="document",
            resource_id="doc_001", title="Privacy Policy",
            content="This is the privacy policy for our platform...",
            tags=["legal", "privacy"], acl_user_ids=["usr_001", "usr_002"],
            metadata={"version": "2.1"}, request_id=request_id,
        )
        assert isinstance(idx, SearchIndex)
        assert idx.id.startswith("idx_")
        assert idx.tenant_id == tenant_id
        assert idx.resource_type == "document"
        assert idx.resource_id == "doc_001"
        assert idx.title == "Privacy Policy"
        assert "privacy" in idx.content

        # Content hash should be SHA-256 first 16 bytes hex
        expected_hash = hashlib.sha256(idx.content.encode()).hexdigest()[:32]
        assert idx.content_hash == expected_hash

        assert "legal" in idx.tags
        assert "usr_001" in idx.acl_user_ids
        assert idx.metadata_json["version"] == "2.1"

    async def test_index_resource_minimal(self, fake_session, tenant_id, request_id):
        svc = _make_svc()
        idx = await svc.index_resource(
            fake_session, tenant_id=tenant_id, resource_type="note",
            resource_id="note_001", title="Quick Note",
            content="Hello world",
            tags=None, acl_user_ids=None, metadata=None,
            request_id=request_id,
        )
        assert idx.tags == []
        assert idx.acl_user_ids == []
        assert idx.metadata_json == {}


class TestSearchQuery:
    async def test_query_basic(self, fake_session, tenant_id, request_id):
        hits = [_hit("doc_001", "Privacy Policy"), _hit("doc_002", "Terms of Service")]
        svc = _make_svc(total=2, hits=hits)

        result = await svc.query(
            fake_session, tenant_id=tenant_id, q="privacy",
            resource_types=None, tags=None, user_id=None,
            cursor=None, limit=20,
        )
        assert "items" in result
        titles = [item["title"] for item in result["items"]]
        assert "Privacy Policy" in titles
        assert result["next_cursor"] is None

    async def test_query_tag_filter(self, fake_session, tenant_id, request_id):
        hits = [_hit("doc_001", "Doc A")]
        svc = _make_svc(total=1, hits=hits)

        result = await svc.query(
            fake_session, tenant_id=tenant_id, q="",
            resource_types=None, tags=["legal"], user_id=None,
            cursor=None, limit=20,
        )
        titles = [item["title"] for item in result["items"]]
        assert "Doc A" in titles

    async def test_query_pagination(self, fake_session, tenant_id, request_id):
        # OS returns 5 items, limit=3 → but OS handles pagination via search_after
        # With our new service, limit is passed to OS directly.
        # Simulate: 5 total but only 3 returned in this page
        from foundation_search.adapters.opensearch_client import SearchResult
        mock_os = MagicMock()
        mock_os.search = AsyncMock(return_value=SearchResult(
            total=5,
            hits=[_hit(f"doc_{i}", f"Doc {i}") for i in range(3)],
            search_after=[0.5, "2026-01-01"],
        ))
        mock_authz = MagicMock()
        mock_authz.list_accessible_ids = AsyncMock(
            return_value=AccessibleIds(ids=[], complete=True, all_in_tenant=True)
        )
        svc = SearchService(os_client=mock_os, authz_client=mock_authz)

        result = await svc.query(
            fake_session, tenant_id=tenant_id, q="",
            resource_types=None, tags=None, user_id=None,
            cursor=None, limit=3,
        )
        assert len(result["items"]) == 3
        assert result["next_cursor"] is not None

    async def test_query_empty(self, fake_session, tenant_id, request_id):
        svc = _make_svc(total=0, hits=[])

        result = await svc.query(
            fake_session, tenant_id=tenant_id, q="nothing",
            resource_types=None, tags=None, user_id=None,
            cursor=None, limit=20,
        )
        assert result["items"] == []
        assert result["total_estimate"] == 0

    async def test_query_logs_search(self, fake_session, tenant_id, request_id):
        """Every query should create a SearchQueryLog entry."""
        svc = _make_svc(total=1, hits=[_hit("doc_1", "Test")])

        await svc.query(
            fake_session, tenant_id=tenant_id, q="test",
            resource_types=None, tags=None, user_id="usr_001",
            cursor=None, limit=20,
        )
        log_entries = [a for a in fake_session.added if isinstance(a, SearchQueryLog)]
        assert len(log_entries) == 1
        assert log_entries[0].query == "test"
        assert log_entries[0].user_id == "usr_001"

    async def test_query_acl_filter(self, fake_session, tenant_id, request_id):
        """ACL filtering: OS is responsible — service passes ACL filter into query body.
        Only Public Doc is returned (simulated by OS mock returning only that hit).
        """
        hits = [_hit("doc_001", "Public Doc")]
        svc = _make_svc(total=1, hits=hits, all_in_tenant=False)

        result = await svc.query(
            fake_session, tenant_id=tenant_id, q="Doc",
            resource_types=None, tags=None, user_id="usr_regular",
            cursor=None, limit=20,
        )
        titles = [item["title"] for item in result["items"]]
        assert "Public Doc" in titles

    async def test_query_acl_admin(self, fake_session, tenant_id, request_id):
        """Admin with all_in_tenant=True sees everything OS returns."""
        hits = [_hit("doc_001", "Public Doc"), _hit("doc_002", "Secret Doc")]
        svc = _make_svc(total=2, hits=hits, all_in_tenant=True)

        result = await svc.query(
            fake_session, tenant_id=tenant_id, q="Doc",
            resource_types=None, tags=None, user_id="usr_admin",
            cursor=None, limit=20,
        )
        titles = [item["title"] for item in result["items"]]
        assert "Public Doc" in titles
        assert "Secret Doc" in titles
