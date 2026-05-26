"""Tests for Search service — index, query, ACL filtering."""

import hashlib

import pytest

from foundation_search.services.search_service import SearchService
from foundation_search.domain.models import SearchIndex, SearchQueryLog


class TestSearchIndex:
    @pytest.fixture
    def svc(self):
        return SearchService()

    async def test_index_resource(self, svc, fake_session, tenant_id, request_id):
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

    async def test_index_resource_minimal(self, svc, fake_session, tenant_id, request_id):
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
    @pytest.fixture
    def svc(self):
        return SearchService()

    async def test_query_basic(self, svc, fake_session, tenant_id, request_id):
        r1 = SearchIndex(
            id="idx_1", tenant_id=tenant_id,
            resource_type="document", resource_id="doc_001",
            title="Privacy Policy", content="This is about privacy and data.",
            content_hash="abc", tags=[], acl_user_ids=[], metadata_json={},
        )
        r2 = SearchIndex(
            id="idx_2", tenant_id=tenant_id,
            resource_type="document", resource_id="doc_002",
            title="Terms of Service", content="These are the terms of service.",
            content_hash="def", tags=[], acl_user_ids=[], metadata_json={},
        )
        fake_session.queue_scalars([r1, r2])

        result = await svc.query(
            fake_session, tenant_id=tenant_id, q="privacy",
            resource_types=None, tags=None, user_id=None,
            cursor=None, limit=20,
        )
        assert "items" in result
        # Postgres ILIKE should match r1 (privacy)
        titles = [item["title"] for item in result["items"]]
        assert "Privacy Policy" in titles
        assert result["next_cursor"] is None  # Only 1 match, no more pages

    async def test_query_tag_filter(self, svc, fake_session, tenant_id, request_id):
        r1 = SearchIndex(
            id="idx_1", tenant_id=tenant_id,
            resource_type="document", resource_id="doc_001",
            title="Doc A", content="content a",
            content_hash="a", tags=["legal"], acl_user_ids=[], metadata_json={},
        )
        r2 = SearchIndex(
            id="idx_2", tenant_id=tenant_id,
            resource_type="document", resource_id="doc_002",
            title="Doc B", content="content b",
            content_hash="b", tags=["engineering"], acl_user_ids=[], metadata_json={},
        )
        # Only enqueue r1 — FakeAsyncSession doesn't apply WHERE, so we pre-filter
        fake_session.queue_scalars([r1])

        result = await svc.query(
            fake_session, tenant_id=tenant_id, q="",
            resource_types=None, tags=["legal"], user_id=None,
            cursor=None, limit=20,
        )
        titles = [item["title"] for item in result["items"]]
        assert "Doc A" in titles

    async def test_query_acl_filter(self, svc, fake_session, tenant_id, request_id):
        r1 = SearchIndex(
            id="idx_1", tenant_id=tenant_id,
            resource_type="document", resource_id="doc_001",
            title="Public Doc", content="public content",
            content_hash="a", tags=[], acl_user_ids=[], metadata_json={},  # No ACL = visible to all
        )
        r2 = SearchIndex(
            id="idx_2", tenant_id=tenant_id,
            resource_type="document", resource_id="doc_002",
            title="Secret Doc", content="secret content",
            content_hash="b", tags=[], acl_user_ids=["usr_admin"], metadata_json={},
        )
        fake_session.queue_scalars([r1, r2])

        result = await svc.query(
            fake_session, tenant_id=tenant_id, q="Doc",
            resource_types=None, tags=None, user_id="usr_regular",
            cursor=None, limit=20,
        )
        titles = [item["title"] for item in result["items"]]
        # Regular user should see Public Doc (no ACL restriction) but not Secret Doc
        assert "Public Doc" in titles
        assert "Secret Doc" not in titles

    async def test_query_acl_admin(self, svc, fake_session, tenant_id, request_id):
        r1 = SearchIndex(
            id="idx_1", tenant_id=tenant_id,
            resource_type="document", resource_id="doc_001",
            title="Public Doc", content="public content",
            content_hash="a", tags=[], acl_user_ids=[], metadata_json={},
        )
        r2 = SearchIndex(
            id="idx_2", tenant_id=tenant_id,
            resource_type="document", resource_id="doc_002",
            title="Secret Doc", content="secret content",
            content_hash="b", tags=[], acl_user_ids=["usr_admin"], metadata_json={},
        )
        fake_session.queue_scalars([r1, r2])

        result = await svc.query(
            fake_session, tenant_id=tenant_id, q="Doc",
            resource_types=None, tags=None, user_id="usr_admin",
            cursor=None, limit=20,
        )
        titles = [item["title"] for item in result["items"]]
        # Admin should see both
        assert "Public Doc" in titles
        assert "Secret Doc" in titles

    async def test_query_pagination(self, svc, fake_session, tenant_id, request_id):
        # Create 5 documents
        indices = [
            SearchIndex(
                id=f"idx_{i}", tenant_id=tenant_id,
                resource_type="document", resource_id=f"doc_00{i}",
                title=f"Document {i}", content=f"content {i}",
                content_hash="x", tags=[], acl_user_ids=[], metadata_json={},
            )
            for i in range(5)
        ]
        fake_session.queue_scalars(indices)

        result = await svc.query(
            fake_session, tenant_id=tenant_id, q="",
            resource_types=None, tags=None, user_id=None,
            cursor=None, limit=3,
        )
        assert len(result["items"]) == 3
        assert result["next_cursor"] is not None  # More results available

    async def test_query_empty(self, svc, fake_session, tenant_id, request_id):
        fake_session.queue_scalars([])

        result = await svc.query(
            fake_session, tenant_id=tenant_id, q="nothing",
            resource_types=None, tags=None, user_id=None,
            cursor=None, limit=20,
        )
        assert result["items"] == []
        assert result["total_estimate"] == 0

    async def test_query_logs_search(self, svc, fake_session, tenant_id, request_id):
        """Every query should create a SearchQueryLog entry."""
        r1 = SearchIndex(
            id="idx_1", tenant_id=tenant_id,
            resource_type="doc", resource_id="r1",
            title="Test", content="test content",
            content_hash="x", tags=[], acl_user_ids=[], metadata_json={},
        )
        fake_session.queue_scalars([r1])

        await svc.query(
            fake_session, tenant_id=tenant_id, q="test",
            resource_types=None, tags=None, user_id="usr_001",
            cursor=None, limit=20,
        )
        # Check a SearchQueryLog was added
        log_entries = [a for a in fake_session.added if isinstance(a, SearchQueryLog)]
        assert len(log_entries) == 1
        assert log_entries[0].query == "test"
        assert log_entries[0].user_id == "usr_001"
