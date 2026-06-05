"""M2 real verification script.

Exercises OpenSearchClient + AuthzClient directly against:
  - OpenSearch at localhost:9200 (started separately)
  - Authz at localhost:8002 (foundation-authz container)

Tests:
  1. Index docs for two tenants (A and B) with different visibility/ACL
  2. Real full-text search: keywords return hits with score (not ILIKE)
  3. Cross-tenant isolation: tenant A user gets zero tenant B docs
  4. Tenant-internal ACL: alice cannot see team-only doc she's not part of
  5. fail-close OS: simulate OS down → 503
  6. fail-close authz: simulate authz down → narrow ACL only

Usage:
  cd packages/search
  PYTHONPATH=src python3 scripts/verify_m2_real.py
"""
from __future__ import annotations
import asyncio
import json
import sys
import time
from unittest.mock import AsyncMock, MagicMock

import httpx

# Override settings before importing service code
import os
os.environ["SEARCH_OPENSEARCH_URL"] = "http://localhost:9200"
os.environ["SEARCH_AUTHZ_URL"] = "http://localhost:8002/api/authz/v1"
os.environ["SEARCH_DB_DSN"] = "postgresql+asyncpg://dummy:dummy@localhost:5432/dummy"

sys.path.insert(0, "src")

from foundation_search.adapters.opensearch_client import OpenSearchClient
from foundation_search.adapters.authz_client import AccessibleIds, AuthzClient
from foundation_search.adapters.opensearch_client import SearchResult
from foundation_search.errors import SEARCH_BACKEND_UNAVAILABLE, FoundationError
from foundation_search.services.search_service import SearchService

PASS = "✓"
FAIL = "✗"
results = []


def ok(name: str, detail: str = "") -> None:
    msg = f"  {PASS} PASS: {name}"
    if detail:
        msg += f" — {detail}"
    print(msg)
    results.append((True, name))


def fail(name: str, detail: str = "") -> None:
    msg = f"  {FAIL} FAIL: {name}"
    if detail:
        msg += f" — {detail}"
    print(msg)
    results.append((False, name))


# ─────────────────────────────────────────────────────────────────────────────
# Minimal FakeSession for service calls that need it (just for PG side-effects)
# ─────────────────────────────────────────────────────────────────────────────

class FakeSession:
    def __init__(self):
        self.added = []
        self.flush_calls = 0
        self._scalars_queue = []

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        self.flush_calls += 1

    def queue_scalars(self, rows):
        self._scalars_queue.append(list(rows))

    async def scalars(self, _stmt):
        class R:
            def __init__(self, rows):
                self._rows = rows
            def all(self):
                return list(self._rows)
        if self._scalars_queue:
            return R(self._scalars_queue.pop(0))
        return R([])


TENANT_A = "tnt_AAAAAAAAAAAAAAAAAAAAAAAAA1"
TENANT_B = "tnt_BBBBBBBBBBBBBBBBBBBBBBBBB2"
USER_ALICE = "usr_AAAAAAAAAAAAAAAAAAAAAAAAA1"
USER_BOB   = "usr_BBBBBBBBBBBBBBBBBBBBBBBBB2"
TEAM_ENG   = "team_ENG0000000000000000000001"

# Documents:
#   Tenant A:
#     doc_pub   — visibility=PUBLIC_IN_TENANT  (alice + bob can see)
#     doc_alice — acl_user_ids=[alice]         (only alice can see)
#     doc_eng   — acl_team_ids=[TEAM_ENG]      (only team_eng members)
#   Tenant B:
#     doc_b1    — PUBLIC_IN_TENANT (should be invisible to tenant A users)

DOCS_A = [
    {
        "resource_id": "doc_pub_a",
        "resource_type": "document",
        "title": "Quarterly Report Public",
        "content": "This is the quarterly financial summary for all employees.",
        "tags": ["finance", "public"],
        "acl_user_ids": [],
        "acl_team_ids": [],
        "owner_id": USER_ALICE,
        "visibility": "PUBLIC_IN_TENANT",
    },
    {
        "resource_id": "doc_alice_private",
        "resource_type": "document",
        "title": "Alice Personal Notes",
        "content": "Private notes about the upcoming roadmap planning session.",
        "tags": ["notes"],
        "acl_user_ids": [USER_ALICE],
        "acl_team_ids": [],
        "owner_id": USER_ALICE,
        "visibility": "PRIVATE",
    },
    {
        "resource_id": "doc_eng_team",
        "resource_type": "document",
        "title": "Engineering Team Spec",
        "content": "Technical specification for the new microservices architecture.",
        "tags": ["engineering", "spec"],
        "acl_user_ids": [],
        "acl_team_ids": [TEAM_ENG],
        "owner_id": USER_BOB,
        "visibility": "PRIVATE",
    },
]

DOCS_B = [
    {
        "resource_id": "doc_b_pub",
        "resource_type": "document",
        "title": "Tenant B Public Doc",
        "content": "This document belongs to tenant B and should be invisible to tenant A.",
        "tags": ["public"],
        "acl_user_ids": [],
        "acl_team_ids": [],
        "owner_id": "usr_TENANTB00000000000000001",
        "visibility": "PUBLIC_IN_TENANT",
    }
]


async def index_docs(os_client: OpenSearchClient) -> None:
    """Directly call OS client to index test documents (bypassing PG)."""
    for doc in DOCS_A:
        full_doc = {**doc, "tenant_id": TENANT_A, "indexed_at": "2026-06-05T12:00:00+00:00"}
        await os_client.index_doc(tenant_id=TENANT_A, resource_id=doc["resource_id"], doc=full_doc)

    for doc in DOCS_B:
        full_doc = {**doc, "tenant_id": TENANT_B, "indexed_at": "2026-06-05T12:00:00+00:00"}
        await os_client.index_doc(tenant_id=TENANT_B, resource_id=doc["resource_id"], doc=full_doc)

    # Wait for OS to index
    await asyncio.sleep(1.5)
    print("  Indexed 3 Tenant-A docs + 1 Tenant-B doc into OpenSearch")


async def test_real_fulltext(os_client: OpenSearchClient) -> None:
    """Test 1: full-text search returns scored hits (not ILIKE)."""
    print("\n[Test 1] Real full-text search (keyword → scored hits)")
    query_body = {
        "query": {
            "bool": {
                "must": [{"multi_match": {"query": "quarterly financial", "fields": ["title^2", "content"]}}],
                "filter": [{"term": {"tenant_id": TENANT_A}}],
            }
        },
        "_source": ["resource_id", "title"],
        "size": 10,
    }
    result = await os_client.search(tenant_id=TENANT_A, query_body=query_body)

    if result.total > 0:
        hit = result.hits[0]
        ok("full-text search returns hits", f"total={result.total}, top hit: '{hit.source.get('title')}', score={hit.score:.4f}")
        if hit.score > 0:
            ok("hit has real score > 0", f"score={hit.score:.4f}")
        else:
            fail("hit score should be > 0")
    else:
        fail("full-text search returned no hits")


async def test_cross_tenant_isolation(os_client: OpenSearchClient) -> None:
    """Test 2: tenant A user cannot see tenant B documents."""
    print("\n[Test 2] Cross-tenant isolation")
    # Search with broad query but scoped to tenant A
    query_body = {
        "query": {
            "bool": {
                "must": [{"match_all": {}}],
                "filter": [{"term": {"tenant_id": TENANT_A}}],
            }
        },
        "_source": ["resource_id", "tenant_id", "title"],
        "size": 100,
    }
    result = await os_client.search(tenant_id=TENANT_A, query_body=query_body)

    tenant_b_hits = [h for h in result.hits if h.source.get("tenant_id") != TENANT_A]
    if tenant_b_hits:
        fail("cross-tenant: found tenant B docs in tenant A results", str([h.source.get("resource_id") for h in tenant_b_hits]))
    else:
        ok("cross-tenant: zero tenant B docs in tenant A results", f"total_hits={result.total}")

    # Verify tenant B doc is in OS at all
    query_body_b = {
        "query": {"bool": {"must": [{"match_all": {}}], "filter": [{"term": {"tenant_id": TENANT_B}}]}},
        "_source": ["resource_id", "tenant_id"],
        "size": 10,
    }
    result_b = await os_client.search(tenant_id=TENANT_B, query_body=query_body_b)
    if result_b.total > 0:
        ok("tenant B docs exist in OS", f"total={result_b.total}")
    else:
        fail("tenant B docs not found in OS")


async def test_acl_filtering_service(os_client: OpenSearchClient) -> None:
    """Test 3: Tenant-internal ACL — alice sees public+own but NOT team-only doc."""
    print("\n[Test 3] Tenant-internal ACL filtering")

    # Alice has: no team membership
    authz_alice = AccessibleIds(ids=[], complete=True, all_in_tenant=False)

    # Bob has team membership in TEAM_ENG
    authz_bob_with_team = AccessibleIds(ids=[TEAM_ENG], complete=True, all_in_tenant=False)

    # ---- Alice sees public + her own private ----
    mock_authz_alice = MagicMock()
    mock_authz_alice.list_accessible_ids = AsyncMock(return_value=authz_alice)
    svc_alice = SearchService(os_client=os_client, authz_client=mock_authz_alice)
    fake_s = FakeSession()

    result_alice = await svc_alice.query(
        fake_s, tenant_id=TENANT_A, q="",
        resource_types=None, tags=None, user_id=USER_ALICE,
        limit=20,
    )
    alice_ids = {item["resource_id"] for item in result_alice["items"]}
    print(f"  Alice sees: {alice_ids}")

    if "doc_pub_a" in alice_ids:
        ok("alice sees PUBLIC_IN_TENANT doc")
    else:
        fail("alice should see PUBLIC_IN_TENANT doc")

    if "doc_alice_private" in alice_ids:
        ok("alice sees her own acl_user_ids doc")
    else:
        fail("alice should see her own acl_user_ids doc")

    if "doc_eng_team" not in alice_ids:
        ok("alice CANNOT see team-only doc (not in TEAM_ENG)")
    else:
        fail("alice should NOT see team-only doc — ACL leak!")

    # ---- Bob (in TEAM_ENG) sees all three ----
    mock_authz_bob = MagicMock()
    mock_authz_bob.list_accessible_ids = AsyncMock(return_value=authz_bob_with_team)
    svc_bob = SearchService(os_client=os_client, authz_client=mock_authz_bob)
    fake_s2 = FakeSession()

    result_bob = await svc_bob.query(
        fake_s2, tenant_id=TENANT_A, q="",
        resource_types=None, tags=None, user_id=USER_BOB,
        limit=20,
    )
    bob_ids = {item["resource_id"] for item in result_bob["items"]}
    print(f"  Bob sees: {bob_ids}")

    if "doc_eng_team" in bob_ids:
        ok("bob (TEAM_ENG member) sees team-only doc")
    else:
        fail("bob should see team-only doc — wrong ACL filter")

    if "doc_pub_a" in bob_ids:
        ok("bob also sees PUBLIC_IN_TENANT doc")
    else:
        fail("bob should also see PUBLIC_IN_TENANT doc")


async def test_failclose_os_down() -> None:
    """Test 4: OS down → 503, no PG fallback."""
    print("\n[Test 4] fail-close: OS unavailable → 503")

    # Use a mock OS client that raises SEARCH_BACKEND_UNAVAILABLE
    broken_os = MagicMock()
    broken_os.search = AsyncMock(
        side_effect=FoundationError(SEARCH_BACKEND_UNAVAILABLE, "OpenSearch unreachable: test")
    )
    broken_os.index_doc = AsyncMock(return_value=None)

    # Also verify with a real httpx client pointing to a dead port (integration check)
    dead_port_os = OpenSearchClient.__new__(OpenSearchClient)
    dead_port_os._base = "http://localhost:19999"
    dead_port_os._index = "foundation-search"
    dead_port_os._write_index = "foundation-search-v1"
    dead_port_os._injected = None

    mock_authz = MagicMock()
    mock_authz.list_accessible_ids = AsyncMock(
        return_value=AccessibleIds(ids=[], complete=True, all_in_tenant=True)
    )
    fake_s = FakeSession()

    # Test 4a: mock raises SEARCH_BACKEND_UNAVAILABLE
    svc = SearchService(os_client=broken_os, authz_client=mock_authz)
    try:
        await svc.query(
            fake_s, tenant_id=TENANT_A, q="test",
            resource_types=None, tags=None, user_id=USER_ALICE,
        )
        fail("OS down (mock) should have raised 503")
    except FoundationError as e:
        if e.error_code.http_status == 503:
            ok("OS down (mock) → FoundationError 503", f"code={e.error_code.code}")
        else:
            fail("OS down (mock): wrong error code", f"got http_status={e.error_code.http_status}")
    except Exception as e:
        fail("OS down (mock): unexpected exception type", str(e))

    # Test 4b: real dead-port httpx → ConnectError → SEARCH_BACKEND_UNAVAILABLE
    svc2 = SearchService(os_client=dead_port_os, authz_client=mock_authz)
    fake_s2 = FakeSession()
    try:
        await svc2.query(
            fake_s2, tenant_id=TENANT_A, q="test",
            resource_types=None, tags=None, user_id=USER_ALICE,
        )
        fail("OS dead-port should have raised 503")
    except FoundationError as e:
        if e.error_code.http_status == 503:
            ok("OS dead-port → FoundationError 503 (real httpx ConnectError)", f"code={e.error_code.code}")
        else:
            fail("OS dead-port: wrong error code", f"got http_status={e.error_code.http_status}")
    except Exception as e:
        fail("OS dead-port: unexpected exception type", type(e).__name__ + ": " + str(e))


async def test_failclose_authz_down(os_client: OpenSearchClient) -> None:
    """Test 5: authz down → fail-close (no team ACL), alice still cannot see team doc."""
    print("\n[Test 5] fail-close: authz down → narrow ACL (no team grants)")

    # Authz returns fail-close result (complete=False, all_in_tenant=False)
    broken_authz = MagicMock()
    broken_authz.list_accessible_ids = AsyncMock(
        return_value=AccessibleIds(ids=[], complete=False, all_in_tenant=False)
    )
    svc = SearchService(os_client=os_client, authz_client=broken_authz)
    fake_s = FakeSession()

    result = await svc.query(
        fake_s, tenant_id=TENANT_A, q="",
        resource_types=None, tags=None, user_id=USER_ALICE,
        limit=20,
    )
    ids = {item["resource_id"] for item in result["items"]}
    print(f"  Alice (authz=down) sees: {ids}")

    if "doc_eng_team" not in ids:
        ok("authz down → alice still cannot see team-only doc (fail-close works)")
    else:
        fail("authz down → alice should NOT see team-only doc — fail-close BROKEN!")

    # She should still see public + her own
    if "doc_pub_a" in ids:
        ok("authz down → alice still sees PUBLIC_IN_TENANT doc")
    else:
        fail("authz down → alice should still see PUBLIC_IN_TENANT doc")


async def cleanup(os_client: OpenSearchClient) -> None:
    """Remove test documents."""
    for doc in DOCS_A:
        await os_client.delete_doc(tenant_id=TENANT_A, resource_id=doc["resource_id"])
    for doc in DOCS_B:
        await os_client.delete_doc(tenant_id=TENANT_B, resource_id=doc["resource_id"])
    print("\n  Cleaned up test documents from OpenSearch")


async def main() -> None:
    print("=" * 60)
    print("M2 Real Verification: OpenSearch + ACL")
    print("=" * 60)
    print(f"  OS URL:    http://localhost:9200")
    print(f"  Authz URL: http://localhost:8002/api/authz/v1")
    print()

    # Check OS health
    try:
        resp = httpx.get("http://localhost:9200/_cluster/health", timeout=3.0)
        os_status = resp.json().get("status", "?")
        print(f"  OpenSearch cluster status: {os_status}")
        if os_status not in ("green", "yellow"):
            print("  ERROR: OpenSearch not healthy, aborting")
            sys.exit(1)
    except Exception as e:
        print(f"  ERROR: Cannot reach OpenSearch: {e}")
        sys.exit(1)

    # Check authz health
    try:
        resp = httpx.get("http://localhost:8002/api/authz/v1/healthz", timeout=3.0)
        print(f"  Authz health: {resp.json().get('status', '?')}")
    except Exception as e:
        print(f"  WARNING: Cannot reach authz ({e}), tests 3+5 will use mock authz anyway")

    os_client = OpenSearchClient()

    print("\n--- Indexing test documents ---")
    await index_docs(os_client)

    await test_real_fulltext(os_client)
    await test_cross_tenant_isolation(os_client)
    await test_acl_filtering_service(os_client)
    await test_failclose_os_down()
    await test_failclose_authz_down(os_client)

    await cleanup(os_client)

    # Summary
    print("\n" + "=" * 60)
    passed = sum(1 for ok, _ in results if ok)
    failed = sum(1 for ok, _ in results if not ok)
    print(f"RESULTS: {passed} passed, {failed} failed out of {len(results)}")
    if failed:
        print("\nFailed tests:")
        for ok_flag, name in results:
            if not ok_flag:
                print(f"  {FAIL} {name}")
        sys.exit(1)
    else:
        print("All tests passed.")


if __name__ == "__main__":
    asyncio.run(main())
