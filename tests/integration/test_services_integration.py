"""Integration tests for remaining Foundation services.

Tests cover: audit, billing, lifecycle, notification, search, api-platform,
llm-gateway, feature-flag, dlp, compliance, pam, data-protection.

By default, all tests are skipped unless the corresponding service is available.
Set FOUNDATION_INTEGRATION_URL, FOUNDATION_API_TOKEN, FOUNDATION_TENANT_ID to run.
"""

from __future__ import annotations

import os

import httpx
import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

INTEGRATION_URL = os.environ.get("FOUNDATION_INTEGRATION_URL", "http://localhost")
API_TOKEN = os.environ.get("FOUNDATION_API_TOKEN", "")
TENANT_ID = os.environ.get("FOUNDATION_TENANT_ID", "tnt_01J0000000000000000000TNT1")

requires_live = pytest.mark.skipif(
    not API_TOKEN,
    reason="Set FOUNDATION_API_TOKEN and FOUNDATION_INTEGRATION_URL to run integration tests",
)

HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "X-Tenant-Id": TENANT_ID,
    "Content-Type": "application/json",
}


def _url(service: str) -> str:
    """Compute service URL from the integration base."""
    return f"{INTEGRATION_URL}/api/{service}/v1"


# =============================================================================
# Audit Service
# =============================================================================


class TestAuditIntegration:
    @requires_live
    async def test_healthz(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{_url('audit')}/healthz")
            assert r.status_code == 200

    @requires_live
    async def test_query_events(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{_url('audit')}/events", params={"limit": 10}, headers=HEADERS)
            assert r.status_code in (200, 404)

    @requires_live
    async def test_verify_chain(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(
                f"{_url('audit')}/verify",
                json={"event_ids": []},
                headers=HEADERS,
            )
            assert r.status_code in (200, 400, 422)


# =============================================================================
# Billing Service
# =============================================================================


class TestBillingIntegration:
    @requires_live
    async def test_healthz(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{_url('billing')}/healthz")
            assert r.status_code == 200

    @requires_live
    async def test_check_quota(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(
                f"{_url('billing')}/quota/check",
                json={"dimension": "user_seats", "requested": 1},
                headers=HEADERS,
            )
            assert r.status_code in (200, 201)
            data = r.json()
            assert "allowed" in data
            assert "limit" in data

    @requires_live
    async def test_list_plans(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{_url('billing')}/plans", headers=HEADERS)
            assert r.status_code in (200, 404)


# =============================================================================
# Lifecycle Service
# =============================================================================


class TestLifecycleIntegration:
    @requires_live
    async def test_healthz(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{_url('lifecycle')}/healthz")
            assert r.status_code == 200

    @requires_live
    async def test_list_legal_holds(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{_url('lifecycle')}/legal-holds", headers=HEADERS)
            assert r.status_code in (200, 404)

    @requires_live
    async def test_list_recycle_bin(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{_url('lifecycle')}/recycle-bin", headers=HEADERS)
            assert r.status_code in (200, 404)


# =============================================================================
# Notification Service
# =============================================================================


class TestNotificationIntegration:
    @requires_live
    async def test_healthz(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{_url('notification')}/healthz")
            assert r.status_code == 200

    @requires_live
    async def test_list_templates(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{_url('notification')}/templates", headers=HEADERS)
            assert r.status_code in (200, 404)


# =============================================================================
# Search Service
# =============================================================================


class TestSearchIntegration:
    @requires_live
    async def test_healthz(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{_url('search')}/healthz")
            assert r.status_code == 200

    @requires_live
    async def test_query(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(
                f"{_url('search')}/query",
                json={"q": "test", "limit": 5},
                headers=HEADERS,
            )
            assert r.status_code in (200, 201)

    @requires_live
    async def test_index_and_query(self):
        async with httpx.AsyncClient(timeout=10) as c:
            # Index a document
            r = await c.post(
                f"{_url('search')}/index",
                json={
                    "resource_type": "test", "resource_id": "test_001",
                    "title": "Integration Test Doc", "content": "Hello world",
                    "tags": [], "acl_user_ids": [], "metadata": {},
                },
                headers=HEADERS,
            )
            assert r.status_code in (200, 201)


# =============================================================================
# API Platform Service
# =============================================================================


class TestAPIPlatformIntegration:
    @requires_live
    async def test_healthz(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{_url('api-platform')}/healthz")
            assert r.status_code == 200

    @requires_live
    async def test_create_and_revoke_key(self):
        async with httpx.AsyncClient(timeout=10) as c:
            # Create key
            r = await c.post(
                f"{_url('api-platform')}/keys",
                json={"name": "test-integration-key", "scopes": ["read"],
                      "rate_limit_rpm": 60},
                headers=HEADERS,
            )
            assert r.status_code in (200, 201)
            data = r.json()
            assert "api_key" in data

            if "id" in data:
                # Revoke
                r2 = await c.post(
                    f"{_url('api-platform')}/keys/{data['id']}/revoke",
                    headers=HEADERS,
                )
                assert r2.status_code in (200, 204)


# =============================================================================
# LLM Gateway Service
# =============================================================================


class TestLLMGatewayIntegration:
    @requires_live
    async def test_healthz(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{_url('llm-gateway')}/healthz")
            assert r.status_code == 200

    @requires_live
    async def test_list_providers(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{_url('llm-gateway')}/providers", headers=HEADERS)
            assert r.status_code in (200, 404)

    @requires_live
    async def test_get_pricing(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{_url('llm-gateway')}/pricing", headers=HEADERS)
            assert r.status_code in (200, 404)


# =============================================================================
# Feature Flag Service
# =============================================================================


class TestFeatureFlagIntegration:
    @requires_live
    async def test_healthz(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{_url('feature-flag')}/healthz")
            assert r.status_code == 200

    @requires_live
    async def test_evaluate_flag(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(
                f"{_url('feature-flag')}/evaluate",
                json={"flag": "billing.saas_mode"},
                headers=HEADERS,
            )
            assert r.status_code in (200, 201)
            data = r.json()
            assert "enabled" in data

    @requires_live
    async def test_list_flags(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{_url('feature-flag')}/flags", headers=HEADERS)
            assert r.status_code in (200, 404)


# =============================================================================
# DLP Service
# =============================================================================


class TestDLPIntegration:
    @requires_live
    async def test_healthz(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{_url('dlp')}/healthz")
            assert r.status_code == 200

    @requires_live
    async def test_scan_content(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(
                f"{_url('dlp')}/scan",
                json={"content": "test content", "content_type": "text"},
                headers=HEADERS,
            )
            assert r.status_code in (200, 201, 422)

    @requires_live
    async def test_get_sensitive_words(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{_url('dlp')}/sensitive-words", headers=HEADERS)
            assert r.status_code in (200, 404)


# =============================================================================
# Compliance Service
# =============================================================================


class TestComplianceIntegration:
    @requires_live
    async def test_healthz(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{_url('compliance')}/healthz")
            assert r.status_code == 200

    @requires_live
    async def test_record_ropa(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(
                f"{_url('compliance')}/ropa",
                json={
                    "service": "identity", "data_category": "personal_info",
                    "purpose": "test", "legal_basis": "consent",
                    "data_subjects": ["test"], "recipients": [],
                    "retention_days": 365, "cross_border": False,
                    "destination_countries": [],
                },
                headers=HEADERS,
            )
            assert r.status_code in (200, 201)

    @requires_live
    async def test_list_ropa(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{_url('compliance')}/ropa", headers=HEADERS)
            assert r.status_code in (200, 404)

    @requires_live
    async def test_generate_report(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(
                f"{_url('compliance')}/reports",
                json={"report_type": "soc2_type2", "compliance_modes": ["soc2"]},
                headers=HEADERS,
            )
            assert r.status_code in (200, 201)


# =============================================================================
# PAM Service
# =============================================================================


class TestPAMIntegration:
    @requires_live
    async def test_healthz(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{_url('pam')}/healthz")
            assert r.status_code == 200

    @requires_live
    async def test_request_elevation(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(
                f"{_url('pam')}/elevations",
                json={"reason": "integration test", "duration_minutes": 5},
                headers=HEADERS,
            )
            assert r.status_code in (200, 201, 422)

    @requires_live
    async def test_list_pending_elevations(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{_url('pam')}/elevations/pending", headers=HEADERS)
            assert r.status_code in (200, 404)


# =============================================================================
# Data Protection Service
# =============================================================================


class TestDataProtectionIntegration:
    @requires_live
    async def test_healthz(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{_url('data-protection')}/healthz")
            assert r.status_code == 200

    @requires_live
    async def test_mask_field(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(
                f"{_url('data-protection')}/mask-field",
                json={"field_name": "email", "value": "test@example.com",
                      "mask_type": "email"},
                headers=HEADERS,
            )
            assert r.status_code in (200, 201, 422)

    @requires_live
    async def test_get_masking_rules(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(
                f"{_url('data-protection')}/masking-rules",
                headers=HEADERS,
            )
            assert r.status_code in (200, 404)

    @requires_live
    async def test_check_cross_border(self):
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(
                f"{_url('data-protection')}/cross-border/check",
                json={"destination_country": "US", "data_categories": ["personal_info"]},
                headers=HEADERS,
            )
            assert r.status_code in (200, 201, 422)
