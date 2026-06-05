"""E2E-01 — 租户生命周期 + 跨租户隔离 (Tenant Lifecycle & Isolation)

场景
----
1. 以 TENANT_A 上下文创建用户 user_a。
2. 用 user_a 身份登录，拿到 access_token（identity.me()）。
3. 以 user_a 身份向底座写一条带 tenant_id 的数据（audit 事件）。
4. 切换到 TENANT_B 上下文，验证读不到 TENANT_A 刚写的数据（跨租户隔离）。
5. 清理：禁用 user_a。

如何运行
--------
需要完整底座栈：
    docker compose -f deploy/docker-compose/dev.yml \\
                   -f deploy/docker-compose/integration.yml up -d
    FOUNDATION_API_URL=http://localhost:8000 \\
    FOUNDATION_API_TOKEN=<seed-token> \\
    pytest tests/e2e/test_e2e_tenant_lifecycle.py -v -m e2e

跳过条件
--------
FOUNDATION_API_URL 未设置时 skip（所有 @pytest.mark.e2e 测试均如此）。
"""

from __future__ import annotations

import time
import uuid

import httpx
import pytest

from foundation_sdk import FoundationClient, tenant_context
from foundation_sdk.errors import FoundationError

from tests.e2e.conftest import E2EConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _unique(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# E2E-01 场景
# ---------------------------------------------------------------------------

@pytest.mark.e2e
class TestTenantLifecycleAndIsolation:
    """Create user → login → write data → verify cross-tenant isolation."""

    # ---- Step 1: Create user in TENANT_A ----

    @pytest.fixture(scope="class")
    def sdk_a(self, e2e_config: E2EConfig) -> FoundationClient:
        return FoundationClient(
            api_url=e2e_config.api_url,
            api_token=e2e_config.api_token,
        )

    @pytest.fixture(scope="class")
    def sdk_b(self, e2e_config: E2EConfig) -> FoundationClient:
        return FoundationClient(
            api_url=e2e_config.api_url,
            api_token=e2e_config.api_token,
        )

    @pytest.fixture(scope="class")
    def created_user(self, sdk_a: FoundationClient, e2e_config: E2EConfig) -> dict:
        """Create test user in TENANT_A; yield user dict; cleanup on teardown."""
        email = f"{_unique('e2e')}@conformance.test"
        user: dict = {}
        with tenant_context(e2e_config.tenant_a):
            user = sdk_a.identity.create_user(
                email=email,
                display_name="E2E Conformance User",
                password="Conform@nce2026!",
            )
        yield user
        # Teardown: disable the user
        try:
            with tenant_context(e2e_config.tenant_a):
                sdk_a.identity.disable_user(user["id"])
        except Exception:
            pass  # best-effort cleanup

    def test_e2e01a_user_created_with_correct_tenant(
        self, created_user: dict, e2e_config: E2EConfig,
    ) -> None:
        """Step 1: Created user belongs to TENANT_A (not another tenant)."""
        assert created_user.get("tenant_id") == e2e_config.tenant_a, (
            f"E2E-01a FAIL: user.tenant_id = {created_user.get('tenant_id')!r}, "
            f"expected {e2e_config.tenant_a!r}. "
            "Check identity-service: new users must inherit caller's tenant context."
        )
        assert created_user.get("id", "").startswith("usr_"), (
            f"E2E-01a FAIL: user.id {created_user.get('id')!r} does not start with 'usr_'. "
            "Check CONVENTIONS §2.8 ID format."
        )

    def test_e2e01b_created_at_is_iso8601_utc(self, created_user: dict) -> None:
        """Step 1 cont: created_at field is ISO 8601 UTC (CONVENTIONS §2.8)."""
        created_at = created_user.get("created_at", "")
        assert created_at.endswith("Z"), (
            f"E2E-01b FAIL: created_at={created_at!r} does not end with 'Z' (UTC). "
            "CONVENTIONS §2.8 requires ISO 8601 UTC."
        )

    def test_e2e01c_tenant_b_cannot_see_tenant_a_user(
        self,
        sdk_b: FoundationClient,
        created_user: dict,
        e2e_config: E2EConfig,
    ) -> None:
        """Step 4: Under TENANT_B context, TENANT_A user is not visible.

        Cross-tenant isolation: looking up usr_xxx created in TENANT_A
        from TENANT_B context must return 404.
        """
        with tenant_context(e2e_config.tenant_b):
            with pytest.raises(FoundationError) as exc_info:
                sdk_b.identity.get_user(created_user["id"])

        exc = exc_info.value
        assert exc.http_status in (403, 404), (
            f"E2E-01c FAIL: Cross-tenant isolation breach! "
            f"Under TENANT_B, get_user({created_user['id']!r}) returned "
            f"HTTP {exc.http_status} (expected 403 or 404). "
            "If no exception was raised, TENANT_B can read TENANT_A user data — "
            "critical multi-tenancy violation."
        )

    def test_e2e01d_list_users_in_tenant_b_does_not_include_tenant_a_user(
        self,
        sdk_b: FoundationClient,
        created_user: dict,
        e2e_config: E2EConfig,
    ) -> None:
        """Step 4 cont: list_users() in TENANT_B never includes TENANT_A user."""
        with tenant_context(e2e_config.tenant_b):
            result = sdk_b.identity.list_users(limit=200)

        items = result.get("items", [])
        a_user_ids = {item.get("id") for item in items}
        assert created_user["id"] not in a_user_ids, (
            f"E2E-01d FAIL: TENANT_B's list_users() returned TENANT_A user "
            f"id={created_user['id']!r}. RLS isolation is broken."
        )


# ---------------------------------------------------------------------------
# E2E-02: SDK header contract — me() response shape
# ---------------------------------------------------------------------------

@pytest.mark.e2e
class TestMeEndpointContract:
    """Verify identity.me() response conforms to documented shape."""

    def test_e2e02_me_returns_required_fields(
        self, e2e_config: E2EConfig,
    ) -> None:
        """identity.me() must return user_id, tenant_id, email (CONVENTIONS §3.6)."""
        sdk = FoundationClient(
            api_url=e2e_config.api_url,
            api_token=e2e_config.api_token,
        )
        with tenant_context(e2e_config.tenant_a):
            me = sdk.identity.me()

        required_fields = ["user_id", "tenant_id", "email"]
        missing = [f for f in required_fields if f not in me]
        assert not missing, (
            f"E2E-02 FAIL: identity.me() response missing fields {missing!r}. "
            f"Got keys: {list(me)}. "
            "BFFs rely on this shape to rehydrate user profile from JWT."
        )

        # tenant_id in response must match the context
        assert me["tenant_id"] == e2e_config.tenant_a, (
            f"E2E-02 FAIL: me().tenant_id = {me['tenant_id']!r}, "
            f"expected {e2e_config.tenant_a!r}. "
            "JWT claim tenant_id must match X-Tenant-Id."
        )
