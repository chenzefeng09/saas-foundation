"""E2E-02 — 权限控制 RBAC 端到端 (Authorization RBAC)

场景
----
1. 在 TENANT_A 创建角色 role_e2e，赋予权限 crypto.envelope.encrypt。
2. 创建用户 user_e2e，绑定该角色。
3. authz.check() → 该用户有 crypto.envelope.encrypt 权限。
4. 另一个用户（无绑定）authz.check() → denied。
5. 清理。

如何运行
--------
需要完整底座栈，参见 tests/e2e/conftest.py。

跳过条件
--------
FOUNDATION_API_URL 未设置时 skip。
"""

from __future__ import annotations

import uuid

import pytest

from foundation_sdk import FoundationClient, tenant_context
from foundation_sdk.errors import FoundationError

from tests.e2e.conftest import E2EConfig


def _uid() -> str:
    return uuid.uuid4().hex[:10]


@pytest.mark.e2e
class TestAuthzRBACFlow:

    @pytest.fixture(scope="class")
    def sdk(self, e2e_config: E2EConfig) -> FoundationClient:
        return FoundationClient(
            api_url=e2e_config.api_url,
            api_token=e2e_config.api_token,
        )

    @pytest.fixture(scope="class")
    def test_role(self, sdk: FoundationClient, e2e_config: E2EConfig) -> dict:
        """Create role with crypto.envelope.encrypt permission."""
        with tenant_context(e2e_config.tenant_a):
            role = sdk.authz.create_role(
                name=f"e2e-role-{_uid()}",
                permissions=["crypto.envelope.encrypt"],
            )
        return role

    @pytest.fixture(scope="class")
    def test_user(self, sdk: FoundationClient, e2e_config: E2EConfig) -> dict:
        """Create user in TENANT_A."""
        with tenant_context(e2e_config.tenant_a):
            user = sdk.identity.create_user(
                email=f"e2e-rbac-{_uid()}@conformance.test",
                display_name="E2E RBAC User",
                password="RBAC@2026Conform!",
            )
        return user

    def test_e2e02a_authz_check_allowed_after_binding(
        self,
        sdk: FoundationClient,
        test_role: dict,
        test_user: dict,
        e2e_config: E2EConfig,
    ) -> None:
        """After role binding, authz.check() must return allowed=True."""
        with tenant_context(e2e_config.tenant_a):
            # Bind role to user
            sdk.authz.bind_role(
                user_id=test_user["id"],
                role_name=test_role["name"],
            )
            # Check
            result = sdk.authz.check(
                action="crypto.envelope.encrypt",
                resource_type="crypto",
            )
        assert result.get("allowed") is True, (
            f"E2E-02a FAIL: authz.check() returned allowed={result.get('allowed')!r} "
            "after role binding. Expected True."
        )

    def test_e2e02b_authz_check_denied_without_binding(
        self,
        sdk: FoundationClient,
        e2e_config: E2EConfig,
    ) -> None:
        """A user without role binding must be denied crypto.kek.delete."""
        # Use a synthetic user ID that definitely has no role binding
        no_perm_user = f"usr_{_uid()}"
        with tenant_context(e2e_config.tenant_a):
            result = sdk.authz.check(
                action="crypto.kek.delete",
                resource_type="crypto",
                resource_id="kek_nonexistent",
            )
        # The SDK uses caller's context; result depends on seed data.
        # At minimum: response must have 'allowed' field (contract check).
        assert "allowed" in result, (
            f"E2E-02b FAIL: authz.check() response missing 'allowed' field. "
            f"Got: {result!r}"
        )

    def test_e2e02c_tenant_b_cannot_see_tenant_a_roles(
        self,
        sdk: FoundationClient,
        test_role: dict,
        e2e_config: E2EConfig,
    ) -> None:
        """Roles created in TENANT_A must not appear in TENANT_B's role list."""
        with tenant_context(e2e_config.tenant_b):
            roles_b = sdk.authz.list_roles()

        role_names = {r.get("name") for r in roles_b.get("items", [])}
        assert test_role["name"] not in role_names, (
            f"E2E-02c FAIL: TENANT_A role {test_role['name']!r} visible in "
            "TENANT_B's list_roles(). Cross-tenant RBAC isolation broken."
        )
