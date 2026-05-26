"""Integration tests for Authz Service — requires Postgres + OPA.

Tests RBAC authorization flow:
  1. List permissions (seed data)
  2. Create role with permissions
  3. Create role binding
  4. Check permission (RBAC path)
  5. Check permission denied (no binding)
"""

from __future__ import annotations

import httpx
import pytest


class TestPermissions:
    async def test_list_permissions(
        self, client: httpx.AsyncClient, endpoints, tenant,
    ) -> None:
        r = await client.get(
            f"{endpoints.authz}/permissions",
            headers=tenant.headers,
        )
        assert r.status_code == 200
        perms = r.json()
        assert isinstance(perms, list)


class TestRoles:
    @pytest.fixture(scope="class")
    async def test_role(self, client: httpx.AsyncClient, endpoints, tenant) -> dict:
        payload = {
            "name": "integration-tester",
            "display_name": "Integration Tester",
            "description": "Role for integration test suite",
            "permissions": ["crypto.envelope.encrypt", "crypto.envelope.decrypt"],
        }
        r = await client.post(
            f"{endpoints.authz}/roles",
            json=payload,
            headers=tenant.headers,
        )
        assert r.status_code == 201, f"Create role failed: {r.text}"
        data = r.json()
        assert data["name"] == "integration-tester"
        assert "crypto.envelope.encrypt" in data["permissions"]
        return data

    async def test_get_role(
        self, client: httpx.AsyncClient, endpoints, tenant, test_role: dict,
    ) -> None:
        r = await client.get(
            f"{endpoints.authz}/roles/{test_role['id']}",
            headers=tenant.headers,
        )
        assert r.status_code == 200
        assert r.json()["name"] == "integration-tester"

    async def test_list_roles(
        self, client: httpx.AsyncClient, endpoints, tenant,
    ) -> None:
        r = await client.get(
            f"{endpoints.authz}/roles",
            headers=tenant.headers,
        )
        assert r.status_code == 200
        assert len(r.json()["items"]) >= 1


class TestBindings:
    @pytest.fixture(scope="class")
    async def bound_role(self, client: httpx.AsyncClient, endpoints, tenant) -> dict:
        # Create role
        role_resp = await client.post(
            f"{endpoints.authz}/roles",
            json={
                "name": "integration-bound",
                "display_name": "Integration Bound",
                "permissions": ["crypto.envelope.encrypt"],
            },
            headers=tenant.headers,
        )
        assert role_resp.status_code == 201
        role = role_resp.json()

        # Create binding
        bind_resp = await client.post(
            f"{endpoints.authz}/bindings",
            json={
                "principal_kind": "USER",
                "principal_id": tenant.user_id,
                "role_id": role["id"],
                "scope_kind": "TENANT",
                "grant_reason": "Integration test",
            },
            headers=tenant.headers,
        )
        assert bind_resp.status_code == 201, f"Create binding failed: {bind_resp.text}"
        return {"role": role, "binding": bind_resp.json()}

    async def test_check_allowed(
        self, client: httpx.AsyncClient, endpoints, tenant, bound_role: dict,
    ) -> None:
        r = await client.post(
            f"{endpoints.authz}/check",
            json={
                "user_id": tenant.user_id,
                "action": "crypto.envelope.encrypt",
                "resource_type": "crypto",
                "resource_id": "kek_test",
            },
            headers=tenant.headers,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["allowed"] is True
        assert data["decision_path"] in ("RBAC_HIT", "OPA_HIT")

    async def test_check_denied(
        self, client: httpx.AsyncClient, endpoints, tenant,
    ) -> None:
        """User without binding should be denied."""
        r = await client.post(
            f"{endpoints.authz}/check",
            json={
                "user_id": "usr_01J5INT0000000000NOPERM",
                "action": "crypto.kek.create",
                "resource_type": "crypto",
            },
            headers=tenant.headers,
        )
        assert r.status_code == 200
        assert r.json()["allowed"] is False


class TestHealth:
    async def test_healthz(self, client: httpx.AsyncClient, endpoints) -> None:
        r = await client.get(f"{endpoints.authz}/healthz")
        assert r.status_code == 200
