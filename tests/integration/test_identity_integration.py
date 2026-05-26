"""Integration tests for Identity Service — requires Keycloak + Postgres.

Tests identity management:
  1. Health check
  2. List users
  3. Password policy validation
"""

from __future__ import annotations

import httpx
import pytest


class TestIdentityHealth:
    async def test_healthz(self, client: httpx.AsyncClient, endpoints) -> None:
        r = await client.get(f"{endpoints.identity}/healthz")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "OK"
        # Identity will show Keycloak as a dependency
        if data.get("dependencies"):
            assert "keycloak" in data["dependencies"]


class TestUsers:
    async def test_list_users(
        self, client: httpx.AsyncClient, endpoints, tenant,
    ) -> None:
        r = await client.get(
            f"{endpoints.identity}/users",
            headers=tenant.headers,
        )
        # May return 200 with empty list if no users seeded
        assert r.status_code in (200, 200)
        data = r.json()
        assert "items" in data

    async def test_get_user_not_found(
        self, client: httpx.AsyncClient, endpoints, tenant,
    ) -> None:
        r = await client.get(
            f"{endpoints.identity}/users/usr_nonexistent",
            headers=tenant.headers,
        )
        assert r.status_code == 404


class TestPasswordPolicy:
    async def test_validate_password(
        self, client: httpx.AsyncClient, endpoints, tenant,
    ) -> None:
        """Password policy validation endpoint."""
        r = await client.post(
            f"{endpoints.identity}/policies/password/validate",
            json={"password": "Short1!"},
            headers=tenant.headers,
        )
        # The response depends on the configured policy baseline
        # Just check the endpoint responds
        assert r.status_code in (200, 422)

    async def test_get_password_policy(
        self, client: httpx.AsyncClient, endpoints, tenant,
    ) -> None:
        r = await client.get(
            f"{endpoints.identity}/policies/password",
            headers=tenant.headers,
        )
        assert r.status_code == 200
        data = r.json()
        # Should return policy config
        assert "min_length" in data or "policy" in data


class TestSessions:
    async def test_list_sessions_empty(
        self, client: httpx.AsyncClient, endpoints, tenant,
    ) -> None:
        """List sessions for a user with no active sessions."""
        r = await client.get(
            f"{endpoints.identity}/sessions",
            headers=tenant.headers,
        )
        assert r.status_code == 200
