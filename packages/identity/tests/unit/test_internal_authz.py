"""P3-E tests: GET /internal/authz — gateway ext_authz target.

The endpoint exists so an ingress (NGINX auth-url / Envoy external_authz) can
verify the bearer token once per request and forward verified ids to upstream
services.  These tests prove:

  * Missing / malformed Authorization header → 401 TOKEN_INVALID.
  * Valid JWKS-verified token → 200 + canonical response headers.
  * Token without an ``actor`` claim → defaults to ``USER`` in the header.
  * The companion health endpoint is anonymous and always 200.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient


async def test_authz_missing_header_returns_401(client: AsyncClient) -> None:
    resp = await client.get("/api/identity/v1/internal/authz")
    assert resp.status_code == 401
    assert "TOKEN_INVALID" in resp.text


async def test_authz_malformed_scheme_returns_401(client: AsyncClient) -> None:
    resp = await client.get(
        "/api/identity/v1/internal/authz",
        headers={"Authorization": "Basic somecreds"},
    )
    assert resp.status_code == 401


async def test_authz_valid_token_returns_headers(client: AsyncClient) -> None:
    """mock_oidc.verify_token returns STUB_OIDC_CLAIMS (user_id/tenant_id)."""
    resp = await client.get(
        "/api/identity/v1/internal/authz",
        headers={"Authorization": "Bearer stub-access-token"},
    )
    assert resp.status_code == 200
    assert resp.headers["X-Foundation-User-Id"].startswith("usr_")
    assert resp.headers["X-Foundation-Tenant-Id"].startswith("tnt_")
    assert resp.headers["X-User-Id"] == resp.headers["X-Foundation-User-Id"]
    assert resp.headers["X-Tenant-Id"] == resp.headers["X-Foundation-Tenant-Id"]
    # STUB has no `actor`, so the endpoint must default to USER.
    assert resp.headers["X-Actor"] == "USER"
    assert resp.headers["X-Foundation-Actor"] == "USER"


async def test_authz_propagates_actor_claim(
    client: AsyncClient, mock_oidc, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.conftest import STUB_OIDC_CLAIMS

    mock_oidc.verify_token.return_value = {**STUB_OIDC_CLAIMS, "actor": "ADMIN"}

    resp = await client.get(
        "/api/identity/v1/internal/authz",
        headers={"Authorization": "Bearer stub-access-token"},
    )
    assert resp.status_code == 200
    assert resp.headers["X-Actor"] == "ADMIN"
    assert resp.headers["X-Foundation-Actor"] == "ADMIN"


async def test_authz_health_is_anonymous(client: AsyncClient) -> None:
    resp = await client.get("/api/identity/v1/internal/authz/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
