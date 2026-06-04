"""Contract tests for POST /sessions/service-account-token and GET /sessions/me.

These endpoints were added so the agent-platform B-M1 layer can stop
forwarding a single global service token into every OpenHands sandbox and
instead mint per-run, scope-limited, tenant-bound tokens.

The tests pin down the parts that business teams will rely on even while
the underlying Keycloak token-exchange implementation is still a skeleton.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient


# Foundation middleware enforces TENANT_ID_PATTERN = ^tnt_[0-9A-Z]{26}$,
# so the IDs we cite here are exactly 26 base32 chars.  These differ from
# the placeholder in tests/conftest.py::tenant_headers — that fixture's
# ID is 25 chars (a pre-existing bug in the conftest unrelated to this
# review) so we always build our own headers below.
_VALID_TENANT = "tnt_01J5DEV00000000000000000A1"
_OTHER_TENANT = "tnt_01J5DEVOTHER000000000000B1"
_VALID_USER = "usr_01J5DEVUSER000000000000001"


def _headers() -> dict[str, str]:
    return {
        "X-Tenant-Id": _VALID_TENANT,
        "X-User-Id": _VALID_USER,
        "X-Actor": "USER",
    }


def _body(**over: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "tenant_id": _VALID_TENANT,
        "subject": "agent-scheduler:run_01j5xyzrun000000000000000",
        "scopes": ["llm-gateway.invoke", "audit.write"],
        "audience": "foundation",
        "ttl_seconds": 600,
    }
    payload.update(over)
    return payload


@pytest.mark.unit
async def test_issue_service_account_token_happy_path(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/identity/v1/sessions/service-account-token",
        json=_body(),
        headers=_headers(),
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["token_type"] == "BEARER"
    assert data["tenant_id"] == _VALID_TENANT
    assert data["audience"] == "foundation"
    assert data["scopes"] == ["llm-gateway.invoke", "audit.write"]
    assert data["jti"].startswith("jti_")
    # expires_at must be after issued_at; both ISO-8601
    assert data["expires_at"] > data["issued_at"]


@pytest.mark.unit
async def test_issue_rejects_cross_tenant(client: AsyncClient) -> None:
    """A service authenticated for tenant A must not mint a token for tenant B."""
    resp = await client.post(
        "/api/identity/v1/sessions/service-account-token",
        json=_body(tenant_id=_OTHER_TENANT),
        headers=_headers(),
    )
    assert resp.status_code == 403, resp.text
    assert "SCOPE_NOT_ALLOWED" in resp.text


@pytest.mark.unit
async def test_issue_rejects_unknown_scope(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/identity/v1/sessions/service-account-token",
        json=_body(scopes=["llm-gateway.invoke", "bogus.scope"]),
        headers=_headers(),
    )
    assert resp.status_code == 403, resp.text
    body = resp.json()
    assert "bogus.scope" in body["detail"]


@pytest.mark.unit
@pytest.mark.parametrize("bad_ttl", [0, 30, 86_401, 1_000_000])
async def test_issue_rejects_out_of_range_ttl(
    client: AsyncClient, bad_ttl: int
) -> None:
    resp = await client.post(
        "/api/identity/v1/sessions/service-account-token",
        json=_body(ttl_seconds=bad_ttl),
        headers=_headers(),
    )
    # pydantic Field rejects with 422; manual fallback returns the same status.
    assert resp.status_code == 422


@pytest.mark.unit
async def test_issue_rejects_malformed_subject(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/identity/v1/sessions/service-account-token",
        json=_body(subject="UPPERCASE NOT ALLOWED"),
        headers=_headers(),
    )
    assert resp.status_code == 422


@pytest.mark.unit
async def test_me_returns_tenant_and_user(client: AsyncClient) -> None:
    # /sessions/me now requires Authorization: Bearer <token>; the OIDC adapter
    # is mocked via app.dependency_overrides so any non-empty bearer works.
    headers = {**_headers(), "Authorization": "Bearer stub-access-token"}
    resp = await client.get("/api/identity/v1/sessions/me", headers=headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["tenant_id"] == _VALID_TENANT
    assert data["user_id"].startswith("usr_")
    assert "email" in data
    assert isinstance(data["roles"], list)


@pytest.mark.unit
async def test_me_requires_context(client: AsyncClient) -> None:
    """No X-Tenant-Id / X-User-Id headers → 401."""
    resp = await client.get("/api/identity/v1/sessions/me")
    assert resp.status_code == 401
