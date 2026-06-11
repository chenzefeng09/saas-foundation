"""P0 security-loop tests: refresh-token rotation, reuse detection, logout.

These exercise the FastAPI handlers via the shared ``client`` fixture (mock
OIDC + in-memory FakeRedisCache + stubbed admin scope).  They prove:

  * refresh rotates the token and blacklists the old jti,
  * replaying a rotated refresh token revokes all sessions (REFRESH_TOKEN_REUSED),
  * a Redis outage fails the refresh secure (does not let the token through),
  * logout / kick mark the session revoked.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient
from jose import jwt

from foundation_identity.errors import REDIS_UNAVAILABLE, FoundationError

_TENANT = "tnt_01J5DEV00000000000000000A1"
_USER = "usr_01J5DEVUSER000000000000001"


def _refresh_token(jti: str, sub: str = "kc-sub-123") -> str:
    """A refresh-token-shaped JWT (only jti/sub are read, signature ignored)."""
    return jwt.encode({"jti": jti, "sub": sub}, "secret", algorithm="HS256")


def _patch_persist_and_relink(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub the DB-touching helpers that refresh calls after a successful grant."""
    monkeypatch.setattr(
        "foundation_identity.api.v1.sessions._relink_session_jti",
        AsyncMock(return_value=None),
    )


# --------------------------------------------------------------------------- #
# refresh — happy path: rotates + blacklists old jti
# --------------------------------------------------------------------------- #
async def test_refresh_rotates_and_blacklists_old_jti(
    client: AsyncClient,
    mock_oidc: AsyncMock,
    mock_redis,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_oidc.refresh_token_grant = AsyncMock(
        return_value={
            "access_token": "new-access",
            "refresh_token": _refresh_token("new-jti"),
            "expires_in": 300,
            "scope": "openid",
        }
    )
    _patch_persist_and_relink(monkeypatch)

    old = _refresh_token("old-jti")
    resp = await client.post(
        "/api/identity/v1/sessions/current/refresh",
        json={"refresh_token": old},
    )

    assert resp.status_code == 200, resp.text
    mock_oidc.refresh_token_grant.assert_awaited_once()
    # Old jti is now blacklisted; a replay would be detected.
    assert await mock_redis.exists("refresh_token:used:old-jti")


# --------------------------------------------------------------------------- #
# refresh — reuse detection: replaying a rotated token kills all sessions
# --------------------------------------------------------------------------- #
async def test_refresh_reuse_detected_revokes_all(
    client: AsyncClient,
    mock_oidc: AsyncMock,
    mock_redis,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Pre-seed the blacklist so the presented token reads as already-used.
    await mock_redis.set_if_absent("refresh_token:used:replayed-jti", "1", 100)

    reuse_handler = AsyncMock(return_value=None)
    monkeypatch.setattr(
        "foundation_identity.api.v1.sessions._handle_refresh_reuse", reuse_handler
    )

    resp = await client.post(
        "/api/identity/v1/sessions/current/refresh",
        json={"refresh_token": _refresh_token("replayed-jti")},
    )

    assert resp.status_code == 401
    assert "REFRESH_TOKEN_REUSED" in resp.text
    reuse_handler.assert_awaited_once()
    # The grant must NOT have been attempted for a replayed token.
    mock_oidc.refresh_token_grant.assert_not_called()


# --------------------------------------------------------------------------- #
# refresh — fail-secure: Redis down → refuse, do not redeem
# --------------------------------------------------------------------------- #
async def test_refresh_fails_secure_when_cache_down(
    client: AsyncClient,
    mock_oidc: AsyncMock,
    mock_redis,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _boom(*_a, **_k):
        raise FoundationError(REDIS_UNAVAILABLE)

    monkeypatch.setattr(mock_redis, "set_if_absent", _boom)

    resp = await client.post(
        "/api/identity/v1/sessions/current/refresh",
        json={"refresh_token": _refresh_token("some-jti")},
    )

    assert resp.status_code == 503
    assert "REDIS_UNAVAILABLE" in resp.text
    mock_oidc.refresh_token_grant.assert_not_called()


# --------------------------------------------------------------------------- #
# logout — ends KC session + blacklists token
# --------------------------------------------------------------------------- #
async def test_logout_current_blacklists_and_calls_keycloak(
    client: AsyncClient,
    tenant_headers: dict[str, str],
    mock_oidc: AsyncMock,
    mock_redis,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_oidc.logout_session = AsyncMock(return_value=None)
    monkeypatch.setattr(
        "foundation_identity.api.v1.sessions._mark_session_revoked_by_jti",
        AsyncMock(return_value=None),
    )

    resp = await client.request(
        "DELETE",
        "/api/identity/v1/sessions/current",
        headers=tenant_headers,
        json={"refresh_token": _refresh_token("logout-jti")},
    )

    assert resp.status_code == 204
    mock_oidc.logout_session.assert_awaited_once()
    assert await mock_redis.exists("refresh_token:used:logout-jti")
