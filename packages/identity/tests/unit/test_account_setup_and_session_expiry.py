"""Login / refresh edge cases that previously collapsed into the wrong outcome.

* Keycloak's "Account is not fully set up" (valid password, required actions
  pending — e.g. an expired password) must surface as
  ``ACCOUNT_SETUP_REQUIRED``, not ``INVALID_CREDENTIALS``, and must not count
  toward the failed-login lockout.
* The ``identity.session`` row's ``expires_at`` is the session's ABSOLUTE
  deadline, not the 5-minute access-token expiry — otherwise the idle/absolute
  checks on refresh and ``/sessions/me`` revoke every session after 5 minutes.
* A refresh that fails because Keycloak is unreachable must not burn the
  refresh token: the reuse mark is released so the caller can retry it.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import respx
from httpx import AsyncClient, Response
from jose import jwt

from foundation_identity.adapters.keycloak_oidc import KeycloakOIDCAdapter
from foundation_identity.api.v1 import sessions as sess_mod
from foundation_identity.config import get_settings
from foundation_identity.errors import (
    ACCOUNT_SETUP_REQUIRED,
    INVALID_CREDENTIALS,
    KEYCLOAK_ERROR,
    KEYCLOAK_UNAVAILABLE,
    FoundationError,
)

_TENANT = "tnt_01J5DEV00000000000000000A1"
_USER = "usr_01J5DEVUSER000000000000001"


# --------------------------------------------------------------------------- #
# Adapter: Keycloak token-endpoint error mapping
# --------------------------------------------------------------------------- #
@respx.mock
async def test_password_grant_account_not_set_up_maps_to_setup_required() -> None:
    adapter = KeycloakOIDCAdapter()
    respx.post(adapter._token_url()).mock(
        return_value=Response(
            400,
            json={
                "error": "invalid_grant",
                "error_description": "Account is not fully set up",
            },
        )
    )

    with pytest.raises(FoundationError) as exc:
        await adapter.password_grant(username="u@example.com", password="pw")
    assert exc.value.error_code is ACCOUNT_SETUP_REQUIRED
    assert exc.value.error_code.http_status == 401
    assert exc.value.error_code.code == "FOUNDATION.IDENTITY.AUTH.ACCOUNT_SETUP_REQUIRED"


@respx.mock
async def test_password_grant_bad_credentials_still_invalid_credentials() -> None:
    adapter = KeycloakOIDCAdapter()
    respx.post(adapter._token_url()).mock(
        return_value=Response(
            401,
            json={
                "error": "invalid_grant",
                "error_description": "Invalid user credentials",
            },
        )
    )

    with pytest.raises(FoundationError) as exc:
        await adapter.password_grant(username="u@example.com", password="bad")
    assert exc.value.error_code is INVALID_CREDENTIALS


@respx.mock
async def test_token_error_with_non_object_body_is_keycloak_error() -> None:
    adapter = KeycloakOIDCAdapter()
    respx.post(adapter._token_url()).mock(return_value=Response(400, json=["nope"]))

    with pytest.raises(FoundationError) as exc:
        await adapter.password_grant(username="u@example.com", password="pw")
    assert exc.value.error_code is KEYCLOAK_ERROR


# --------------------------------------------------------------------------- #
# POST /sessions (EMAIL_PASSWORD)
# --------------------------------------------------------------------------- #
def _stub_lockout(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    monkeypatch.setattr(sess_mod, "_check_account_lockout", AsyncMock(return_value=None))
    record_failure = AsyncMock(return_value=None)
    monkeypatch.setattr(sess_mod, "_record_login_failure", record_failure)
    return record_failure


async def test_login_account_setup_required_is_distinct_and_not_a_failure(
    client: AsyncClient,
    mock_oidc: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record_failure = _stub_lockout(monkeypatch)
    mock_oidc.password_grant.side_effect = FoundationError(ACCOUNT_SETUP_REQUIRED)

    resp = await client.post(
        "/api/identity/v1/sessions",
        json={"method": "EMAIL_PASSWORD", "email": "u@example.com", "password": "pw"},
    )

    assert resp.status_code == 401, resp.text
    body = resp.json()
    assert body["code"] == "FOUNDATION.IDENTITY.AUTH.ACCOUNT_SETUP_REQUIRED"
    assert body["user_message"]
    assert resp.headers["content-type"].startswith("application/problem+json")
    # The password was right — this must not push the account toward lockout.
    record_failure.assert_not_awaited()


async def test_login_invalid_credentials_still_counts_as_failure(
    client: AsyncClient,
    mock_oidc: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record_failure = _stub_lockout(monkeypatch)
    mock_oidc.password_grant.side_effect = FoundationError(INVALID_CREDENTIALS)

    resp = await client.post(
        "/api/identity/v1/sessions",
        json={"method": "EMAIL_PASSWORD", "email": "u@example.com", "password": "bad"},
    )

    assert resp.status_code == 401
    assert resp.json()["code"] == "FOUNDATION.IDENTITY.AUTH.INVALID_CREDENTIALS"
    record_failure.assert_awaited_once_with("u@example.com")


# --------------------------------------------------------------------------- #
# _persist_session: row expires_at is the absolute session deadline
# --------------------------------------------------------------------------- #
async def test_persist_session_uses_absolute_timeout_not_token_expiry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    added: list[Any] = []
    db = MagicMock()
    db.add = added.append
    db.flush = AsyncMock()

    @asynccontextmanager
    async def _scope(*, tenant_id: str = "", user_id: str = "PLATFORM"):
        yield db

    monkeypatch.setattr(sess_mod, "admin_session_scope", _scope)

    issued_at = datetime.now(UTC)
    await sess_mod._persist_session(
        session_id="sess_01J5TEST",
        tenant_id=_TENANT,
        user_id=_USER,
        issued_at=issued_at,
        refresh_token_jti="jti-1",
        device_id=None,
        scopes=["openid"],
    )

    assert len(added) == 1
    row = added[0]
    absolute = timedelta(seconds=get_settings().session_absolute_timeout_floor_seconds)
    assert row.expires_at == issued_at + absolute
    assert row.last_seen_at == issued_at
    assert row.refresh_token_jti == "jti-1"


async def test_relink_accepts_refresh_after_access_token_lifetime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A session row written at login must survive a refresh 5+ minutes later."""
    issued_at = datetime.now(UTC) - timedelta(minutes=6)
    row = MagicMock(
        expires_at=issued_at
        + timedelta(seconds=get_settings().session_absolute_timeout_floor_seconds),
        last_seen_at=issued_at + timedelta(minutes=2),
        revoked_at=None,
        refresh_token_jti="old-jti",
    )
    result = MagicMock()
    result.scalar_one_or_none.return_value = row
    db = MagicMock()
    db.execute = AsyncMock(return_value=result)
    db.flush = AsyncMock()

    @asynccontextmanager
    async def _scope(*, tenant_id: str = "", user_id: str = "PLATFORM"):
        yield db

    monkeypatch.setattr(sess_mod, "admin_session_scope", _scope)

    now = datetime.now(UTC)
    await sess_mod._relink_session_jti(
        tenant_id=_TENANT,
        user_id=_USER,
        old_jti="old-jti",
        new_jti="new-jti",
        last_seen_at=now,
    )
    assert row.refresh_token_jti == "new-jti"
    assert row.last_seen_at == now
    assert row.revoked_at is None


# --------------------------------------------------------------------------- #
# refresh: a Keycloak outage must not burn the refresh token
# --------------------------------------------------------------------------- #
def _refresh_token(jti: str) -> str:
    return jwt.encode({"jti": jti, "sub": "kc-sub-123"}, "secret", algorithm="HS256")


@pytest.mark.parametrize("dependency_error", [KEYCLOAK_UNAVAILABLE, KEYCLOAK_ERROR])
async def test_refresh_dependency_failure_releases_reuse_mark(
    client: AsyncClient,
    mock_oidc: AsyncMock,
    mock_redis,
    monkeypatch: pytest.MonkeyPatch,
    dependency_error,
) -> None:
    monkeypatch.setattr(sess_mod, "_relink_session_jti", AsyncMock(return_value=None))
    reuse_handler = AsyncMock(return_value=None)
    monkeypatch.setattr(sess_mod, "_handle_refresh_reuse", reuse_handler)
    token = _refresh_token("flaky-jti")

    mock_oidc.refresh_token_grant = AsyncMock(
        side_effect=FoundationError(dependency_error)
    )
    resp = await client.post(
        "/api/identity/v1/sessions/current/refresh", json={"refresh_token": token}
    )
    assert resp.status_code == dependency_error.http_status
    assert not await mock_redis.exists("refresh_token:used:flaky-jti")

    # Keycloak recovers → the SAME token is redeemed normally, not flagged as reuse.
    mock_oidc.refresh_token_grant = AsyncMock(
        return_value={
            "access_token": "new-access",
            "refresh_token": _refresh_token("next-jti"),
            "expires_in": 300,
        }
    )
    resp = await client.post(
        "/api/identity/v1/sessions/current/refresh", json={"refresh_token": token}
    )
    assert resp.status_code == 200, resp.text
    reuse_handler.assert_not_awaited()
    assert await mock_redis.exists("refresh_token:used:flaky-jti")


async def test_refresh_definitive_rejection_keeps_reuse_mark(
    client: AsyncClient,
    mock_oidc: AsyncMock,
    mock_redis,
) -> None:
    mock_oidc.refresh_token_grant = AsyncMock(
        side_effect=FoundationError(INVALID_CREDENTIALS)
    )
    resp = await client.post(
        "/api/identity/v1/sessions/current/refresh",
        json={"refresh_token": _refresh_token("dead-jti")},
    )
    assert resp.status_code == 401
    assert await mock_redis.exists("refresh_token:used:dead-jti")
