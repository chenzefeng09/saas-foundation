"""P1 MFA login-flow tests: password → challenge → mfa-verify.

Exercises the password-then-MFA gate added to create_session plus the
``POST /sessions/{challenge_id}/mfa-verify`` completion endpoint, via the shared
``client`` fixture (mock OIDC + FakeRedisCache + stubbed admin scope).

Proves:
  * password login for a non-MFA user returns 201 + token (unchanged path),
  * password login for an MFA user returns 202 + challenge and NO token,
  * mfa-verify with a good code returns 201 + the stashed session,
  * a bad code is rejected and the stash survives for retry,
  * an unknown / expired challenge is 404.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import AsyncClient

from foundation_identity.errors import MFA_CODE_INVALID, FoundationError
from foundation_identity.schemas.mfa import MfaChallengeResponse

_TENANT = "tnt_01J5DEV00000000000000000A1"
_USER = "usr_01J5DEVUSER000000000000001"
_LOGIN = {"method": "EMAIL_PASSWORD", "email": "u@example.com", "password": "pw-123456"}


def _patch_admin_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub admin_session_scope used by _persist_session (no real DB)."""

    @asynccontextmanager
    async def _scope(*, tenant_id: str = "", user_id: str = "PLATFORM"):
        # add() must be sync (AsyncMock would yield an un-awaited coroutine);
        # flush()/execute() are async.  execute() returns a Result whose
        # scalar_one_or_none() / scalars().all() default to None / [] — the
        # honest "row not found" shape the login / session-touch helpers expect.
        fake = MagicMock()
        fake.add = MagicMock()
        fake.flush = AsyncMock()
        empty_result = MagicMock()
        empty_result.scalar_one_or_none.return_value = None
        empty_result.scalars.return_value.all.return_value = []
        fake.execute = AsyncMock(return_value=empty_result)
        yield fake

    monkeypatch.setattr(
        "foundation_identity.api.v1.sessions.admin_session_scope", _scope
    )


def _set_mfa_enabled(app, enabled: bool) -> None:
    """Make the db_session override report the user's mfa_enabled flag."""
    from foundation_identity.api.dependencies import db_session
    from tests.conftest import FakeAsyncSession, _ExecuteResult

    async def _override():
        yield FakeAsyncSession(execute_result=_ExecuteResult(scalar=enabled))

    app.dependency_overrides[db_session] = _override


# --------------------------------------------------------------------------- #
async def test_password_login_without_mfa_returns_token(
    client: AsyncClient, app, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_admin_scope(monkeypatch)
    _set_mfa_enabled(app, False)

    resp = await client.post("/api/identity/v1/sessions", json=_LOGIN)

    assert resp.status_code == 201, resp.text
    assert resp.json()["access_token"] == "stub-access-token"


async def test_password_login_with_mfa_returns_challenge_no_token(
    client: AsyncClient, app, mock_redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_admin_scope(monkeypatch)
    _set_mfa_enabled(app, True)

    challenge = MfaChallengeResponse(
        challenge_id="chal_login1",
        methods=["TOTP"],
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    monkeypatch.setattr(
        "foundation_identity.services.mfa_service.MfaService.begin_challenge",
        AsyncMock(return_value=challenge),
    )

    resp = await client.post("/api/identity/v1/sessions", json=_LOGIN)

    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["challenge_id"] == "chal_login1"
    assert body["methods"] == ["TOTP"]
    # Crucially: no token leaks in the 202 response.
    assert "access_token" not in resp.text
    # The token bundle is stashed server-side for the verify leg.
    assert await mock_redis.exists("mfa:login:chal_login1")


async def test_mfa_verify_good_code_issues_session(
    client: AsyncClient, app, mock_redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_admin_scope(monkeypatch)
    # Pre-stash a token bundle as the password leg would have.
    import json

    await mock_redis.set(
        "mfa:login:chal_ok",
        json.dumps(
            {
                "tenant_id": _TENANT,
                "user_id": _USER,
                "tokens": {
                    "access_token": "stashed-access",
                    "refresh_token": "",
                    "expires_in": 300,
                },
                "device_id": None,
            }
        ),
        ttl_seconds=300,
    )
    monkeypatch.setattr(
        "foundation_identity.services.mfa_service.MfaService.verify_challenge",
        AsyncMock(return_value=_USER),
    )

    resp = await client.post(
        "/api/identity/v1/sessions/chal_ok/mfa-verify",
        json={"code": "123456", "method": "TOTP"},
    )

    assert resp.status_code == 201, resp.text
    assert resp.json()["access_token"] == "stashed-access"
    # Stash consumed → replay is impossible.
    assert not await mock_redis.exists("mfa:login:chal_ok")


async def test_mfa_verify_bad_code_rejected_stash_survives(
    client: AsyncClient, app, mock_redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    import json

    await mock_redis.set(
        "mfa:login:chal_bad",
        json.dumps({"tenant_id": _TENANT, "user_id": _USER, "tokens": {}, "device_id": None}),
        ttl_seconds=300,
    )

    async def _reject(*_a, **_k):
        raise FoundationError(MFA_CODE_INVALID)

    monkeypatch.setattr(
        "foundation_identity.services.mfa_service.MfaService.verify_challenge", _reject
    )

    resp = await client.post(
        "/api/identity/v1/sessions/chal_bad/mfa-verify",
        json={"code": "000000", "method": "TOTP"},
    )

    assert resp.status_code == 401
    assert "MFA_CODE_INVALID" in resp.text
    # Stash NOT consumed on failure → user can retry.
    assert await mock_redis.exists("mfa:login:chal_bad")


async def test_mfa_verify_unknown_challenge_404(
    client: AsyncClient, app
) -> None:
    resp = await client.post(
        "/api/identity/v1/sessions/chal_missing/mfa-verify",
        json={"code": "123456", "method": "TOTP"},
    )
    assert resp.status_code == 404
