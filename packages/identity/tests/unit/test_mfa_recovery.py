"""P1 MFA tests: TOTP secret encryption-at-rest + recovery codes.

Unit-level (service helpers + FakeAsyncSession) plus a login-via-recovery
integration test through the shared client fixture.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import AsyncClient

from foundation_identity.services.mfa_service import (
    MfaService,
    _decrypt_secret,
    _encrypt_secret,
    _generate_recovery_code,
    _hash_recovery_code,
)

_TENANT = "tnt_01J5DEV00000000000000000A1"
_USER = "usr_01J5DEVUSER000000000000001"


# --------------------------------------------------------------------------- #
# TOTP secret encryption at rest
# --------------------------------------------------------------------------- #
def test_totp_secret_encrypts_and_roundtrips() -> None:
    secret = "JBSWY3DPEHPK3PXP"
    stored = _encrypt_secret(secret)
    assert stored != secret  # not plaintext at rest
    assert _decrypt_secret(stored) == secret


def test_decrypt_tolerates_legacy_plaintext() -> None:
    # Rows written before encryption was introduced are returned as-is.
    assert _decrypt_secret("JBSWY3DPEHPK3PXP") == "JBSWY3DPEHPK3PXP"


# --------------------------------------------------------------------------- #
# recovery code helpers
# --------------------------------------------------------------------------- #
def test_recovery_code_shape_and_hash() -> None:
    code = _generate_recovery_code()
    assert len(code) == 14
    assert code.count("-") == 2
    h = _hash_recovery_code(code)
    assert len(h) == 64
    assert h == _hash_recovery_code(code)  # deterministic


# --------------------------------------------------------------------------- #
# verify_recovery_code service behaviour
# --------------------------------------------------------------------------- #
class _FakeRow:
    def __init__(self) -> None:
        self.used_at = None


class _FakeResult:
    def __init__(self, row: object) -> None:
        self._row = row

    def scalar_one_or_none(self) -> object:
        return self._row


class _FakeSession:
    def __init__(self, row: object) -> None:
        self._row = row
        self.flushed = False

    async def execute(self, *_a: object, **_k: object) -> _FakeResult:
        return _FakeResult(self._row)

    async def flush(self) -> None:
        self.flushed = True


def _svc() -> MfaService:
    return MfaService(keycloak=AsyncMock(), audit=AsyncMock(), cache=AsyncMock())


async def test_verify_recovery_code_good_marks_used() -> None:
    row = _FakeRow()
    db = _FakeSession(row)
    ok = await _svc().verify_recovery_code(
        db, tenant_id=_TENANT, user_id=_USER, code="abcd-efgh-ijkl"
    )
    assert ok is True
    assert row.used_at is not None  # single-use: consumed
    assert db.flushed


async def test_verify_recovery_code_unknown_returns_false() -> None:
    db = _FakeSession(None)  # no matching unused code
    ok = await _svc().verify_recovery_code(
        db, tenant_id=_TENANT, user_id=_USER, code="zzzz-zzzz-zzzz"
    )
    assert ok is False


# --------------------------------------------------------------------------- #
# login via recovery code (integration through the endpoint)
# --------------------------------------------------------------------------- #
async def test_login_mfa_verify_with_recovery_code(
    client: AsyncClient, app, mock_redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    @asynccontextmanager
    async def _scope(*, tenant_id: str = "", user_id: str = "PLATFORM"):
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
    # Recovery verification succeeds.
    monkeypatch.setattr(
        "foundation_identity.services.mfa_service.MfaService.verify_recovery_code",
        AsyncMock(return_value=True),
    )

    await mock_redis.set(
        "mfa:login:chal_rec",
        json.dumps(
            {
                "tenant_id": _TENANT,
                "user_id": _USER,
                "tokens": {"access_token": "rec-access", "refresh_token": "", "expires_in": 300},
                "device_id": None,
            }
        ),
        ttl_seconds=300,
    )

    resp = await client.post(
        "/api/identity/v1/sessions/chal_rec/mfa-verify",
        json={"code": "abcd-efgh-ijkl", "method": "RECOVERY"},
    )

    assert resp.status_code == 201, resp.text
    assert resp.json()["access_token"] == "rec-access"
    assert not await mock_redis.exists("mfa:login:chal_rec")  # stash consumed
