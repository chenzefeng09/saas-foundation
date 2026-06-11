"""P1 batch D: SMS OTP + admin MFA reset + step-up gating.

Covers:
  * SMS enrol stashes encrypted phone, never plaintext at rest.
  * send_sms_challenge dispatches via NotificationGateway + stashes code.
  * verify_sms_challenge accepts good code, rejects bad, consumes on success.
  * require_recent_mfa: passes when actor has no MFA, blocks when actor has
    MFA but no satisfied session, passes when latest session is satisfied.
  * admin_reset_user_mfa wipes methods + recovery codes + clears mfa_enabled
    + best-effort KC credential cleanup.
  * Endpoints wire through correctly (force_password_reset gated; admin reset).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import AsyncClient

from foundation_identity.errors import MFA_REQUIRED, FoundationError
from foundation_identity.services.mfa_service import (
    MfaService,
    _decrypt_secret,
)

_TENANT = "tnt_01J5DEV00000000000000000A1"
_USER = "usr_01J5DEVUSER000000000000001"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
class _Stash:
    """Minimal in-memory cache exposing the RedisCacheAdapter surface used here."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    async def set(self, key: str, value: str, ttl_seconds: int | None = None) -> None:
        self.store[key] = value

    async def get(self, key: str) -> str | None:
        return self.store.get(key)

    async def delete(self, key: str) -> None:
        self.store.pop(key, None)


def _result(scalar: object = None, rows: list | None = None) -> MagicMock:
    r = MagicMock()
    r.scalar_one_or_none.return_value = scalar
    scalars = MagicMock()
    scalars.all.return_value = rows or []
    r.scalars.return_value = scalars
    return r


# --------------------------------------------------------------------------- #
# SMS enrol — phone encrypted at rest
# --------------------------------------------------------------------------- #
async def test_sms_enroll_encrypts_phone_at_rest() -> None:
    """The stored secret_ref must NOT equal the plaintext phone."""
    db = MagicMock()
    db.execute = AsyncMock(return_value=_result(scalar=MagicMock(email="u@x.com")))
    db.flush = AsyncMock()
    captured: dict[str, object] = {}

    def _capture(obj: object) -> None:
        captured["method"] = obj

    db.add = _capture

    svc = MfaService(
        keycloak=AsyncMock(),
        audit=AsyncMock(),
        cache=_Stash(),
        notification=AsyncMock(),
    )
    out = await svc.enroll_sms(
        db,
        tenant_id=_TENANT,
        user_id=_USER,
        request_id="req",
        phone="+13800001234",
    )

    method = captured["method"]
    assert method.kind == "SMS_OTP"
    # Encrypted at rest, decrypts back to plaintext.
    assert method.secret_ref != "+13800001234"
    assert _decrypt_secret(method.secret_ref) == "+13800001234"
    # Only the suffix appears in the user-visible label.
    assert "1234" in (out.label or "")


# --------------------------------------------------------------------------- #
# send / verify SMS challenge
# --------------------------------------------------------------------------- #
async def test_send_sms_challenge_dispatches_and_stashes() -> None:
    stash = _Stash()
    notification = AsyncMock()
    notification.send_sms = AsyncMock()
    svc = MfaService(
        keycloak=AsyncMock(),
        audit=AsyncMock(),
        cache=stash,
        notification=notification,
    )

    await svc.send_sms_challenge(challenge_id="ch1", phone="+13800001234")

    code = stash.store["mfa:sms_challenge:ch1"]
    assert len(code) == 6
    assert code.isdigit()
    notification.send_sms.assert_awaited_once()
    sent_body = notification.send_sms.await_args.kwargs["body"]
    assert code in sent_body


async def test_verify_sms_challenge_consumes_on_success() -> None:
    stash = _Stash()
    stash.store["mfa:sms_challenge:ch2"] = "123456"
    svc = MfaService(keycloak=AsyncMock(), audit=AsyncMock(), cache=stash, notification=AsyncMock())

    ok = await svc.verify_sms_challenge(challenge_id="ch2", code="123456")
    assert ok is True
    assert "mfa:sms_challenge:ch2" not in stash.store  # single-use


async def test_verify_sms_challenge_rejects_bad_code() -> None:
    stash = _Stash()
    stash.store["mfa:sms_challenge:ch3"] = "111111"
    svc = MfaService(keycloak=AsyncMock(), audit=AsyncMock(), cache=stash, notification=AsyncMock())

    ok = await svc.verify_sms_challenge(challenge_id="ch3", code="999999")
    assert ok is False
    assert "mfa:sms_challenge:ch3" in stash.store  # NOT consumed on failure


# --------------------------------------------------------------------------- #
# require_recent_mfa
# --------------------------------------------------------------------------- #
async def test_step_up_passes_when_actor_has_no_mfa() -> None:
    actor = MagicMock()
    actor.mfa_enabled = False
    db = MagicMock()
    db.execute = AsyncMock(return_value=_result(scalar=actor))
    svc = MfaService(keycloak=AsyncMock(), audit=AsyncMock(), cache=AsyncMock())

    await svc.require_recent_mfa(db, tenant_id=_TENANT, user_id=_USER)  # no raise


async def test_step_up_blocks_when_mfa_user_lacks_satisfied_session() -> None:
    actor = MagicMock()
    actor.mfa_enabled = True
    latest = MagicMock()
    latest.mfa_satisfied = False
    db = MagicMock()
    # Two execute calls: actor lookup, then session lookup.
    db.execute = AsyncMock(side_effect=[_result(scalar=actor), _result(scalar=latest)])
    svc = MfaService(keycloak=AsyncMock(), audit=AsyncMock(), cache=AsyncMock())

    with pytest.raises(FoundationError) as exc:
        await svc.require_recent_mfa(db, tenant_id=_TENANT, user_id=_USER)
    assert exc.value.error_code is MFA_REQUIRED


async def test_step_up_passes_with_satisfied_session() -> None:
    actor = MagicMock()
    actor.mfa_enabled = True
    latest = MagicMock()
    latest.mfa_satisfied = True
    db = MagicMock()
    db.execute = AsyncMock(side_effect=[_result(scalar=actor), _result(scalar=latest)])
    svc = MfaService(keycloak=AsyncMock(), audit=AsyncMock(), cache=AsyncMock())

    await svc.require_recent_mfa(db, tenant_id=_TENANT, user_id=_USER)  # no raise


# --------------------------------------------------------------------------- #
# admin_reset_user_mfa
# --------------------------------------------------------------------------- #
async def test_admin_reset_wipes_methods_codes_and_flag() -> None:
    method = MagicMock(disabled_at=None)
    code = MagicMock(used_at=None)
    user = MagicMock(mfa_enabled=True, keycloak_user_id=None)
    db = MagicMock()
    db.execute = AsyncMock(
        side_effect=[
            _result(rows=[method]),
            _result(rows=[code]),
            _result(scalar=user),
        ]
    )
    db.flush = AsyncMock()
    audit = AsyncMock()
    svc = MfaService(keycloak=AsyncMock(), audit=audit, cache=AsyncMock())

    await svc.admin_reset_user_mfa(
        db,
        tenant_id=_TENANT,
        actor_id="usr_admin_00000000000000000",
        user_id=_USER,
        request_id="req",
    )

    assert method.disabled_at is not None
    assert code.used_at is not None
    assert user.mfa_enabled is False
    # SECURITY-severity audit event emitted.
    audit.publish.assert_awaited()
    payload = audit.publish.await_args.kwargs["payload"]
    assert payload["severity"] == "SECURITY"


# --------------------------------------------------------------------------- #
# endpoint wiring
# --------------------------------------------------------------------------- #
async def test_endpoint_admin_reset_mfa_requires_step_up(
    client: AsyncClient, app, tenant_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _block(*_a, **_kw):
        raise FoundationError(MFA_REQUIRED)

    monkeypatch.setattr(
        "foundation_identity.services.mfa_service.MfaService.require_recent_mfa", _block
    )
    resp = await client.post(
        f"/api/identity/v1/users/{_USER}/mfa:reset", headers=tenant_headers
    )
    assert resp.status_code == 401
    assert "MFA_REQUIRED" in resp.text


async def test_endpoint_admin_reset_mfa_happy_path(
    client: AsyncClient, app, tenant_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "foundation_identity.services.mfa_service.MfaService.require_recent_mfa",
        AsyncMock(return_value=None),
    )
    reset = AsyncMock(return_value=None)
    monkeypatch.setattr(
        "foundation_identity.services.mfa_service.MfaService.admin_reset_user_mfa", reset
    )
    resp = await client.post(
        f"/api/identity/v1/users/{_USER}/mfa:reset", headers=tenant_headers
    )
    assert resp.status_code == 204
    reset.assert_awaited_once()


async def test_endpoint_force_password_reset_gated_by_step_up(
    client: AsyncClient, app, tenant_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _block(*_a, **_kw):
        raise FoundationError(MFA_REQUIRED)

    monkeypatch.setattr(
        "foundation_identity.services.mfa_service.MfaService.require_recent_mfa", _block
    )
    resp = await client.post(
        f"/api/identity/v1/users/{_USER}/password:reset", headers=tenant_headers
    )
    assert resp.status_code == 401


async def test_endpoint_sms_enroll_returns_201(
    client: AsyncClient,
    app,
    tenant_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from foundation_identity.schemas.mfa import MfaMethodRead

    monkeypatch.setattr(
        "foundation_identity.services.mfa_service.MfaService.enroll_sms",
        AsyncMock(
            return_value=MfaMethodRead(
                id="mfa_x",
                kind="SMS_OTP",
                label="SMS to ***1234",
                enrolled_at=datetime.now(UTC) - timedelta(seconds=1),
                last_used_at=None,
            )
        ),
    )
    resp = await client.post(
        "/api/identity/v1/mfa/sms/enroll",
        headers=tenant_headers,
        json={"phone": "+13800001234"},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["kind"] == "SMS_OTP"
