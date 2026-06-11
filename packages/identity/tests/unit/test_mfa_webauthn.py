"""P1 MFA tests: WebAuthn credential management (delegated to Keycloak).

WebAuthn enrolment and assertion run inside Keycloak's required-action pages
(navigator.credentials.* there).  Foundation only:
  * lists the user's credentials (filtered to ``webauthn*`` types),
  * triggers the required-action email,
  * removes individual keys.

These tests prove the delegation calls KC with the right shapes and that the
service filters non-WebAuthn credentials out of the listing.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import AsyncClient

from foundation_identity.services.mfa_service import MfaService

_TENANT = "tnt_01J5DEV00000000000000000A1"
_USER = "usr_01J5DEVUSER000000000000001"
_KC_SUB = "kc-sub-uuid-abc"


# --------------------------------------------------------------------------- #
# Service-layer: filtering + delegation
# --------------------------------------------------------------------------- #
def _user_row() -> MagicMock:
    u = MagicMock()
    u.keycloak_user_id = _KC_SUB
    u.deleted_at = None
    return u


def _result(scalar: object) -> MagicMock:
    r = MagicMock()
    r.scalar_one_or_none.return_value = scalar
    return r


def _db_with_user() -> MagicMock:
    db = MagicMock()
    db.execute = AsyncMock(return_value=_result(_user_row()))
    db.flush = AsyncMock()
    return db


def _svc_with_kc(kc: AsyncMock) -> MfaService:
    return MfaService(keycloak=kc, audit=AsyncMock(), cache=AsyncMock())


async def test_list_webauthn_filters_non_webauthn_types() -> None:
    kc = AsyncMock()
    kc.list_credentials = AsyncMock(
        return_value=[
            {"id": "c1", "type": "password", "userLabel": "pw", "createdDate": "t1"},
            {"id": "c2", "type": "webauthn", "userLabel": "YubiKey", "createdDate": "t2"},
            {"id": "c3", "type": "otp", "userLabel": "Authy", "createdDate": "t3"},
            {
                "id": "c4",
                "type": "webauthn-passwordless",
                "userLabel": "Passkey",
                "createdDate": "t4",
            },
        ]
    )

    out = await _svc_with_kc(kc).list_webauthn_credentials(
        _db_with_user(), tenant_id=_TENANT, user_id=_USER
    )

    ids = [c["id"] for c in out]
    assert ids == ["c2", "c4"]
    kc.list_credentials.assert_awaited_once_with(_KC_SUB)


async def test_trigger_webauthn_register_calls_kc_required_action() -> None:
    kc = AsyncMock()
    kc.trigger_required_action = AsyncMock(return_value=None)

    await _svc_with_kc(kc).trigger_webauthn_register(
        _db_with_user(),
        tenant_id=_TENANT,
        user_id=_USER,
        request_id="req-1",
        passwordless=False,
    )

    kc.trigger_required_action.assert_awaited_once_with(
        _KC_SUB, action="webauthn-register"
    )


async def test_trigger_webauthn_register_passwordless_variant() -> None:
    kc = AsyncMock()
    kc.trigger_required_action = AsyncMock(return_value=None)

    await _svc_with_kc(kc).trigger_webauthn_register(
        _db_with_user(),
        tenant_id=_TENANT,
        user_id=_USER,
        request_id="req-2",
        passwordless=True,
    )

    kc.trigger_required_action.assert_awaited_once_with(
        _KC_SUB, action="webauthn-register-passwordless"
    )


async def test_delete_webauthn_credential_calls_kc() -> None:
    kc = AsyncMock()
    kc.delete_credential = AsyncMock(return_value=None)

    await _svc_with_kc(kc).delete_webauthn_credential(
        _db_with_user(),
        tenant_id=_TENANT,
        user_id=_USER,
        request_id="req-3",
        credential_id="cred-xyz",
    )

    kc.delete_credential.assert_awaited_once_with(_KC_SUB, "cred-xyz")


async def test_resolve_kc_sub_raises_for_unlinked_user() -> None:
    from foundation_identity.errors import USER_NOT_FOUND, FoundationError

    # User exists but has no keycloak_user_id (e.g. half-provisioned).
    u = MagicMock()
    u.keycloak_user_id = None
    u.deleted_at = None
    db = MagicMock()
    db.execute = AsyncMock(return_value=_result(u))

    kc = AsyncMock()
    with pytest.raises(FoundationError) as exc:
        await _svc_with_kc(kc).list_webauthn_credentials(
            db, tenant_id=_TENANT, user_id=_USER
        )
    assert exc.value.error_code is USER_NOT_FOUND


# --------------------------------------------------------------------------- #
# Endpoint-level: routes wire to service correctly
# --------------------------------------------------------------------------- #
async def test_endpoint_list_webauthn_returns_filtered_items(
    client: AsyncClient, app, tenant_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "foundation_identity.services.mfa_service.MfaService.list_webauthn_credentials",
        AsyncMock(
            return_value=[
                {"id": "c2", "type": "webauthn", "label": "YubiKey", "created_at": "t2"},
            ]
        ),
    )
    resp = await client.get(
        "/api/identity/v1/mfa/webauthn/credentials", headers=tenant_headers
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body) == 1
    assert body[0]["id"] == "c2"


async def test_endpoint_trigger_webauthn_register_returns_202(
    client: AsyncClient, app, tenant_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    triggered = AsyncMock(return_value=None)
    monkeypatch.setattr(
        "foundation_identity.services.mfa_service.MfaService.trigger_webauthn_register",
        triggered,
    )
    resp = await client.post(
        "/api/identity/v1/mfa/webauthn/register",
        headers=tenant_headers,
        json={"passwordless": True},
    )
    assert resp.status_code == 202, resp.text
    triggered.assert_awaited_once()
    assert triggered.await_args.kwargs["passwordless"] is True


async def test_endpoint_delete_webauthn_credential_returns_204(
    client: AsyncClient, app, tenant_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    deleted = AsyncMock(return_value=None)
    monkeypatch.setattr(
        "foundation_identity.services.mfa_service.MfaService.delete_webauthn_credential",
        deleted,
    )
    resp = await client.delete(
        "/api/identity/v1/mfa/webauthn/credentials/cred-xyz", headers=tenant_headers
    )
    assert resp.status_code == 204, resp.text
    deleted.assert_awaited_once()
    assert deleted.await_args.kwargs["credential_id"] == "cred-xyz"
