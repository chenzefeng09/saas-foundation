"""Integration test: POST /sessions/me/password self-service change-password.

Exercises the full app stack (middleware → router → bearer-verify → service →
OIDC verify-current-password + Keycloak reset-password + audit publisher) for
the self-service password change.

Authentication is by bearer token (mirroring ``PATCH /sessions/me``): the mock
OIDC adapter's ``verify_token`` returns ``STUB_OIDC_CLAIMS`` so the caller is
resolved to the seeded user.  The DB layer is the ``FakeAsyncSession`` stub, so
we patch ``UserService.get_user`` to make the caller's row "exist" — exactly the
seeding strategy used by the PATCH /sessions/me test.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

from foundation_identity.domain.models import User
from foundation_identity.errors import INVALID_CREDENTIALS, FoundationError

# Mirrors tests.conftest.STUB_OIDC_CLAIMS — the bearer token resolves to this caller.
CALLER_USER_ID = "usr_01J5DEVUSER000000000000001"
CALLER_TENANT_ID = "tnt_01J5DEV00000000000000000A1"


def _seed_user() -> User:
    """Build an in-memory User row for the caller (no DB)."""
    user = User(
        id=CALLER_USER_ID,
        tenant_id=CALLER_TENANT_ID,
        email="stub-user@example.com",
        display_name="Stub User",
        status="ACTIVE",
        keycloak_user_id="kc-user-fake-uuid",
        roles=["user"],
        clearance="L2",
        mfa_enabled=False,
    )
    user.deleted_at = None
    return user


def _patch_get_user(seeded: User):
    async def _fake_get_user(self, session, *, tenant_id, user_id):
        # The caller must only ever resolve to themselves.
        assert user_id == CALLER_USER_ID
        assert tenant_id == CALLER_TENANT_ID
        return seeded

    return patch(
        "foundation_identity.services.user_service.UserService.get_user",
        new=_fake_get_user,
    )


@pytest.mark.integration
async def test_change_own_password_happy_path(
    client: AsyncClient,
    mock_keycloak: AsyncMock,
    mock_oidc: AsyncMock,
    mock_audit: AsyncMock,
) -> None:
    """Correct current password + strong new password → 204 + side effects.

    Verifies the BFF-facing contract:
      * 204 No Content (no body).
      * Current password verified via the OIDC password grant.
      * New password set via Admin reset_password(temporary=False).
      * foundation.identity.password.changed audit event published.
    """
    seeded = _seed_user()
    # Local-password user: a `password` credential exists, no federationLink.
    mock_keycloak.get_user.return_value = {"id": "kc-user-fake-uuid"}
    mock_keycloak.has_local_password.return_value = True

    with _patch_get_user(seeded):
        resp = await client.post(
            "/api/identity/v1/sessions/me/password",
            headers={"Authorization": "Bearer stub-access-token"},
            json={"current_password": "OldPassw0rd", "new_password": "NewStrongPassw0rd"},
        )

    assert resp.status_code == 204, resp.text
    assert resp.content == b""

    # Current password verified against the caller's email.
    mock_oidc.password_grant.assert_awaited_once()
    grant_kwargs = mock_oidc.password_grant.call_args.kwargs
    assert grant_kwargs["username"] == "stub-user@example.com"
    assert grant_kwargs["password"] == "OldPassw0rd"

    # New password set directly, non-temporary.
    mock_keycloak.reset_password.assert_awaited_once()
    rp_call = mock_keycloak.reset_password.call_args
    assert rp_call.args[0] == "kc-user-fake-uuid"
    assert rp_call.args[1] == "NewStrongPassw0rd"
    assert rp_call.kwargs.get("temporary") is False

    # Audit event published.
    mock_audit.publish.assert_called_once()
    audit_call = mock_audit.publish.call_args
    assert audit_call.kwargs["event_type"] == "foundation.identity.password.changed"
    assert audit_call.kwargs["tenant_id"] == CALLER_TENANT_ID
    assert audit_call.kwargs["payload"]["user_id"] == CALLER_USER_ID
    assert audit_call.kwargs["payload"]["source"] == "self_service"


@pytest.mark.integration
async def test_change_own_password_wrong_current_is_400(
    client: AsyncClient,
    mock_keycloak: AsyncMock,
    mock_oidc: AsyncMock,
    mock_audit: AsyncMock,
) -> None:
    """Wrong current password → 400 CURRENT_PASSWORD_INCORRECT, no write."""
    seeded = _seed_user()
    mock_keycloak.get_user.return_value = {"id": "kc-user-fake-uuid"}
    mock_keycloak.has_local_password.return_value = True
    # The OIDC password grant rejects bad credentials with INVALID_CREDENTIALS.
    mock_oidc.password_grant.side_effect = FoundationError(INVALID_CREDENTIALS)

    with _patch_get_user(seeded):
        resp = await client.post(
            "/api/identity/v1/sessions/me/password",
            headers={"Authorization": "Bearer stub-access-token"},
            json={"current_password": "WRONG", "new_password": "NewStrongPassw0rd"},
        )

    assert resp.status_code == 400, resp.text
    assert resp.json()["code"] == "FOUNDATION.IDENTITY.INPUT.CURRENT_PASSWORD_INCORRECT"
    # No password was set, no audit emitted.
    mock_keycloak.reset_password.assert_not_called()
    mock_audit.publish.assert_not_called()


@pytest.mark.integration
async def test_change_own_password_sso_account_is_409(
    client: AsyncClient,
    mock_keycloak: AsyncMock,
    mock_oidc: AsyncMock,
    mock_audit: AsyncMock,
) -> None:
    """Federated (SSO) account → 409 PASSWORD_CHANGE_NOT_ALLOWED, no verify/write.

    A non-empty ``federationLink`` on the KC user record marks the account as
    owned by an external IdP — there is no local password to change.
    """
    seeded = _seed_user()
    mock_keycloak.get_user.return_value = {
        "id": "kc-user-fake-uuid",
        "federationLink": "ldap-or-idp-link",
    }

    with _patch_get_user(seeded):
        resp = await client.post(
            "/api/identity/v1/sessions/me/password",
            headers={"Authorization": "Bearer stub-access-token"},
            json={"current_password": "whatever", "new_password": "NewStrongPassw0rd"},
        )

    assert resp.status_code == 409, resp.text
    assert resp.json()["code"] == "FOUNDATION.IDENTITY.STATE.PASSWORD_CHANGE_NOT_ALLOWED"
    # Federated accounts are rejected before verifying or setting anything.
    mock_oidc.password_grant.assert_not_called()
    mock_keycloak.reset_password.assert_not_called()
    mock_audit.publish.assert_not_called()


@pytest.mark.integration
async def test_change_own_password_passwordless_account_is_409(
    client: AsyncClient,
    mock_keycloak: AsyncMock,
    mock_oidc: AsyncMock,
    mock_audit: AsyncMock,
) -> None:
    """Account with no local `password` credential → 409, no verify/write."""
    seeded = _seed_user()
    mock_keycloak.get_user.return_value = {"id": "kc-user-fake-uuid"}
    mock_keycloak.has_local_password.return_value = False

    with _patch_get_user(seeded):
        resp = await client.post(
            "/api/identity/v1/sessions/me/password",
            headers={"Authorization": "Bearer stub-access-token"},
            json={"current_password": "whatever", "new_password": "NewStrongPassw0rd"},
        )

    assert resp.status_code == 409, resp.text
    assert resp.json()["code"] == "FOUNDATION.IDENTITY.STATE.PASSWORD_CHANGE_NOT_ALLOWED"
    mock_oidc.password_grant.assert_not_called()
    mock_keycloak.reset_password.assert_not_called()


@pytest.mark.integration
async def test_change_own_password_weak_new_is_422(
    client: AsyncClient,
    mock_keycloak: AsyncMock,
    mock_oidc: AsyncMock,
    mock_audit: AsyncMock,
) -> None:
    """New password below the length floor (8) → 422 PASSWORD_TOO_WEAK, no write.

    The current password is NOT verified in this case — policy is checked first,
    so a weak new password fails fast without a Keycloak round-trip.
    """
    seeded = _seed_user()
    mock_keycloak.get_user.return_value = {"id": "kc-user-fake-uuid"}
    mock_keycloak.has_local_password.return_value = True

    with _patch_get_user(seeded):
        resp = await client.post(
            "/api/identity/v1/sessions/me/password",
            headers={"Authorization": "Bearer stub-access-token"},
            json={"current_password": "OldPassw0rd", "new_password": "short"},
        )

    assert resp.status_code == 422, resp.text
    assert resp.json()["code"] == "FOUNDATION.IDENTITY.INPUT.PASSWORD_TOO_WEAK"
    mock_oidc.password_grant.assert_not_called()
    mock_keycloak.reset_password.assert_not_called()
    mock_audit.publish.assert_not_called()


@pytest.mark.integration
async def test_change_own_password_requires_bearer(
    client: AsyncClient,
) -> None:
    """No Authorization header → 401 (token invalid), never reaching the service."""
    resp = await client.post(
        "/api/identity/v1/sessions/me/password",
        json={"current_password": "x", "new_password": "NewStrongPassw0rd"},
    )
    assert resp.status_code == 401, resp.text


@pytest.mark.integration
async def test_change_own_password_rejects_extra_fields(
    client: AsyncClient,
) -> None:
    """extra='forbid' blocks smuggling (e.g. target user_id) → 422, no write."""
    resp = await client.post(
        "/api/identity/v1/sessions/me/password",
        headers={"Authorization": "Bearer stub-access-token"},
        json={
            "current_password": "x",
            "new_password": "NewStrongPassw0rd",
            "user_id": "usr_someoneelse",
        },
    )
    assert resp.status_code == 422, resp.text
