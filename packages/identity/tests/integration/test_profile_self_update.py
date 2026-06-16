"""Integration test: PATCH /sessions/me self-service profile update.

Exercises the full app stack (middleware → router → bearer-verify → service →
Keycloak sync + audit publisher) for the self-service ``display_name`` update.

Authentication is by bearer token (mirroring ``GET /sessions/me``): the mock
OIDC adapter's ``verify_token`` returns ``STUB_OIDC_CLAIMS`` so the caller is
resolved to the seeded user.  The DB layer is the ``FakeAsyncSession`` stub, so
we patch ``UserService.get_user`` to make the caller's row "exist" — exactly the
seeding strategy used by the PATCH /users tests.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

from foundation_identity.domain.models import User

# Mirrors tests.conftest.STUB_OIDC_CLAIMS — the bearer token resolves to this caller.
CALLER_USER_ID = "usr_01J5DEVUSER000000000000001"
CALLER_TENANT_ID = "tnt_01J5DEV00000000000000000A1"


def _seed_user(display_name: str = "Old Name") -> User:
    """Build an in-memory User row for the caller (no DB)."""
    user = User(
        id=CALLER_USER_ID,
        tenant_id=CALLER_TENANT_ID,
        email="stub-user@example.com",
        display_name=display_name,
        status="ACTIVE",
        keycloak_user_id="kc-user-fake-uuid",
        roles=["user"],
        clearance="L2",
        mfa_enabled=False,
    )
    user.deleted_at = None
    return user


@pytest.mark.integration
async def test_update_my_profile_happy_path(
    client: AsyncClient,
    mock_keycloak: AsyncMock,
    mock_audit: AsyncMock,
) -> None:
    """PATCH /sessions/me with a new display_name → 200 + updated value + side effects.

    Verifies the contract the BFF relies on:
      * 200 with a MeResponse whose display_name is the freshly-saved value.
      * Keycloak firstName sync fired (mock_keycloak.update_user called).
      * foundation.identity.user.updated audit event published.
      * Target user is the caller (resolved from bearer token), not a path param.
    """
    seeded = _seed_user(display_name="Old Name")

    async def _fake_get_user(self, session, *, tenant_id, user_id):
        # The caller must only ever resolve to themselves.
        assert user_id == CALLER_USER_ID
        assert tenant_id == CALLER_TENANT_ID
        return seeded

    with patch(
        "foundation_identity.services.user_service.UserService.get_user",
        new=_fake_get_user,
    ):
        resp = await client.patch(
            "/api/identity/v1/sessions/me",
            headers={"Authorization": "Bearer stub-access-token"},
            json={"display_name": "Brand New Name"},
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["user_id"] == CALLER_USER_ID
    assert body["tenant_id"] == CALLER_TENANT_ID
    assert body["display_name"] == "Brand New Name"
    assert body["email"] == "stub-user@example.com"
    assert body["roles"] == ["user"]

    # Keycloak firstName sync fired with the new name.
    mock_keycloak.update_user.assert_called_once()
    kc_call = mock_keycloak.update_user.call_args
    assert kc_call.args[0] == "kc-user-fake-uuid"
    assert kc_call.args[1] == {"firstName": "Brand New Name"}

    # Audit event published for the update.
    mock_audit.publish.assert_called_once()
    audit_call = mock_audit.publish.call_args
    assert audit_call.kwargs["event_type"] == "foundation.identity.user.updated"
    assert audit_call.kwargs["tenant_id"] == CALLER_TENANT_ID
    assert audit_call.kwargs["payload"]["user_id"] == CALLER_USER_ID
    assert "display_name" in audit_call.kwargs["payload"]["changed_fields"]


@pytest.mark.integration
async def test_update_my_profile_missing_display_name_is_422(
    client: AsyncClient,
    mock_keycloak: AsyncMock,
    mock_audit: AsyncMock,
) -> None:
    """display_name is the only thing this endpoint sets — omitting it is a 422.

    No write must happen (no Keycloak sync, no audit event).
    """
    resp = await client.patch(
        "/api/identity/v1/sessions/me",
        headers={"Authorization": "Bearer stub-access-token"},
        json={},
    )
    assert resp.status_code == 422, resp.text
    body = resp.json()
    assert body["code"] == "FOUNDATION.IDENTITY.INPUT.VALIDATION_FAILED"
    mock_keycloak.update_user.assert_not_called()
    mock_audit.publish.assert_not_called()


@pytest.mark.integration
async def test_update_my_profile_rejects_extra_fields(
    client: AsyncClient,
) -> None:
    """extra='forbid' blocks privilege smuggling (status/roles) → 422, no write."""
    resp = await client.patch(
        "/api/identity/v1/sessions/me",
        headers={"Authorization": "Bearer stub-access-token"},
        json={"display_name": "X", "roles": ["admin"], "status": "ACTIVE"},
    )
    assert resp.status_code == 422, resp.text


@pytest.mark.integration
async def test_update_my_profile_requires_bearer(
    client: AsyncClient,
) -> None:
    """No Authorization header → 401 (token invalid), never reaching the service."""
    resp = await client.patch(
        "/api/identity/v1/sessions/me",
        json={"display_name": "X"},
    )
    assert resp.status_code == 401, resp.text
