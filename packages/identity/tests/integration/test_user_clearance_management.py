"""Tenant-admin clearance management through the user API."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

from foundation_identity.domain.models import User

CALLER_USER_ID = "usr_01J5DEVUSER000000000000001"
TARGET_USER_ID = "usr_01J5DEVUSER000000000000002"
TENANT_ID = "tnt_01J5DEV00000000000000000A1"


def _seed_user(*, user_id: str = TARGET_USER_ID, clearance: str | None = "L3") -> User:
    now = datetime.now(UTC)
    user = User(
        id=user_id,
        tenant_id=TENANT_ID,
        email="target@example.com",
        display_name="Target User",
        status="ACTIVE",
        keycloak_user_id="kc-target-uuid",
        roles=["USER"],
        clearance=clearance,
        mfa_enabled=False,
        created_at=now,
        updated_at=now,
    )
    user.deleted_at = None
    return user


@pytest.mark.integration
async def test_update_clearance_persists_syncs_keycloak_and_emits_minimal_audit(
    client: AsyncClient,
    tenant_headers: dict[str, str],
    mock_keycloak: AsyncMock,
    mock_audit: AsyncMock,
) -> None:
    seeded = _seed_user(clearance="L3")
    management_headers = {**tenant_headers, "X-Actor": "SERVICE"}
    mock_keycloak.get_user.return_value = {
        "attributes": {
            "tenant_id": [TENANT_ID],
            "user_id": [TARGET_USER_ID],
            "clearance": ["L3"],
            "locale": ["zh-CN"],
        }
    }

    async def _fake_get_user(
        self: object,
        session: object,
        *,
        tenant_id: str,
        user_id: str,
    ) -> User:
        assert tenant_id == TENANT_ID
        assert user_id == TARGET_USER_ID
        return seeded

    with patch(
        "foundation_identity.services.user_service.UserService.get_user",
        new=_fake_get_user,
    ):
        resp = await client.patch(
            f"/api/identity/v1/users/{TARGET_USER_ID}",
            headers=management_headers,
            json={"clearance": "L4"},
        )

    assert resp.status_code == 200, resp.text
    assert resp.json()["clearance"] == "L4"
    assert seeded.clearance == "L4"
    mock_keycloak.get_user.assert_awaited_once_with("kc-target-uuid")
    mock_keycloak.update_user.assert_awaited_once_with(
        "kc-target-uuid",
        {
            "attributes": {
                "tenant_id": [TENANT_ID],
                "user_id": [TARGET_USER_ID],
                "clearance": ["L4"],
                "locale": ["zh-CN"],
            }
        },
    )

    audit_payload = mock_audit.publish.call_args.kwargs["payload"]
    assert audit_payload == {
        "user_id": TARGET_USER_ID,
        "changed_fields": ["clearance"],
        "updated_by": CALLER_USER_ID,
        "clearance_change": {"from": "L3", "to": "L4"},
    }


@pytest.mark.integration
async def test_regular_user_cannot_change_another_users_clearance(
    client: AsyncClient,
    tenant_headers: dict[str, str],
    mock_keycloak: AsyncMock,
) -> None:
    resp = await client.patch(
        f"/api/identity/v1/users/{TARGET_USER_ID}",
        headers=tenant_headers,
        json={"clearance": "L5"},
    )

    assert resp.status_code == 403, resp.text
    mock_keycloak.get_user.assert_not_awaited()
    mock_keycloak.update_user.assert_not_awaited()


@pytest.mark.integration
async def test_get_user_returns_l3_for_legacy_null_clearance(
    client: AsyncClient,
    tenant_headers: dict[str, str],
) -> None:
    seeded = _seed_user(clearance=None)

    async def _fake_get_user(
        self: object,
        session: object,
        *,
        tenant_id: str,
        user_id: str,
    ) -> User:
        return seeded

    with patch(
        "foundation_identity.services.user_service.UserService.get_user",
        new=_fake_get_user,
    ):
        resp = await client.get(
            f"/api/identity/v1/users/{TARGET_USER_ID}",
            headers=tenant_headers,
        )

    assert resp.status_code == 200, resp.text
    assert resp.json()["clearance"] == "L3"


@pytest.mark.integration
async def test_user_cannot_modify_own_clearance(
    client: AsyncClient,
    tenant_headers: dict[str, str],
    mock_keycloak: AsyncMock,
    mock_audit: AsyncMock,
) -> None:
    seeded = _seed_user(user_id=CALLER_USER_ID, clearance="L3")

    async def _fake_get_user(
        self: object,
        session: object,
        *,
        tenant_id: str,
        user_id: str,
    ) -> User:
        return seeded

    with patch(
        "foundation_identity.services.user_service.UserService.get_user",
        new=_fake_get_user,
    ):
        resp = await client.patch(
            f"/api/identity/v1/users/{CALLER_USER_ID}",
            headers=tenant_headers,
            json={"clearance": "L5"},
        )

    assert resp.status_code == 403, resp.text
    assert seeded.clearance == "L3"
    mock_keycloak.get_user.assert_not_awaited()
    mock_keycloak.update_user.assert_not_awaited()
    mock_audit.publish.assert_not_awaited()


@pytest.mark.integration
@pytest.mark.parametrize("clearance", ["L0", "L6", "l3", "3", None])
async def test_update_user_rejects_invalid_clearance_before_service_call(
    client: AsyncClient,
    tenant_headers: dict[str, str],
    mock_keycloak: AsyncMock,
    clearance: object,
) -> None:
    resp = await client.patch(
        f"/api/identity/v1/users/{TARGET_USER_ID}",
        headers=tenant_headers,
        json={"clearance": clearance},
    )

    assert resp.status_code == 422, resp.text
    mock_keycloak.get_user.assert_not_awaited()
    mock_keycloak.update_user.assert_not_awaited()
