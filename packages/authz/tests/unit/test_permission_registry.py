"""PermissionRegistry tests."""

from __future__ import annotations

import pytest

from foundation_authz.domain.models import PermissionDefinition
from foundation_authz.services.permission_registry import PermissionRegistry
from tests.conftest import FakeAsyncSession

pytestmark = pytest.mark.unit


def make_permission(permission_id: str = "billing.invoice.read") -> PermissionDefinition:
    return PermissionDefinition(
        id=permission_id,
        service="billing",
        resource_type="invoice",
        action="read",
        description="Read invoices",
        risk_level="LOW",
        requires_mfa=False,
        requires_4eyes=False,
        requires_pam_jit=False,
        requires_business_hours=False,
        is_system=True,
    )


async def test_list_all_returns_permissions(fake_session: FakeAsyncSession) -> None:
    rows = [make_permission(), make_permission("billing.invoice.write")]
    fake_session.queue_scalars(rows)

    result = await PermissionRegistry().list_all(fake_session, service="billing")

    assert result == rows


async def test_upsert_creates_missing_permission(fake_session: FakeAsyncSession) -> None:
    result = await PermissionRegistry().upsert(
        fake_session,
        permission_id="billing.invoice.approve",
        service="billing",
        resource_type="invoice",
        action="approve",
        description="Approve invoices",
        risk_level="HIGH",
        requires_mfa=True,
    )

    assert result.id == "billing.invoice.approve"
    assert result.requires_mfa is True
    assert result in fake_session.added
    assert fake_session.flush_calls == 1


async def test_upsert_updates_existing_permission(fake_session: FakeAsyncSession) -> None:
    existing = make_permission()
    fake_session.put(existing)

    result = await PermissionRegistry().upsert(
        fake_session,
        permission_id=existing.id,
        service="billing",
        resource_type="invoice",
        action="read",
        description="Updated",
        risk_level="CRITICAL",
        requires_mfa=True,
        requires_4eyes=True,
        requires_pam_jit=True,
        requires_business_hours=True,
    )

    assert result is existing
    assert existing.description == "Updated"
    assert existing.risk_level == "CRITICAL"
    assert existing.requires_4eyes is True
    assert existing.requires_pam_jit is True
    assert existing.requires_business_hours is True
    assert fake_session.flush_calls == 1
