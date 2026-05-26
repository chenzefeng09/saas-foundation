"""BindingService CRUD tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from foundation_authz.errors import (
    BINDING_NOT_FOUND,
    ROLE_NOT_FOUND,
    FoundationError,
)
from foundation_authz.services.binding_service import BindingService

from tests._factories import make_binding, make_role
from tests.conftest import FakeAsyncSession


pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------

async def test_create_binding_succeeds(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    user_id: str,
    request_id: str,
) -> None:
    role = make_role(tenant_id=tenant_id)
    fake_session.put(role)

    svc = BindingService(audit=audit_publisher)
    binding = await svc.create(
        fake_session,
        tenant_id=tenant_id,
        request_id=request_id,
        actor_id=actor_id,
        principal_kind="USER",
        principal_id=user_id,
        role_id=role.id,
        scope_kind="TENANT",
        scope_id=None,
        expires_at=None,
        grant_reason="onboarding",
    )

    assert binding.id.startswith("rbd_")
    assert binding.tenant_id == tenant_id
    assert binding.principal_id == user_id
    assert binding.role_id == role.id
    assert binding.granted_by == actor_id
    assert binding.revoked_at is None
    assert binding in fake_session.added
    assert fake_session.flush_calls >= 1

    audit_publisher.publish.assert_awaited_once()
    call = audit_publisher.publish.await_args
    assert call.kwargs["event_type"] == "foundation.authz.binding.created"
    assert call.kwargs["payload"]["grant_reason"] == "onboarding"


async def test_create_binding_unknown_role_raises_404(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    user_id: str,
    request_id: str,
) -> None:
    svc = BindingService(audit=audit_publisher)
    with pytest.raises(FoundationError) as ei:
        await svc.create(
            fake_session,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=actor_id,
            principal_kind="USER",
            principal_id=user_id,
            role_id="rol_01J0000000000000000000ROLX",
            scope_kind="TENANT",
            scope_id=None,
            expires_at=None,
            grant_reason=None,
        )
    assert ei.value.error_code is ROLE_NOT_FOUND
    audit_publisher.publish.assert_not_awaited()


async def test_create_binding_cross_tenant_role_rejected(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    user_id: str,
    request_id: str,
) -> None:
    other_tenant = "tnt_01J0000000000000000000OTH1"
    role = make_role(tenant_id=other_tenant)
    fake_session.put(role)  # exists, but in different tenant

    svc = BindingService(audit=audit_publisher)
    with pytest.raises(FoundationError) as ei:
        await svc.create(
            fake_session,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=actor_id,
            principal_kind="USER",
            principal_id=user_id,
            role_id=role.id,
            scope_kind="TENANT",
            scope_id=None,
            expires_at=None,
            grant_reason=None,
        )
    assert ei.value.error_code is ROLE_NOT_FOUND


async def test_create_binding_with_expiry_persists_value(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    user_id: str,
    request_id: str,
) -> None:
    role = make_role(tenant_id=tenant_id)
    fake_session.put(role)
    expires = datetime.now(UTC) + timedelta(days=30)

    svc = BindingService(audit=audit_publisher)
    binding = await svc.create(
        fake_session,
        tenant_id=tenant_id,
        request_id=request_id,
        actor_id=actor_id,
        principal_kind="USER",
        principal_id=user_id,
        role_id=role.id,
        scope_kind="TENANT",
        scope_id=None,
        expires_at=expires,
        grant_reason=None,
    )
    assert binding.expires_at == expires
    payload = audit_publisher.publish.await_args.kwargs["payload"]
    assert payload["expires_at"] == expires.isoformat()


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

async def test_list_bindings_paginates(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
) -> None:
    bindings = [
        make_binding(binding_id=f"rbd_01J000000000000000000RBD{i}", tenant_id=tenant_id)
        for i in range(5)
    ]
    fake_session.queue_scalars(bindings[:3])

    svc = BindingService(audit=audit_publisher)
    items, next_cursor = await svc.list(
        fake_session, tenant_id=tenant_id, cursor=None, limit=2
    )
    assert len(items) == 2
    assert next_cursor == bindings[2].id


async def test_list_bindings_passes_through_filters(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    user_id: str,
) -> None:
    """Smoke: filters don't crash; result staging still produces output."""
    fake_session.queue_scalars([])
    svc = BindingService(audit=audit_publisher)
    items, _ = await svc.list(
        fake_session,
        tenant_id=tenant_id,
        cursor=None,
        limit=10,
        principal_kind="USER",
        principal_id=user_id,
        role_id="rol_01J0000000000000000000ROL1",
    )
    assert items == []


# ---------------------------------------------------------------------------
# revoke
# ---------------------------------------------------------------------------

async def test_revoke_binding_marks_revoked_and_audits(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    request_id: str,
) -> None:
    binding = make_binding(tenant_id=tenant_id)
    fake_session.put(binding)

    svc = BindingService(audit=audit_publisher)
    await svc.revoke(
        fake_session,
        tenant_id=tenant_id,
        request_id=request_id,
        actor_id=actor_id,
        binding_id=binding.id,
        reason="offboarding",
    )
    assert binding.revoked_at is not None
    assert binding.revoked_by == actor_id
    assert binding.revoked_reason == "offboarding"
    audit_publisher.publish.assert_awaited_once()
    assert (
        audit_publisher.publish.await_args.kwargs["event_type"]
        == "foundation.authz.binding.revoked"
    )


async def test_revoke_binding_idempotent_when_already_revoked(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    request_id: str,
) -> None:
    binding = make_binding(tenant_id=tenant_id, revoked=True)
    original_revoked_at = binding.revoked_at
    fake_session.put(binding)

    svc = BindingService(audit=audit_publisher)
    await svc.revoke(
        fake_session,
        tenant_id=tenant_id,
        request_id=request_id,
        actor_id=actor_id,
        binding_id=binding.id,
        reason="dup",
    )
    # No-op: timestamp unchanged, no audit event
    assert binding.revoked_at == original_revoked_at
    audit_publisher.publish.assert_not_awaited()


async def test_revoke_unknown_binding_raises_404(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    request_id: str,
) -> None:
    svc = BindingService(audit=audit_publisher)
    with pytest.raises(FoundationError) as ei:
        await svc.revoke(
            fake_session,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=actor_id,
            binding_id="rbd_01J0000000000000000000NONE",
            reason=None,
        )
    assert ei.value.error_code is BINDING_NOT_FOUND


async def test_revoke_cross_tenant_binding_treated_as_not_found(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    request_id: str,
) -> None:
    other = "tnt_01J0000000000000000000OTH1"
    binding = make_binding(tenant_id=other)
    fake_session.put(binding)

    svc = BindingService(audit=audit_publisher)
    with pytest.raises(FoundationError) as ei:
        await svc.revoke(
            fake_session,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=actor_id,
            binding_id=binding.id,
            reason=None,
        )
    assert ei.value.error_code is BINDING_NOT_FOUND
