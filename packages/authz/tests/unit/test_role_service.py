"""RoleService CRUD tests."""

from __future__ import annotations

import pytest

from foundation_authz.errors import (
    PERMISSION_ESCALATION,
    ROLE_ALREADY_EXISTS,
    ROLE_HAS_BINDINGS,
    ROLE_IMMUTABLE,
    ROLE_NOT_FOUND,
    FoundationError,
)
from foundation_authz.services.role_service import RoleService

from tests._factories import make_binding, make_role
from tests.conftest import FakeAsyncSession


pytestmark = pytest.mark.unit

# Omnipotent actor permission set: delegates anything (used where escalation is
# not under test, so the guard is transparent).
_SUPER = {"*"}
# tenant_admin-like set: broad business perms + the two authz management tokens,
# but NOT "*".
_TENANT_ADMIN = {
    "session.*",
    "run.*",
    "sandbox.*",
    "skill.*",
    "document.*",
    "mcp_server.*",
    "app.*",
    "authz.role.manage",
    "authz.binding.manage",
}


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------

async def test_create_role_succeeds(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    request_id: str,
) -> None:
    fake_session.queue_scalar(None)  # uniqueness check returns no existing role

    svc = RoleService(audit=audit_publisher)
    role = await svc.create(
        fake_session,
        tenant_id=tenant_id,
        request_id=request_id,
        actor_id=actor_id,
        actor_perms=_SUPER,
        name="custom_role",
        display_name="Custom Role",
        description="A test role",
        permissions=["billing.invoice.read"],
    )

    assert role.id.startswith("rol_")
    assert role.tenant_id == tenant_id
    assert role.name == "custom_role"
    assert role.permissions == ["billing.invoice.read"]
    assert role.is_system is False
    assert role.created_by == actor_id

    assert role in fake_session.added
    assert fake_session.flush_calls >= 1
    audit_publisher.publish.assert_awaited_once()
    call = audit_publisher.publish.await_args
    assert call.kwargs["event_type"] == "foundation.authz.role.created"
    assert call.kwargs["tenant_id"] == tenant_id
    assert call.kwargs["aggregate_id"] == role.id
    assert call.kwargs["request_id"] == request_id


async def test_create_role_duplicate_name_rejected(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    request_id: str,
) -> None:
    existing = make_role(tenant_id=tenant_id, name="custom_role")
    fake_session.queue_scalar(existing)  # uniqueness check finds existing

    svc = RoleService(audit=audit_publisher)
    with pytest.raises(FoundationError) as ei:
        await svc.create(
            fake_session,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=actor_id,
            actor_perms=_SUPER,
            name="custom_role",
            display_name="Dup",
            description=None,
            permissions=[],
        )

    assert ei.value.error_code is ROLE_ALREADY_EXISTS
    assert ei.value.extra == {"name": "custom_role"}
    audit_publisher.publish.assert_not_awaited()


# ---------------------------------------------------------------------------
# get / list
# ---------------------------------------------------------------------------

async def test_get_role_not_found_raises(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
) -> None:
    svc = RoleService(audit=audit_publisher)
    with pytest.raises(FoundationError) as ei:
        await svc.get(fake_session, tenant_id=tenant_id, role_id="rol_DOES_NOT_EXIST")
    assert ei.value.error_code is ROLE_NOT_FOUND


async def test_get_role_cross_tenant_returns_not_found(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
) -> None:
    other_tenant = "tnt_01J0000000000000000000OTH1"
    role = make_role(tenant_id=other_tenant)
    fake_session.put(role)

    svc = RoleService(audit=audit_publisher)
    with pytest.raises(FoundationError) as ei:
        await svc.get(fake_session, tenant_id=tenant_id, role_id=role.id)
    assert ei.value.error_code is ROLE_NOT_FOUND


async def test_get_role_soft_deleted_treated_as_missing(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
) -> None:
    role = make_role(tenant_id=tenant_id, deleted=True)
    fake_session.put(role)

    svc = RoleService(audit=audit_publisher)
    with pytest.raises(FoundationError) as ei:
        await svc.get(fake_session, tenant_id=tenant_id, role_id=role.id)
    assert ei.value.error_code is ROLE_NOT_FOUND


async def test_list_roles_paginates(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
) -> None:
    rows = [
        make_role(role_id=f"rol_01J000000000000000000ROL{i}", tenant_id=tenant_id, name=f"r{i}")
        for i in range(5)
    ]
    fake_session.queue_scalars(rows[:3])

    svc = RoleService(audit=audit_publisher)
    items, next_cursor = await svc.list_roles(
        fake_session, tenant_id=tenant_id, cursor=None, limit=2
    )
    assert len(items) == 2
    assert next_cursor == rows[2].id  # limit+1 row signals next page


async def test_list_roles_last_page_returns_no_cursor(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
) -> None:
    rows = [make_role(role_id="rol_01J000000000000000000ROLA", tenant_id=tenant_id, name="r1")]
    fake_session.queue_scalars(rows)

    svc = RoleService(audit=audit_publisher)
    items, next_cursor = await svc.list_roles(
        fake_session, tenant_id=tenant_id, cursor=None, limit=10
    )
    assert items == rows
    assert next_cursor is None


# ---------------------------------------------------------------------------
# update
# ---------------------------------------------------------------------------

async def test_update_role_patches_fields(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    request_id: str,
) -> None:
    role = make_role(tenant_id=tenant_id, permissions=["a.b.c"])
    fake_session.put(role)

    svc = RoleService(audit=audit_publisher)
    updated = await svc.update(
        fake_session,
        tenant_id=tenant_id,
        request_id=request_id,
        actor_id=actor_id,
        actor_perms=_SUPER,
        role_id=role.id,
        patch={"display_name": "New Name", "permissions": ["x.y.z"]},
    )
    assert updated.display_name == "New Name"
    assert updated.permissions == ["x.y.z"]
    audit_publisher.publish.assert_awaited_once()
    payload = audit_publisher.publish.await_args.kwargs["payload"]
    assert payload["changed_fields"] == ["display_name", "permissions"]


async def test_update_role_system_immutable_rejected(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    request_id: str,
) -> None:
    role = make_role(tenant_id=tenant_id, is_system=True)
    fake_session.put(role)

    svc = RoleService(audit=audit_publisher)
    with pytest.raises(FoundationError) as ei:
        await svc.update(
            fake_session,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=actor_id,
            actor_perms=_SUPER,
            role_id=role.id,
            patch={"display_name": "Nope"},
        )
    assert ei.value.error_code is ROLE_IMMUTABLE
    audit_publisher.publish.assert_not_awaited()


async def test_update_role_immutable_flag_rejected(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    request_id: str,
) -> None:
    role = make_role(tenant_id=tenant_id, immutable=True)
    fake_session.put(role)

    svc = RoleService(audit=audit_publisher)
    with pytest.raises(FoundationError) as ei:
        await svc.update(
            fake_session,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=actor_id,
            actor_perms=_SUPER,
            role_id=role.id,
            patch={"display_name": "Nope"},
        )
    assert ei.value.error_code is ROLE_IMMUTABLE


async def test_update_role_skips_none_values(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    request_id: str,
) -> None:
    role = make_role(tenant_id=tenant_id, permissions=["keep.me"])
    fake_session.put(role)

    svc = RoleService(audit=audit_publisher)
    updated = await svc.update(
        fake_session,
        tenant_id=tenant_id,
        request_id=request_id,
        actor_id=actor_id,
        actor_perms=_SUPER,
        role_id=role.id,
        patch={"description": "new desc", "permissions": None},
    )
    assert updated.description == "new desc"
    assert updated.permissions == ["keep.me"]


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------

async def test_delete_role_soft_deletes(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    request_id: str,
) -> None:
    role = make_role(tenant_id=tenant_id)
    fake_session.put(role)
    fake_session.queue_scalar(None)  # no active bindings

    svc = RoleService(audit=audit_publisher)
    await svc.delete(
        fake_session,
        tenant_id=tenant_id,
        request_id=request_id,
        actor_id=actor_id,
        role_id=role.id,
    )
    assert role.deleted_at is not None
    audit_publisher.publish.assert_awaited_once()
    assert audit_publisher.publish.await_args.kwargs["event_type"] == "foundation.authz.role.deleted"


async def test_delete_role_with_active_bindings_rejected(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    request_id: str,
) -> None:
    role = make_role(tenant_id=tenant_id)
    fake_session.put(role)
    fake_session.queue_scalar(make_binding(tenant_id=tenant_id, role_id=role.id))

    svc = RoleService(audit=audit_publisher)
    with pytest.raises(FoundationError) as ei:
        await svc.delete(
            fake_session,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=actor_id,
            role_id=role.id,
        )
    assert ei.value.error_code is ROLE_HAS_BINDINGS
    assert role.deleted_at is None
    audit_publisher.publish.assert_not_awaited()


async def test_delete_system_role_rejected(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    request_id: str,
) -> None:
    role = make_role(tenant_id=tenant_id, is_system=True)
    fake_session.put(role)

    svc = RoleService(audit=audit_publisher)
    with pytest.raises(FoundationError) as ei:
        await svc.delete(
            fake_session,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=actor_id,
            role_id=role.id,
        )
    assert ei.value.error_code is ROLE_IMMUTABLE


# ---------------------------------------------------------------------------
# create / update — anti-escalation
# ---------------------------------------------------------------------------

async def test_create_role_escalation_rejected_for_tenant_admin(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    request_id: str,
) -> None:
    """tenant_admin (no "*") creating a role with an out-of-scope perm → 403.

    ``platform.admin`` is not covered by any tenant_admin token, so the create is
    refused before any write or uniqueness probe.
    """
    svc = RoleService(audit=audit_publisher)
    with pytest.raises(FoundationError) as ei:
        await svc.create(
            fake_session,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=actor_id,
            actor_perms=_TENANT_ADMIN,
            name="escalated",
            display_name="Escalated",
            description=None,
            permissions=["session.read", "platform.admin"],
        )
    assert ei.value.error_code is PERMISSION_ESCALATION
    assert ei.value.extra == {"permission": "platform.admin"}
    audit_publisher.publish.assert_not_awaited()
    assert fake_session.added == []  # nothing persisted


async def test_create_role_authz_token_not_delegable_by_tenant_admin(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    request_id: str,
) -> None:
    """Even though tenant_admin HOLDS authz.role.manage, it cannot DELEGATE it.

    Management non-delegation: only a holder of the bare "*" may grant authz.* .
    """
    svc = RoleService(audit=audit_publisher)
    with pytest.raises(FoundationError) as ei:
        await svc.create(
            fake_session,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=actor_id,
            actor_perms=_TENANT_ADMIN,
            name="mini_admin",
            display_name="Mini Admin",
            description=None,
            permissions=["authz.role.manage"],
        )
    assert ei.value.error_code is PERMISSION_ESCALATION
    assert ei.value.extra == {"permission": "authz.role.manage"}


async def test_create_role_in_scope_allowed_for_tenant_admin(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    request_id: str,
) -> None:
    """tenant_admin CAN create a role with perms it covers (session.read ⊂ session.*)."""
    fake_session.queue_scalar(None)  # uniqueness check: no existing role

    svc = RoleService(audit=audit_publisher)
    role = await svc.create(
        fake_session,
        tenant_id=tenant_id,
        request_id=request_id,
        actor_id=actor_id,
        actor_perms=_TENANT_ADMIN,
        name="viewer",
        display_name="Viewer",
        description=None,
        permissions=["session.read", "run.read", "document.search"],
    )
    assert role.name == "viewer"
    assert role in fake_session.added


async def test_create_role_super_admin_can_grant_anything(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    request_id: str,
) -> None:
    """super_admin (holds "*") may grant any token, including authz.* — no regression."""
    fake_session.queue_scalar(None)

    svc = RoleService(audit=audit_publisher)
    role = await svc.create(
        fake_session,
        tenant_id=tenant_id,
        request_id=request_id,
        actor_id=actor_id,
        actor_perms=_SUPER,
        name="another_admin",
        display_name="Another Admin",
        description=None,
        permissions=["authz.role.manage", "authz.binding.manage", "platform.admin", "*"],
    )
    assert role in fake_session.added


async def test_update_role_escalation_on_permissions_patch_rejected(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    request_id: str,
) -> None:
    """Updating permissions to include an out-of-scope token → 403 (full-set check)."""
    role = make_role(tenant_id=tenant_id, permissions=["session.read"])
    fake_session.put(role)

    svc = RoleService(audit=audit_publisher)
    with pytest.raises(FoundationError) as ei:
        await svc.update(
            fake_session,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=actor_id,
            actor_perms=_TENANT_ADMIN,
            role_id=role.id,
            patch={"permissions": ["session.read", "platform.admin"]},
        )
    assert ei.value.error_code is PERMISSION_ESCALATION
    audit_publisher.publish.assert_not_awaited()


async def test_update_role_non_permission_patch_skips_escalation_check(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    request_id: str,
) -> None:
    """A patch without 'permissions' is not subject to the grant check.

    Even with an empty actor_perms set, renaming an existing role is allowed —
    the escalation guard only fires when the patch carries a permissions array.
    """
    role = make_role(tenant_id=tenant_id, permissions=["session.read"])
    fake_session.put(role)

    svc = RoleService(audit=audit_publisher)
    updated = await svc.update(
        fake_session,
        tenant_id=tenant_id,
        request_id=request_id,
        actor_id=actor_id,
        actor_perms=set(),
        role_id=role.id,
        patch={"display_name": "Renamed"},
    )
    assert updated.display_name == "Renamed"
