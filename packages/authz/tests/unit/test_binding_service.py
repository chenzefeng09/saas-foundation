"""BindingService CRUD tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from unittest.mock import AsyncMock

from foundation_authz.adapters.opa_client import OpaClient
from foundation_authz.errors import (
    BINDING_NOT_FOUND,
    PERMISSION_ESCALATION,
    ROLE_NOT_FOUND,
    FoundationError,
)
from foundation_authz.services.binding_service import BindingService
from foundation_authz.services.check_service import CheckService

from tests._factories import make_binding, make_role
from tests.conftest import FakeAsyncSession


pytestmark = pytest.mark.unit


# Actor permission set that delegates anything except authz.* (only "*" delegates
# authz.*).  Most existing tests use the omnipotent "*" so the anti-escalation
# guard is transparent and they exercise the original create behaviour.
_SUPER = {"*"}


def _check_svc() -> CheckService:
    """A real CheckService with a stubbed OPA — role_permission_closure only
    uses the DB (FakeAsyncSession), never OPA."""
    return CheckService(opa=AsyncMock(spec=OpaClient))


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
        actor_perms=_SUPER,
        check_svc=_check_svc(),
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
            actor_perms=_SUPER,
            check_svc=_check_svc(),
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
            actor_perms=_SUPER,
            check_svc=_check_svc(),
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
        actor_perms=_SUPER,
        check_svc=_check_svc(),
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
# create — anti-escalation
# ---------------------------------------------------------------------------

# tenant_admin-like effective set: broad business perms + the two specific authz
# management tokens, but NOT the bare "*" wildcard.
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


async def test_create_binding_to_super_admin_role_rejected_for_tenant_admin(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    user_id: str,
    request_id: str,
) -> None:
    """A tenant_admin (no "*") may not bind anyone to a super_admin role (perms=["*"]).

    Binding grants the target's full permission closure; "*" is only delegable by
    a holder of "*".  This is the core privilege-escalation guard.
    """
    super_admin = make_role(tenant_id=tenant_id, name="super_admin", permissions=["*"])
    fake_session.put(super_admin)

    svc = BindingService(audit=audit_publisher)
    with pytest.raises(FoundationError) as ei:
        await svc.create(
            fake_session,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=actor_id,
            actor_perms=_TENANT_ADMIN,
            check_svc=_check_svc(),
            principal_kind="USER",
            principal_id=user_id,
            role_id=super_admin.id,
            scope_kind="TENANT",
            scope_id=None,
            expires_at=None,
            grant_reason=None,
        )
    assert ei.value.error_code is PERMISSION_ESCALATION
    audit_publisher.publish.assert_not_awaited()


async def test_create_binding_to_super_admin_role_allowed_for_super_admin(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    user_id: str,
    request_id: str,
) -> None:
    """A super_admin (holds "*") may bind to a super_admin role — no regression."""
    super_admin = make_role(tenant_id=tenant_id, name="super_admin", permissions=["*"])
    fake_session.put(super_admin)

    svc = BindingService(audit=audit_publisher)
    binding = await svc.create(
        fake_session,
        tenant_id=tenant_id,
        request_id=request_id,
        actor_id=actor_id,
        actor_perms=_SUPER,
        check_svc=_check_svc(),
        principal_kind="USER",
        principal_id=user_id,
        role_id=super_admin.id,
        scope_kind="TENANT",
        scope_id=None,
        expires_at=None,
        grant_reason=None,
    )
    assert binding.role_id == super_admin.id
    audit_publisher.publish.assert_awaited_once()


async def test_create_binding_to_role_inheriting_star_rejected_for_tenant_admin(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    user_id: str,
    request_id: str,
) -> None:
    """Anti-escalation via the INHERITANCE closure (the path with no prior test).

    Role C holds NO dangerous direct permissions (``permissions=[]``) but inherits
    from parent role P whose ``permissions=["*"]``.  Binding a principal to C grants
    that principal C's *effective* closure — which includes the inherited "*" — so a
    tenant_admin (no "*") must be rejected with PERMISSION_ESCALATION.  This proves
    ``role_permission_closure`` walks ``RoleInherit`` and that the escalation guard
    fires on inherited (not just direct) tokens.

    Why this is NOT a false-green test (the trap the review flags):
    ``FakeAsyncSession.execute`` is statement-agnostic — it pops queued rows in FIFO
    order.  The closure walk issues exactly two ``execute`` calls:
      1) RoleInherit JOIN where child_role_id IN {C.id}  → we stage [(C.id, P)]
      2) RoleInherit JOIN where child_role_id IN {P.id}  → we stage []   (terminates)
    If the production merge logic were broken (didn't union the parent's perms, or
    skipped the inherit walk), the closure would be empty and is_grantable would
    PASS for the tenant_admin → the expected raise would NOT happen and this test
    would FAIL.  The control test below (super_admin allowed) consumes the SAME
    staged inheritance rows, so both halves genuinely traverse the inheritance walk.
    """
    child = make_role(
        role_id="rol_01J0000000000000000000CHLD",
        tenant_id=tenant_id,
        name="child_role",
        permissions=[],  # no dangerous direct perms
    )
    parent = make_role(
        role_id="rol_01J0000000000000000000PRNT",
        tenant_id=tenant_id,
        name="parent_super",
        permissions=["*"],  # the danger lives ONLY in the inherited parent
    )
    fake_session.put(child)
    fake_session.put(parent)
    # Stage the inheritance walk: iter 1 → child inherits parent; iter 2 → no more.
    fake_session.queue_execute([(child.id, parent)])
    fake_session.queue_execute([])

    svc = BindingService(audit=audit_publisher)
    with pytest.raises(FoundationError) as ei:
        await svc.create(
            fake_session,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=actor_id,
            actor_perms=_TENANT_ADMIN,
            check_svc=_check_svc(),
            principal_kind="USER",
            principal_id=user_id,
            role_id=child.id,
            scope_kind="TENANT",
            scope_id=None,
            expires_at=None,
            grant_reason=None,
        )
    assert ei.value.error_code is PERMISSION_ESCALATION
    # The offending token must be the INHERITED "*", proving inheritance expansion ran.
    assert ei.value.extra["permission"] == "*"
    assert ei.value.extra["role_id"] == child.id
    audit_publisher.publish.assert_not_awaited()


async def test_create_binding_to_role_inheriting_star_allowed_for_super_admin(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    user_id: str,
    request_id: str,
) -> None:
    """Control for the inheritance test: a super_admin (holds "*") MAY bind to a role
    that inherits "*".  Consumes the identical staged inheritance rows, so the
    closure walk genuinely traverses the parent — the only difference is the actor's
    permission set, isolating the escalation guard as the cause of the rejection above.
    """
    child = make_role(
        role_id="rol_01J0000000000000000000CHLD",
        tenant_id=tenant_id,
        name="child_role",
        permissions=[],
    )
    parent = make_role(
        role_id="rol_01J0000000000000000000PRNT",
        tenant_id=tenant_id,
        name="parent_super",
        permissions=["*"],
    )
    fake_session.put(child)
    fake_session.put(parent)
    fake_session.queue_execute([(child.id, parent)])
    fake_session.queue_execute([])

    svc = BindingService(audit=audit_publisher)
    binding = await svc.create(
        fake_session,
        tenant_id=tenant_id,
        request_id=request_id,
        actor_id=actor_id,
        actor_perms=_SUPER,
        check_svc=_check_svc(),
        principal_kind="USER",
        principal_id=user_id,
        role_id=child.id,
        scope_kind="TENANT",
        scope_id=None,
        expires_at=None,
        grant_reason=None,
    )
    assert binding.role_id == child.id
    audit_publisher.publish.assert_awaited_once()


async def test_create_binding_to_business_role_allowed_for_tenant_admin(
    fake_session: FakeAsyncSession,
    audit_publisher,
    tenant_id: str,
    actor_id: str,
    user_id: str,
    request_id: str,
) -> None:
    """tenant_admin CAN bind to a role whose perms it covers (session.read ⊂ session.*)."""
    role = make_role(tenant_id=tenant_id, name="viewer", permissions=["session.read", "run.read"])
    fake_session.put(role)

    svc = BindingService(audit=audit_publisher)
    binding = await svc.create(
        fake_session,
        tenant_id=tenant_id,
        request_id=request_id,
        actor_id=actor_id,
        actor_perms=_TENANT_ADMIN,
        check_svc=_check_svc(),
        principal_kind="USER",
        principal_id=user_id,
        role_id=role.id,
        scope_kind="TENANT",
        scope_id=None,
        expires_at=None,
        grant_reason=None,
    )
    assert binding.role_id == role.id


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
