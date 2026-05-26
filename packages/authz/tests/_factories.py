"""ORM-object factory helpers shared across authz unit tests.

Pulled out of conftest.py so test files can `from tests._factories import ...`
without depending on conftest import semantics.
"""

from __future__ import annotations

from datetime import UTC, datetime

from foundation_authz.domain.models import (
    Outbox,
    PermissionDefinition,
    Role,
    RoleBinding,
)


def make_role(
    *,
    role_id: str = "rol_01J0000000000000000000ROL1",
    tenant_id: str = "tnt_01J0000000000000000000TNT1",
    name: str = "viewer",
    display_name: str = "Viewer",
    permissions: list[str] | None = None,
    is_system: bool = False,
    immutable: bool = False,
    deleted: bool = False,
) -> Role:
    r = Role(
        id=role_id,
        tenant_id=tenant_id,
        name=name,
        display_name=display_name,
        description=None,
        is_system=is_system,
        immutable=immutable,
        permissions=permissions or [],
        created_by="usr_01J0000000000000000000ACT1",
    )
    now = datetime.now(UTC)
    r.created_at = now
    r.updated_at = now
    if deleted:
        r.deleted_at = now
    return r


def make_binding(
    *,
    binding_id: str = "rbd_01J0000000000000000000RBD1",
    tenant_id: str = "tnt_01J0000000000000000000TNT1",
    principal_kind: str = "USER",
    principal_id: str = "usr_01J0000000000000000000USR1",
    role_id: str = "rol_01J0000000000000000000ROL1",
    scope_kind: str = "TENANT",
    scope_id: str | None = None,
    expires_at: datetime | None = None,
    revoked: bool = False,
) -> RoleBinding:
    b = RoleBinding(
        id=binding_id,
        tenant_id=tenant_id,
        principal_kind=principal_kind,
        principal_id=principal_id,
        role_id=role_id,
        scope_kind=scope_kind,
        scope_id=scope_id,
        expires_at=expires_at,
        granted_by="usr_01J0000000000000000000ACT1",
        grant_reason=None,
    )
    b.granted_at = datetime.now(UTC)
    if revoked:
        b.revoked_at = datetime.now(UTC)
        b.revoked_by = "usr_01J0000000000000000000ACT1"
    return b


def make_permission(
    *,
    permission_id: str = "billing.invoice.read",
    service: str = "billing",
    resource_type: str = "invoice",
    action: str = "read",
    risk_level: str = "LOW",
    requires_mfa: bool = False,
    requires_4eyes: bool = False,
    requires_pam_jit: bool = False,
    requires_business_hours: bool = False,
) -> PermissionDefinition:
    p = PermissionDefinition(
        id=permission_id,
        service=service,
        resource_type=resource_type,
        action=action,
        description=f"{service}.{resource_type}.{action}",
        risk_level=risk_level,
        requires_mfa=requires_mfa,
        requires_4eyes=requires_4eyes,
        requires_pam_jit=requires_pam_jit,
        requires_business_hours=requires_business_hours,
        is_system=True,
    )
    p.created_at = datetime.now(UTC)
    return p


def outbox_events_of_type(added: list[object], event_type: str) -> list[Outbox]:
    return [
        o for o in added
        if isinstance(o, Outbox) and o.event_type == event_type
    ]
