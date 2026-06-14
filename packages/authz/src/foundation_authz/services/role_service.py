"""Role CRUD."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import ulid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_authz.adapters.audit_publisher import AuditPublisher
from foundation_authz.domain.models import Role, RoleBinding
from foundation_authz.errors import (
    PERMISSION_ESCALATION,
    ROLE_ALREADY_EXISTS,
    ROLE_HAS_BINDINGS,
    ROLE_IMMUTABLE,
    ROLE_NOT_FOUND,
    FoundationError,
)
from foundation_authz.services.check_service import is_grantable


def _new_role_id() -> str:
    return f"rol_{ulid.new()!s}"


def _assert_grantable(permissions: list[str], actor_perms: set[str]) -> None:
    """Reject any requested permission the actor is not entitled to delegate.

    ``actor_perms`` is the actor's flattened effective permission set (inheritance
    expanded).  A super_admin holding ``*`` passes everything; everyone else is
    bounded by what they hold, and ``authz.*`` tokens are non-delegable unless the
    actor holds the bare ``*`` wildcard.  Empty set ⇒ nothing is grantable.
    """
    for perm in permissions:
        if not is_grantable(perm, actor_perms):
            raise FoundationError(
                PERMISSION_ESCALATION,
                extra={"permission": perm},
            )


class RoleService:
    def __init__(self, audit: AuditPublisher) -> None:
        self._audit = audit

    async def list_roles(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        cursor: str | None = None,
        limit: int = 50,
    ) -> tuple[list[Role], str | None]:
        stmt = select(Role).where(Role.tenant_id == tenant_id, Role.deleted_at.is_(None))
        if cursor:
            stmt = stmt.where(Role.id > cursor)
        stmt = stmt.order_by(Role.id).limit(limit + 1)
        rows = (await session.scalars(stmt)).all()
        next_cursor = rows[-1].id if len(rows) > limit else None
        return list(rows[:limit]), next_cursor

    async def get(self, session: AsyncSession, *, tenant_id: str, role_id: str) -> Role:
        r = await session.get(Role, role_id)
        if r is None or r.tenant_id != tenant_id or r.deleted_at is not None:
            raise FoundationError(ROLE_NOT_FOUND, extra={"role_id": role_id})
        return r

    async def create(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        actor_id: str,
        actor_perms: set[str],
        name: str,
        display_name: str,
        description: str | None,
        permissions: list[str],
    ) -> Role:
        # Anti-escalation: the actor may only grant permissions covered by their
        # own effective set.  Checked before any write / uniqueness probe.
        _assert_grantable(permissions, actor_perms)

        existing = await session.scalar(
            select(Role).where(
                Role.tenant_id == tenant_id,
                Role.name == name,
                Role.deleted_at.is_(None),
            )
        )
        if existing is not None:
            raise FoundationError(ROLE_ALREADY_EXISTS, extra={"name": name})

        role = Role(
            id=_new_role_id(),
            tenant_id=tenant_id,
            name=name,
            display_name=display_name,
            description=description,
            permissions=permissions,
            is_system=False,
            immutable=False,
            created_by=actor_id,
        )
        session.add(role)
        await session.flush()
        await self._audit.publish(
            session,
            event_type="foundation.authz.role.created",
            tenant_id=tenant_id,
            aggregate_id=role.id,
            payload={
                "role_id": role.id,
                "name": name,
                "permissions": permissions,
                "created_by": actor_id,
            },
            request_id=request_id,
        )
        return role

    async def update(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        actor_id: str,
        actor_perms: set[str],
        role_id: str,
        patch: dict[str, Any],
    ) -> Role:
        role = await self.get(session, tenant_id=tenant_id, role_id=role_id)
        if role.is_system or role.immutable:
            raise FoundationError(ROLE_IMMUTABLE, extra={"role_id": role_id})

        # Anti-escalation: merge-patch replaces the whole permissions array, so
        # validate the FULL requested set (not a delta) — and only when the patch
        # actually carries permissions.
        if patch.get("permissions") is not None:
            _assert_grantable(list(patch["permissions"]), actor_perms)

        for field in ("display_name", "description", "permissions"):
            if field in patch and patch[field] is not None:
                setattr(role, field, patch[field])

        await session.flush()
        await self._audit.publish(
            session,
            event_type="foundation.authz.role.updated",
            tenant_id=tenant_id,
            aggregate_id=role.id,
            payload={
                "role_id": role.id,
                "changed_fields": sorted(patch.keys()),
                "updated_by": actor_id,
            },
            request_id=request_id,
        )
        return role

    async def delete(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        actor_id: str,
        role_id: str,
    ) -> None:
        role = await self.get(session, tenant_id=tenant_id, role_id=role_id)
        if role.is_system or role.immutable:
            raise FoundationError(ROLE_IMMUTABLE)

        active = await session.scalar(
            select(RoleBinding)
            .where(
                RoleBinding.tenant_id == tenant_id,
                RoleBinding.role_id == role_id,
                RoleBinding.revoked_at.is_(None),
            )
            .limit(1)
        )
        if active is not None:
            raise FoundationError(ROLE_HAS_BINDINGS, extra={"role_id": role_id})

        role.deleted_at = datetime.now(UTC)
        await self._audit.publish(
            session,
            event_type="foundation.authz.role.deleted",
            tenant_id=tenant_id,
            aggregate_id=role.id,
            payload={"role_id": role.id, "deleted_by": actor_id},
            request_id=request_id,
        )
        await session.flush()
