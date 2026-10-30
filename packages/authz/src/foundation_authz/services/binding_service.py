"""Role binding CRUD."""

from __future__ import annotations

from collections.abc import Collection
from datetime import UTC, datetime

import ulid
from sqlalchemy import ColumnElement, and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_authz.adapters.audit_publisher import AuditPublisher
from foundation_authz.domain.models import Role, RoleBinding
from foundation_authz.errors import (
    BINDING_NOT_FOUND,
    PERMISSION_ESCALATION,
    ROLE_NOT_FOUND,
    FoundationError,
)
from foundation_authz.schemas.binding import (
    BINDING_STATUSES,
    DEFAULT_LIST_STATUSES,
    BindingStatus,
)
from foundation_authz.services.check_service import CheckService, is_grantable


def _new_binding_id() -> str:
    return f"rbd_{ulid.new()!s}"


def status_filter_clause(
    statuses: Collection[BindingStatus], *, now: datetime
) -> ColumnElement[bool] | None:
    """SQL predicate selecting bindings whose lifecycle state is in ``statuses``.

    Mirrors ``schemas.binding.binding_status`` (and so CheckService): revoked
    wins, then a past ``expires_at`` means EXPIRED, everything else is ACTIVE.
    Returns ``None`` when every state is requested (no filtering needed).
    """
    wanted = set(statuses)
    if not wanted:
        raise ValueError("at least one binding status is required")
    unknown = wanted.difference(BINDING_STATUSES)
    if unknown:
        raise ValueError(f"unknown binding status(es): {sorted(unknown)}")
    if wanted.issuperset(BINDING_STATUSES):
        return None

    not_revoked = RoleBinding.revoked_at.is_(None)
    predicates: dict[BindingStatus, ColumnElement[bool]] = {
        "ACTIVE": and_(
            not_revoked,
            or_(RoleBinding.expires_at.is_(None), RoleBinding.expires_at >= now),
        ),
        "EXPIRED": and_(not_revoked, RoleBinding.expires_at < now),
        "REVOKED": RoleBinding.revoked_at.is_not(None),
    }
    return or_(*(predicates[s] for s in BINDING_STATUSES if s in wanted))


class BindingService:
    def __init__(self, audit: AuditPublisher) -> None:
        self._audit = audit

    async def list(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        cursor: str | None = None,
        limit: int = 50,
        principal_kind: str | None = None,
        principal_id: str | None = None,
        role_id: str | None = None,
        statuses: Collection[BindingStatus] = DEFAULT_LIST_STATUSES,
        now: datetime | None = None,
    ) -> tuple[list[RoleBinding], str | None]:
        """List the tenant's role bindings, cursor-paginated by id.

        Only ACTIVE bindings — the ones CheckService actually honours — are
        returned unless ``statuses`` asks for EXPIRED and/or REVOKED ones.  A
        revoked binding is audit history, never a current grant, so callers
        must opt in to see it (and get ``revoked_at`` / ``status`` to tell).
        """
        stmt = select(RoleBinding).where(RoleBinding.tenant_id == tenant_id)
        status_clause = status_filter_clause(statuses, now=now or datetime.now(UTC))
        if status_clause is not None:
            stmt = stmt.where(status_clause)
        if principal_kind:
            stmt = stmt.where(RoleBinding.principal_kind == principal_kind)
        if principal_id:
            stmt = stmt.where(RoleBinding.principal_id == principal_id)
        if role_id:
            stmt = stmt.where(RoleBinding.role_id == role_id)
        if cursor:
            stmt = stmt.where(RoleBinding.id > cursor)
        stmt = stmt.order_by(RoleBinding.id).limit(limit + 1)
        rows = list((await session.scalars(stmt)).all())
        page = rows[:limit]
        # The cursor is the last id *returned*: the next page selects id > cursor,
        # so handing out the (limit+1)-th id would silently skip that row.
        next_cursor = page[-1].id if len(rows) > limit else None
        return page, next_cursor

    async def create(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        actor_id: str,
        actor_perms: set[str],
        check_svc: CheckService,
        principal_kind: str,
        principal_id: str,
        role_id: str,
        scope_kind: str,
        scope_id: str | None,
        expires_at: datetime | None,
        grant_reason: str | None,
    ) -> RoleBinding:
        # Verify role exists in tenant
        role = await session.get(Role, role_id)
        if role is None or role.tenant_id != tenant_id or role.deleted_at is not None:
            raise FoundationError(ROLE_NOT_FOUND, extra={"role_id": role_id})

        # Anti-escalation: binding a principal to a role grants that principal the
        # role's full permission closure (own + inherited).  The actor must be
        # entitled to delegate every token in that closure.  This is what blocks
        # e.g. a tenant_admin from binding itself (or anyone) to a super_admin role
        # whose permissions=["*"] — only a holder of "*" can delegate "*".
        closure = await check_svc.role_permission_closure(
            session, tenant_id=tenant_id, role=role
        )
        for perm in closure:
            if not is_grantable(perm, actor_perms):
                raise FoundationError(
                    PERMISSION_ESCALATION,
                    extra={"permission": perm, "role_id": role_id},
                )

        binding = RoleBinding(
            id=_new_binding_id(),
            tenant_id=tenant_id,
            principal_kind=principal_kind,
            principal_id=principal_id,
            role_id=role_id,
            scope_kind=scope_kind,
            scope_id=scope_id,
            expires_at=expires_at,
            granted_by=actor_id,
            grant_reason=grant_reason,
        )
        session.add(binding)
        await session.flush()
        await self._audit.publish(
            session,
            event_type="foundation.authz.binding.created",
            tenant_id=tenant_id,
            aggregate_id=binding.id,
            payload={
                "binding_id": binding.id,
                "principal_kind": principal_kind,
                "principal_id": principal_id,
                "role_id": role_id,
                "scope_kind": scope_kind,
                "scope_id": scope_id,
                "expires_at": expires_at.isoformat() if expires_at else None,
                "granted_by": actor_id,
                "grant_reason": grant_reason,
            },
            request_id=request_id,
        )
        return binding

    async def revoke(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        actor_id: str,
        binding_id: str,
        reason: str | None,
    ) -> None:
        binding = await session.get(RoleBinding, binding_id)
        if binding is None or binding.tenant_id != tenant_id:
            raise FoundationError(BINDING_NOT_FOUND, extra={"binding_id": binding_id})
        if binding.revoked_at is not None:
            return  # idempotent

        binding.revoked_at = datetime.now(UTC)
        binding.revoked_by = actor_id
        binding.revoked_reason = reason

        await self._audit.publish(
            session,
            event_type="foundation.authz.binding.revoked",
            tenant_id=tenant_id,
            aggregate_id=binding.id,
            payload={
                "binding_id": binding.id,
                "revoked_by": actor_id,
                "reason": reason,
            },
            request_id=request_id,
        )
        await session.flush()
