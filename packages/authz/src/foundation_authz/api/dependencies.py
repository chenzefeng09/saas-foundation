"""FastAPI dependency-injection wiring."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_authz.adapters.audit_publisher import AuditPublisher, get_audit_publisher
from foundation_authz.adapters.opa_client import OpaClient, get_opa_client
from foundation_authz.adapters.security_attributes import (
    SecurityAttributeProvider,
    get_security_attribute_provider,
)
from foundation_authz.domain.base import FoundationContext, foundation_context
from foundation_authz.domain.db import session_scope
from foundation_authz.errors import PERMISSION_DENIED, TENANT_CONTEXT_MISSING, FoundationError
from foundation_authz.services.binding_service import BindingService
from foundation_authz.services.check_service import CheckService
from foundation_authz.services.permission_registry import PermissionRegistry
from foundation_authz.services.role_service import RoleService


def current_context() -> FoundationContext:
    ctx = foundation_context.get()
    if ctx is None:
        raise FoundationError(TENANT_CONTEXT_MISSING)
    return ctx


async def db_session() -> AsyncIterator[AsyncSession]:
    async with session_scope() as session:
        yield session


def opa() -> OpaClient:
    return get_opa_client()


def audit() -> AuditPublisher:
    return get_audit_publisher()


def security_attributes() -> SecurityAttributeProvider:
    return get_security_attribute_provider()


def check_service(
    o: OpaClient = Depends(opa),
    attributes: SecurityAttributeProvider = Depends(security_attributes),
) -> CheckService:
    return CheckService(opa=o, attributes=attributes)


def role_service(a: AuditPublisher = Depends(audit)) -> RoleService:
    return RoleService(audit=a)


def binding_service(a: AuditPublisher = Depends(audit)) -> BindingService:
    return BindingService(audit=a)


def permission_registry() -> PermissionRegistry:
    return PermissionRegistry()


def require_permission(action: str) -> Callable[..., object]:
    """Build a FastAPI dependency that self-authorizes ``action`` for the caller.

    Runs the SAME in-process RBAC decision as ``CheckService.check`` (no HTTP
    self-call): loads the caller's effective roles for ``ctx.tenant_id`` /
    ``ctx.user_id`` and asserts the action is granted (exact or wildcard).  On
    miss it raises PERMISSION_DENIED (403).  A super_admin's ``*`` wildcard
    naturally satisfies any ``authz.*`` management action.

    Resource-agnostic: management actions (role/binding manage) are tenant-wide,
    so we issue the check with ``resource_id=None`` and a synthetic resource_type.
    """

    async def _dep(
        ctx: FoundationContext = Depends(current_context),
        session: AsyncSession = Depends(db_session),
        svc: CheckService = Depends(check_service),
    ) -> None:
        if ctx.user_id is None:
            raise FoundationError(PERMISSION_DENIED, detail="Actor user_id required")
        perms = await svc.effective_permissions(
            session, tenant_id=ctx.tenant_id, user_id=ctx.user_id
        )
        from foundation_authz.services.check_service import covers

        if not any(covers(held, action) for held in perms):
            raise FoundationError(
                PERMISSION_DENIED,
                detail=f"Missing required permission: {action}",
                extra={"required_permission": action},
            )

    return _dep
