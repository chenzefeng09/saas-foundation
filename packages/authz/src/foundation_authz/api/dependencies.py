"""FastAPI dependency-injection wiring."""

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_authz.adapters.audit_publisher import AuditPublisher, get_audit_publisher
from foundation_authz.adapters.opa_client import OpaClient, get_opa_client
from foundation_authz.domain.base import FoundationContext, foundation_context
from foundation_authz.domain.db import session_scope
from foundation_authz.services.binding_service import BindingService
from foundation_authz.services.check_service import CheckService
from foundation_authz.services.permission_registry import PermissionRegistry
from foundation_authz.services.role_service import RoleService


def current_context() -> FoundationContext:
    ctx = foundation_context.get()
    if ctx is None:
        raise HTTPException(status_code=401, detail="Tenant context missing")
    return ctx


async def db_session() -> AsyncIterator[AsyncSession]:
    async with session_scope() as session:
        yield session


def opa() -> OpaClient:
    return get_opa_client()


def audit() -> AuditPublisher:
    return get_audit_publisher()


def check_service(o: OpaClient = Depends(opa)) -> CheckService:
    return CheckService(opa=o)


def role_service(a: AuditPublisher = Depends(audit)) -> RoleService:
    return RoleService(audit=a)


def binding_service(a: AuditPublisher = Depends(audit)) -> BindingService:
    return BindingService(audit=a)


def permission_registry() -> PermissionRegistry:
    return PermissionRegistry()
