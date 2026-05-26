"""FastAPI dependency-injection wiring."""

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_identity.adapters.audit_publisher import AuditPublisher, get_audit_publisher
from foundation_identity.adapters.keycloak_admin import (
    KeycloakAdminAdapter,
    get_keycloak_admin,
)
from foundation_identity.adapters.password_hasher import PasswordHasher, get_password_hasher
from foundation_identity.domain.base import FoundationContext, foundation_context
from foundation_identity.domain.db import session_scope
from foundation_identity.services.password_policy_service import PasswordPolicyService
from foundation_identity.services.user_service import UserService


# -------------------------------------------------------------------- context
def current_context() -> FoundationContext:
    ctx = foundation_context.get()
    if ctx is None:
        # Middleware should have populated this; if it didn't, the path is mis-configured.
        raise HTTPException(status_code=401, detail="Tenant context missing")
    return ctx


# -------------------------------------------------------------------- db
async def db_session() -> AsyncIterator[AsyncSession]:
    async with session_scope() as session:
        yield session


# -------------------------------------------------------------------- adapters
def keycloak() -> KeycloakAdminAdapter:
    return get_keycloak_admin()


def audit() -> AuditPublisher:
    return get_audit_publisher()


def hasher() -> PasswordHasher:
    return get_password_hasher()


# -------------------------------------------------------------------- services
def user_service(
    kc: KeycloakAdminAdapter = Depends(keycloak),
    ap: AuditPublisher = Depends(audit),
) -> UserService:
    return UserService(keycloak=kc, audit=ap)


def password_policy_service() -> PasswordPolicyService:
    return PasswordPolicyService()
