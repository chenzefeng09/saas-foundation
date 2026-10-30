"""FastAPI dependency-injection wiring."""

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_identity.adapters.audit_publisher import AuditPublisher, get_audit_publisher
from foundation_identity.adapters.hibp_gateway import HibpGateway, get_hibp_gateway
from foundation_identity.adapters.keycloak_admin import (
    KeycloakAdminAdapter,
    get_keycloak_admin,
)
from foundation_identity.adapters.notification_gateway import (
    NotificationGateway,
    get_notification_gateway,
)
from foundation_identity.adapters.password_hasher import PasswordHasher, get_password_hasher
from foundation_identity.adapters.redis_cache import RedisCacheAdapter, get_redis_cache
from foundation_identity.domain.base import FoundationContext, foundation_context
from foundation_identity.domain.db import session_scope
from foundation_identity.errors import TENANT_CONTEXT_MISSING, FoundationError
from foundation_identity.services.mfa_service import MfaService
from foundation_identity.services.password_policy_service import PasswordPolicyService
from foundation_identity.services.risk_evaluator import (
    RiskEvaluator,
    get_risk_evaluator,
)
from foundation_identity.services.sso_service import SsoService
from foundation_identity.services.user_service import UserService


# -------------------------------------------------------------------- context
def current_context() -> FoundationContext:
    ctx = foundation_context.get()
    if ctx is None:
        # Middleware should have populated this; if it didn't, the path is mis-configured.
        raise FoundationError(TENANT_CONTEXT_MISSING)
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


def redis_cache() -> RedisCacheAdapter:
    return get_redis_cache()


def notification_gateway() -> NotificationGateway:
    return get_notification_gateway()


def hibp_gateway() -> HibpGateway:
    return get_hibp_gateway()


def risk_evaluator() -> RiskEvaluator:
    return get_risk_evaluator()


# -------------------------------------------------------------------- services
def user_service(
    kc: KeycloakAdminAdapter = Depends(keycloak),
    ap: AuditPublisher = Depends(audit),
) -> UserService:
    return UserService(keycloak=kc, audit=ap)


def password_policy_service(
    hibp: HibpGateway = Depends(hibp_gateway),
) -> PasswordPolicyService:
    return PasswordPolicyService(hibp=hibp)


def mfa_service(
    kc: KeycloakAdminAdapter = Depends(keycloak),
    ap: AuditPublisher = Depends(audit),
    rc: RedisCacheAdapter = Depends(redis_cache),
    ng: NotificationGateway = Depends(notification_gateway),
) -> MfaService:
    return MfaService(keycloak=kc, audit=ap, cache=rc, notification=ng)


def sso_service(
    kc: KeycloakAdminAdapter = Depends(keycloak),
    ap: AuditPublisher = Depends(audit),
) -> SsoService:
    return SsoService(keycloak=kc, audit=ap)
