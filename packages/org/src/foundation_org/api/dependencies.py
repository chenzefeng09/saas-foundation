"""FastAPI dependency-injection wiring."""

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_org.adapters.audit_publisher import AuditPublisher, get_audit_publisher
from foundation_org.domain.base import FoundationContext, foundation_context
from foundation_org.domain.db import session_scope
from foundation_org.errors import TENANT_CONTEXT_MISSING, FoundationError
from foundation_org.services.membership_service import MembershipService
from foundation_org.services.org_unit_service import OrgUnitService
from foundation_org.services.team_service import TeamService


def current_context() -> FoundationContext:
    ctx = foundation_context.get()
    if ctx is None:
        raise FoundationError(TENANT_CONTEXT_MISSING)
    return ctx


async def db_session() -> AsyncIterator[AsyncSession]:
    async with session_scope() as session:
        yield session


def audit() -> AuditPublisher:
    return get_audit_publisher()


def org_unit_service(a: AuditPublisher = Depends(audit)) -> OrgUnitService:
    return OrgUnitService(audit=a)


def team_service(a: AuditPublisher = Depends(audit)) -> TeamService:
    return TeamService(audit=a)


def membership_service(a: AuditPublisher = Depends(audit)) -> MembershipService:
    return MembershipService(audit=a)
