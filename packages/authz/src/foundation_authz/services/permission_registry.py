"""Permission catalogue — read-only browsing + upsert on registration."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_authz.domain.models import PermissionDefinition


class PermissionRegistry:
    async def list_all(
        self,
        session: AsyncSession,
        *,
        service: str | None = None,
    ) -> list[PermissionDefinition]:
        stmt = select(PermissionDefinition)
        if service:
            stmt = stmt.where(PermissionDefinition.service == service)
        stmt = stmt.order_by(PermissionDefinition.id)
        return list((await session.scalars(stmt)).all())

    async def upsert(
        self,
        session: AsyncSession,
        *,
        permission_id: str,
        service: str,
        resource_type: str,
        action: str,
        description: str,
        risk_level: str = "LOW",
        requires_mfa: bool = False,
        requires_4eyes: bool = False,
        requires_pam_jit: bool = False,
        requires_business_hours: bool = False,
        is_system: bool = True,
    ) -> PermissionDefinition:
        existing = await session.get(PermissionDefinition, permission_id)
        if existing is None:
            row = PermissionDefinition(
                id=permission_id,
                service=service,
                resource_type=resource_type,
                action=action,
                description=description,
                risk_level=risk_level,
                requires_mfa=requires_mfa,
                requires_4eyes=requires_4eyes,
                requires_pam_jit=requires_pam_jit,
                requires_business_hours=requires_business_hours,
                is_system=is_system,
            )
            session.add(row)
            await session.flush()
            return row
        for field in (
            "description",
            "risk_level",
            "requires_mfa",
            "requires_4eyes",
            "requires_pam_jit",
            "requires_business_hours",
        ):
            setattr(existing, field, locals()[field])
        await session.flush()
        return existing
