"""User membership + transfer + secondary OU assignments."""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_org.adapters.audit_publisher import AuditPublisher
from foundation_org.domain.models import (
    OrgUnit,
    Team,
    UserMembership,
    UserOrgUnitSecondary,
    UserTeamMembership,
)
from foundation_org.errors import (
    MEMBERSHIP_NOT_FOUND,
    ORG_UNIT_ARCHIVED,
    ORG_UNIT_NOT_FOUND,
    TEAM_NOT_FOUND,
    FoundationError,
)


class MembershipService:
    def __init__(self, audit: AuditPublisher) -> None:
        self._audit = audit

    # ------------------------------------------------------------------ get
    async def get(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        user_id: str,
    ) -> UserMembership:
        m = await session.get(UserMembership, user_id)
        if m is None or m.tenant_id != tenant_id:
            raise FoundationError(MEMBERSHIP_NOT_FOUND, extra={"user_id": user_id})
        return m

    # ------------------------------------------------------------------ upsert
    async def upsert(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        actor_id: str,
        user_id: str,
        primary_org_unit_id: str,
        job_title: str | None,
        employee_no: str | None,
        join_date: date | None,
        manager_user_id: str | None,
        employment_kind: str,
        metadata: dict[str, Any],
    ) -> UserMembership:
        await _require_active_ou(session, tenant_id=tenant_id, ou_id=primary_org_unit_id)

        existing = await session.get(UserMembership, user_id)
        is_new = existing is None or existing.tenant_id != tenant_id

        if is_new:
            m = UserMembership(
                user_id=user_id,
                tenant_id=tenant_id,
                primary_org_unit_id=primary_org_unit_id,
                job_title=job_title,
                employee_no=employee_no,
                join_date=join_date or date.today(),
                manager_user_id=manager_user_id,
                employment_kind=employment_kind,
                metadata_json=metadata,
                updated_by=actor_id,
            )
            session.add(m)
        else:
            m = existing  # type: ignore[assignment]
            m.primary_org_unit_id = primary_org_unit_id
            m.job_title = job_title
            m.employee_no = employee_no
            if join_date is not None:
                m.join_date = join_date
            m.manager_user_id = manager_user_id
            m.employment_kind = employment_kind
            m.metadata_json = metadata
            m.updated_by = actor_id

        await session.flush()
        await self._audit.publish(
            session,
            event_type=(
                "foundation.org.user.joined"
                if is_new
                else "foundation.org.user.membership_updated"
            ),
            tenant_id=tenant_id,
            aggregate_id=user_id,
            payload={
                "user_id": user_id,
                "primary_org_unit_id": primary_org_unit_id,
                "manager_user_id": manager_user_id,
                "actor_id": actor_id,
            },
            request_id=request_id,
        )
        return m

    # ------------------------------------------------------------------ transfer
    async def transfer(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        actor_id: str,
        user_id: str,
        to_org_unit_id: str,
        to_team_ids: list[str],
        effective_date: date | None,
        reason: str | None,
    ) -> UserMembership:
        m = await self.get(session, tenant_id=tenant_id, user_id=user_id)
        from_ou = m.primary_org_unit_id

        await _require_active_ou(session, tenant_id=tenant_id, ou_id=to_org_unit_id)

        # Validate all target teams up-front.
        for tid in to_team_ids:
            t = await session.get(Team, tid)
            if (
                t is None
                or t.tenant_id != tenant_id
                or t.deleted_at is not None
                or t.is_archived
            ):
                raise FoundationError(TEAM_NOT_FOUND, extra={"team_id": tid})
            if t.org_unit_id != to_org_unit_id:
                raise FoundationError(
                    TEAM_NOT_FOUND,
                    detail="Team does not belong to the target org-unit.",
                    extra={"team_id": tid, "expected_ou": to_org_unit_id},
                )

        # Update primary OU
        m.primary_org_unit_id = to_org_unit_id
        if effective_date is not None:
            m.join_date = effective_date
        m.updated_by = actor_id

        # Leave all previous teams.
        previous_teams = list(
            (
                await session.scalars(
                    select(UserTeamMembership).where(
                        UserTeamMembership.tenant_id == tenant_id,
                        UserTeamMembership.user_id == user_id,
                        UserTeamMembership.left_at.is_(None),
                    )
                )
            ).all()
        )
        now = datetime.now(UTC)
        for utm in previous_teams:
            utm.left_at = now

        # Join target teams.
        for tid in to_team_ids:
            existing = await session.get(UserTeamMembership, (user_id, tid))
            if existing is not None:
                existing.left_at = None
                existing.role_in_team = "MEMBER"
                existing.joined_at = now
                existing.granted_by = actor_id
            else:
                session.add(
                    UserTeamMembership(
                        user_id=user_id,
                        team_id=tid,
                        tenant_id=tenant_id,
                        role_in_team="MEMBER",
                        joined_at=now,
                        granted_by=actor_id,
                    )
                )

        await session.flush()
        await self._audit.publish(
            session,
            event_type="foundation.org.user.transferred",
            tenant_id=tenant_id,
            aggregate_id=user_id,
            payload={
                "user_id": user_id,
                "from_org_unit_id": from_ou,
                "to_org_unit_id": to_org_unit_id,
                "to_team_ids": to_team_ids,
                "effective_date": effective_date.isoformat() if effective_date else None,
                "reason": reason,
                "transferred_by": actor_id,
            },
            request_id=request_id,
        )
        return m

    # ------------------------------------------------------------------ secondary
    async def list_secondary(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        user_id: str,
    ) -> list[UserOrgUnitSecondary]:
        stmt = (
            select(UserOrgUnitSecondary)
            .where(
                UserOrgUnitSecondary.tenant_id == tenant_id,
                UserOrgUnitSecondary.user_id == user_id,
            )
            .order_by(UserOrgUnitSecondary.valid_from.desc())
        )
        return list((await session.scalars(stmt)).all())

    async def add_secondary(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        actor_id: str,
        user_id: str,
        org_unit_id: str,
        reason: str,
        valid_until: datetime | None,
    ) -> UserOrgUnitSecondary:
        await _require_active_ou(session, tenant_id=tenant_id, ou_id=org_unit_id)
        row = UserOrgUnitSecondary(
            user_id=user_id,
            org_unit_id=org_unit_id,
            tenant_id=tenant_id,
            reason=reason,
            valid_until=valid_until,
            granted_by=actor_id,
        )
        session.add(row)
        await session.flush()
        await self._audit.publish(
            session,
            event_type="foundation.org.user.secondary_assigned",
            tenant_id=tenant_id,
            aggregate_id=user_id,
            payload={
                "user_id": user_id,
                "org_unit_id": org_unit_id,
                "reason": reason,
                "valid_until": valid_until.isoformat() if valid_until else None,
                "granted_by": actor_id,
            },
            request_id=request_id,
        )
        return row


async def _require_active_ou(
    session: AsyncSession,
    *,
    tenant_id: str,
    ou_id: str,
) -> OrgUnit:
    ou = await session.get(OrgUnit, ou_id)
    if (
        ou is None
        or ou.tenant_id != tenant_id
        or ou.deleted_at is not None
    ):
        raise FoundationError(ORG_UNIT_NOT_FOUND, extra={"ou_id": ou_id})
    if ou.is_archived:
        raise FoundationError(ORG_UNIT_ARCHIVED, extra={"ou_id": ou_id})
    return ou
