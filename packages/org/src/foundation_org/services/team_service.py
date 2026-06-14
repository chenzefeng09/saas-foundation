"""Team CRUD + membership management."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import ulid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_org.adapters.audit_publisher import AuditPublisher
from foundation_org.domain.models import (
    OrgUnit,
    Team,
    UserTeamMembership,
)
from foundation_org.errors import (
    MEMBER_ALREADY_IN_TEAM,
    MEMBER_NOT_IN_TEAM,
    ORG_UNIT_ARCHIVED,
    ORG_UNIT_NOT_FOUND,
    TEAM_CODE_CONFLICT,
    TEAM_NOT_EMPTY,
    TEAM_NOT_FOUND,
    FoundationError,
)


def _new_team_id() -> str:
    return f"tm_{ulid.new()!s}"


class TeamService:
    def __init__(self, audit: AuditPublisher) -> None:
        self._audit = audit

    # ------------------------------------------------------------------ get
    async def get(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        team_id: str,
        include_archived: bool = False,
    ) -> Team:
        t = await session.get(Team, team_id)
        if (
            t is None
            or t.tenant_id != tenant_id
            or t.deleted_at is not None
            or (t.is_archived and not include_archived)
        ):
            raise FoundationError(TEAM_NOT_FOUND, extra={"team_id": team_id})
        return t

    # ------------------------------------------------------------------ list
    async def list(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        org_unit_id: str | None = None,
        include_archived: bool = False,
        cursor: str | None = None,
        limit: int = 50,
    ) -> tuple[list[Team], str | None]:
        stmt = select(Team).where(
            Team.tenant_id == tenant_id,
            Team.deleted_at.is_(None),
        )
        if org_unit_id is not None:
            stmt = stmt.where(Team.org_unit_id == org_unit_id)
        if not include_archived:
            stmt = stmt.where(Team.is_archived.is_(False))
        if cursor:
            stmt = stmt.where(Team.id > cursor)
        stmt = stmt.order_by(Team.id).limit(limit + 1)
        rows = list((await session.scalars(stmt)).all())
        next_cursor = rows[-1].id if len(rows) > limit else None
        return rows[:limit], next_cursor

    # ------------------------------------------------------------------ create
    async def create(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        actor_id: str,
        org_unit_id: str,
        code: str,
        name: str,
        description: str | None,
        lead_user_id: str | None,
        kind: str,
        metadata: dict[str, Any],
    ) -> Team:
        ou = await session.get(OrgUnit, org_unit_id)
        if (
            ou is None
            or ou.tenant_id != tenant_id
            or ou.deleted_at is not None
        ):
            raise FoundationError(ORG_UNIT_NOT_FOUND, extra={"ou_id": org_unit_id})
        if ou.is_archived:
            raise FoundationError(ORG_UNIT_ARCHIVED, extra={"ou_id": org_unit_id})

        existing = await session.scalar(
            select(Team).where(
                Team.tenant_id == tenant_id,
                Team.org_unit_id == org_unit_id,
                Team.code == code,
                Team.deleted_at.is_(None),
            )
        )
        if existing is not None:
            raise FoundationError(
                TEAM_CODE_CONFLICT,
                extra={"code": code, "ou_id": org_unit_id},
            )

        team = Team(
            id=_new_team_id(),
            tenant_id=tenant_id,
            org_unit_id=org_unit_id,
            code=code,
            name=name,
            description=description,
            lead_user_id=lead_user_id,
            kind=kind,
            metadata_json=metadata,
            created_by=actor_id,
            updated_by=actor_id,
        )
        session.add(team)
        await session.flush()
        await self._audit.publish(
            session,
            event_type="foundation.org.team.created",
            tenant_id=tenant_id,
            aggregate_id=team.id,
            payload={
                "team_id": team.id,
                "org_unit_id": org_unit_id,
                "code": code,
                "name": name,
                "created_by": actor_id,
            },
            request_id=request_id,
        )
        return team

    # ------------------------------------------------------------------ update
    async def update(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        actor_id: str,
        team_id: str,
        patch: dict[str, Any],
    ) -> Team:
        team = await self.get(session, tenant_id=tenant_id, team_id=team_id, include_archived=True)
        changed: list[str] = []
        for field in ("name", "description", "lead_user_id", "metadata"):
            if field in patch and patch[field] is not None:
                attr = "metadata_json" if field == "metadata" else field
                old = getattr(team, attr)
                new = patch[field]
                if old != new:
                    setattr(team, attr, new)
                    changed.append(field)

        if not changed:
            return team

        team.updated_by = actor_id
        await session.flush()
        await self._audit.publish(
            session,
            event_type="foundation.org.team.updated",
            tenant_id=tenant_id,
            aggregate_id=team.id,
            payload={
                "team_id": team.id,
                "changed_fields": sorted(changed),
                "updated_by": actor_id,
            },
            request_id=request_id,
        )
        return team

    # ------------------------------------------------------------------ delete (soft)
    async def delete(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        actor_id: str,
        team_id: str,
    ) -> None:
        team = await self.get(session, tenant_id=tenant_id, team_id=team_id, include_archived=True)
        active = await session.scalar(
            select(UserTeamMembership)
            .where(
                UserTeamMembership.tenant_id == tenant_id,
                UserTeamMembership.team_id == team_id,
                UserTeamMembership.left_at.is_(None),
            )
            .limit(1)
        )
        if active is not None:
            raise FoundationError(
                TEAM_NOT_EMPTY,
                detail="Team has active members; remove them first.",
                extra={"team_id": team_id, "reason": "has_members"},
            )

        team.deleted_at = datetime.now(UTC)
        team.updated_by = actor_id
        await self._audit.publish(
            session,
            event_type="foundation.org.team.deleted",
            tenant_id=tenant_id,
            aggregate_id=team.id,
            payload={"team_id": team.id, "deleted_by": actor_id},
            request_id=request_id,
        )
        await session.flush()

    # ------------------------------------------------------------------ members
    async def list_members(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        team_id: str,
        include_left: bool = False,
    ) -> list[UserTeamMembership]:
        await self.get(session, tenant_id=tenant_id, team_id=team_id, include_archived=True)
        stmt = select(UserTeamMembership).where(
            UserTeamMembership.tenant_id == tenant_id,
            UserTeamMembership.team_id == team_id,
        )
        if not include_left:
            stmt = stmt.where(UserTeamMembership.left_at.is_(None))
        stmt = stmt.order_by(UserTeamMembership.user_id)
        return list((await session.scalars(stmt)).all())

    async def list_teams_for_user(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        user_id: str,
        include_left: bool = False,
    ) -> list[Team]:
        """Reverse lookup: teams a user is a member of (active by default)."""
        stmt = (
            select(Team)
            .join(UserTeamMembership, UserTeamMembership.team_id == Team.id)
            .where(
                UserTeamMembership.tenant_id == tenant_id,
                UserTeamMembership.user_id == user_id,
                Team.tenant_id == tenant_id,
                Team.deleted_at.is_(None),
            )
        )
        if not include_left:
            stmt = stmt.where(UserTeamMembership.left_at.is_(None))
        stmt = stmt.order_by(Team.id)
        return list((await session.scalars(stmt)).all())

    async def add_member(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        actor_id: str,
        team_id: str,
        user_id: str,
        role_in_team: str,
    ) -> UserTeamMembership:
        await self.get(session, tenant_id=tenant_id, team_id=team_id)  # active team only

        existing = await session.get(UserTeamMembership, (user_id, team_id))
        if existing is not None:
            if existing.left_at is None:
                raise FoundationError(
                    MEMBER_ALREADY_IN_TEAM,
                    extra={"team_id": team_id, "user_id": user_id},
                )
            # Re-add: clear left_at + bump role.
            existing.left_at = None
            existing.role_in_team = role_in_team
            existing.joined_at = datetime.now(UTC)
            existing.granted_by = actor_id
            new = existing
        else:
            new = UserTeamMembership(
                user_id=user_id,
                team_id=team_id,
                tenant_id=tenant_id,
                role_in_team=role_in_team,
                granted_by=actor_id,
            )
            session.add(new)

        await session.flush()
        await self._audit.publish(
            session,
            event_type="foundation.org.team.member_added",
            tenant_id=tenant_id,
            aggregate_id=team_id,
            payload={
                "team_id": team_id,
                "user_id": user_id,
                "role_in_team": role_in_team,
                "added_by": actor_id,
            },
            request_id=request_id,
        )
        return new

    async def remove_member(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        request_id: str,
        actor_id: str,
        team_id: str,
        user_id: str,
    ) -> None:
        existing = await session.get(UserTeamMembership, (user_id, team_id))
        if (
            existing is None
            or existing.tenant_id != tenant_id
            or existing.left_at is not None
        ):
            raise FoundationError(
                MEMBER_NOT_IN_TEAM,
                extra={"team_id": team_id, "user_id": user_id},
            )

        existing.left_at = datetime.now(UTC)
        await self._audit.publish(
            session,
            event_type="foundation.org.team.member_removed",
            tenant_id=tenant_id,
            aggregate_id=team_id,
            payload={
                "team_id": team_id,
                "user_id": user_id,
                "removed_by": actor_id,
            },
            request_id=request_id,
        )
        await session.flush()
