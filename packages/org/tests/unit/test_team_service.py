"""Unit tests for TeamService."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from foundation_org.errors import (
    MEMBER_ALREADY_IN_TEAM,
    MEMBER_NOT_IN_TEAM,
    ORG_UNIT_ARCHIVED,
    ORG_UNIT_NOT_FOUND,
    TEAM_CODE_CONFLICT,
    TEAM_NOT_FOUND,
    FoundationError,
)
from foundation_org.services.team_service import TeamService

from tests._factories import make_org_unit, make_team, make_team_membership


@pytest.fixture
def svc(audit_publisher: AsyncMock) -> TeamService:
    return TeamService(audit=audit_publisher)


class TestGet:
    async def test_get_found(self, svc: TeamService, fake_session, tenant_id: str) -> None:
        team = make_team(tenant_id=tenant_id)
        fake_session.put(team)

        result = await svc.get(fake_session, tenant_id=tenant_id, team_id=team.id)
        assert result.id == team.id

    async def test_get_not_found(self, svc: TeamService, fake_session, tenant_id: str) -> None:
        with pytest.raises(FoundationError) as exc:
            await svc.get(fake_session, tenant_id=tenant_id, team_id="tm_nonexistent")
        assert exc.value.error_code is TEAM_NOT_FOUND

    async def test_get_archived_excluded(
        self, svc: TeamService, fake_session, tenant_id: str,
    ) -> None:
        team = make_team(tenant_id=tenant_id, is_archived=True)
        fake_session.put(team)

        with pytest.raises(FoundationError) as exc:
            await svc.get(fake_session, tenant_id=tenant_id, team_id=team.id)
        assert exc.value.error_code is TEAM_NOT_FOUND


class TestCreate:
    async def test_create_success(
        self, svc: TeamService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        ou = make_org_unit(tenant_id=tenant_id)
        fake_session.put(ou)
        fake_session.queue_scalar(None)  # no code conflict

        result = await svc.create(
            fake_session, tenant_id=tenant_id, request_id=request_id, actor_id=actor_id,
            org_unit_id=ou.id, code="backend", name="Backend Team",
            description=None, lead_user_id=None, kind="PROJECT", metadata={},
        )
        assert result.code == "backend"
        assert result.org_unit_id == ou.id
        assert result.id.startswith("tm_")

    async def test_create_ou_not_found(
        self, svc: TeamService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        with pytest.raises(FoundationError) as exc:
            await svc.create(
                fake_session, tenant_id=tenant_id, request_id=request_id, actor_id=actor_id,
                org_unit_id="ou_nonexistent", code="backend", name="Backend",
                description=None, lead_user_id=None, kind="PROJECT", metadata={},
            )
        assert exc.value.error_code is ORG_UNIT_NOT_FOUND

    async def test_create_ou_archived(
        self, svc: TeamService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        ou = make_org_unit(tenant_id=tenant_id, is_archived=True)
        fake_session.put(ou)

        with pytest.raises(FoundationError) as exc:
            await svc.create(
                fake_session, tenant_id=tenant_id, request_id=request_id, actor_id=actor_id,
                org_unit_id=ou.id, code="backend", name="Backend",
                description=None, lead_user_id=None, kind="PROJECT", metadata={},
            )
        assert exc.value.error_code is ORG_UNIT_ARCHIVED

    async def test_create_code_conflict(
        self, svc: TeamService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        ou = make_org_unit(tenant_id=tenant_id)
        existing = make_team(tenant_id=tenant_id, org_unit_id=ou.id, code="backend")
        fake_session.put(ou)
        fake_session.queue_scalar(existing)

        with pytest.raises(FoundationError) as exc:
            await svc.create(
                fake_session, tenant_id=tenant_id, request_id=request_id, actor_id=actor_id,
                org_unit_id=ou.id, code="backend", name="Backend",
                description=None, lead_user_id=None, kind="PROJECT", metadata={},
            )
        assert exc.value.error_code is TEAM_CODE_CONFLICT


class TestMembers:
    async def test_add_member_success(
        self, svc: TeamService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        team = make_team(tenant_id=tenant_id)
        fake_session.put(team)

        result = await svc.add_member(
            fake_session, tenant_id=tenant_id, request_id=request_id, actor_id=actor_id,
            team_id=team.id, user_id="usr_new", role_in_team="MEMBER",
        )
        assert result.user_id == "usr_new"
        assert result.team_id == team.id

    async def test_add_member_already_in_team(
        self, svc: TeamService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        team = make_team(tenant_id=tenant_id)
        existing = make_team_membership(team_id=team.id, user_id="usr_new", left=False)
        fake_session.put(team)
        fake_session.put(existing)

        with pytest.raises(FoundationError) as exc:
            await svc.add_member(
                fake_session, tenant_id=tenant_id, request_id=request_id, actor_id=actor_id,
                team_id=team.id, user_id="usr_new", role_in_team="MEMBER",
            )
        assert exc.value.error_code is MEMBER_ALREADY_IN_TEAM

    async def test_remove_member_success(
        self, svc: TeamService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        utm = make_team_membership(tenant_id=tenant_id, left=False)
        fake_session.put(utm)

        await svc.remove_member(
            fake_session, tenant_id=tenant_id, request_id=request_id, actor_id=actor_id,
            team_id=utm.team_id, user_id=utm.user_id,
        )
        assert utm.left_at is not None

    async def test_remove_member_not_in_team(
        self, svc: TeamService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        with pytest.raises(FoundationError) as exc:
            await svc.remove_member(
                fake_session, tenant_id=tenant_id, request_id=request_id, actor_id=actor_id,
                team_id="tm_unknown", user_id="usr_unknown",
            )
        assert exc.value.error_code is MEMBER_NOT_IN_TEAM


class TestDelete:
    async def test_delete_empty_team(
        self, svc: TeamService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        team = make_team(tenant_id=tenant_id)
        fake_session.put(team)
        fake_session.queue_scalar(None)  # no active members

        await svc.delete(
            fake_session, tenant_id=tenant_id, request_id=request_id,
            actor_id=actor_id, team_id=team.id,
        )
        assert team.deleted_at is not None

    async def test_delete_with_members_raises(
        self, svc: TeamService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        team = make_team(tenant_id=tenant_id)
        active_member = make_team_membership(tenant_id=tenant_id, team_id=team.id, left=False)
        fake_session.put(team)
        fake_session.queue_scalar(active_member)

        with pytest.raises(FoundationError) as exc:
            await svc.delete(
                fake_session, tenant_id=tenant_id, request_id=request_id,
                actor_id=actor_id, team_id=team.id,
            )
        assert exc.value.error_code is TEAM_CODE_CONFLICT
