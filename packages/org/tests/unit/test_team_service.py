"""Unit tests for TeamService."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.dialects import postgresql

from foundation_org.domain.models import Team
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
from foundation_org.services.team_service import TeamService

from tests._factories import make_org_unit, make_team, make_team_membership


@pytest.fixture
def svc(audit_publisher: AsyncMock) -> TeamService:
    return TeamService(audit=audit_publisher)


def _capture_statement(fake_session: Any) -> list[Any]:
    """Record the SQL statement passed to ``session.scalars`` for inspection."""
    captured: list[Any] = []
    original = fake_session.scalars

    async def _spy(stmt: Any) -> Any:
        captured.append(stmt)
        return await original(stmt)

    fake_session.scalars = _spy
    return captured


def _sql(stmt: Any) -> str:
    """Render a recorded SELECT as Postgres SQL, values inlined."""
    compiled = stmt.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True})
    return " ".join(str(compiled).split())


def _db_answer(teams: list[Team], cursor: str | None, limit: int) -> list[Team]:
    """What ``WHERE id > :cursor ORDER BY id LIMIT :limit + 1`` returns from ``teams``."""
    ordered = sorted(teams, key=lambda t: t.id)
    return [t for t in ordered if cursor is None or t.id > cursor][: limit + 1]


def _compiled_where(captured: list[Any]) -> str:
    assert captured, "expected a statement to be issued"
    return str(
        captured[0].compile(compile_kwargs={"literal_binds": True})
    )


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


class TestList:
    async def test_list_pages_through_every_team_once(
        self, svc: TeamService, fake_session, tenant_id: str,
    ) -> None:
        teams = [
            make_team(team_id=f"tm_01J00000000000000000000A{i}", tenant_id=tenant_id)
            for i in range(1, 6)
        ]

        pages: list[list[Team]] = []
        cursor = None
        for _ in teams:  # a cursor that never runs out fails below instead of looping
            fake_session.queue_scalars(_db_answer(teams, cursor, limit=2))
            page, cursor = await svc.list(
                fake_session, tenant_id=tenant_id, cursor=cursor, limit=2,
            )
            pages.append(page)
            if cursor is None:
                break

        assert cursor is None
        assert pages == [teams[0:2], teams[2:4], teams[4:5]]
        first, *later = (_sql(s) for s in fake_session.statements)
        assert "ORDER BY org.team.id LIMIT 3" in first
        assert "org.team.id >" not in first
        for previous, sql in zip(pages[:-1], later, strict=True):
            # Each page resumes right after the last team the previous one showed.
            assert f"org.team.id > '{previous[-1].id}' ORDER BY org.team.id LIMIT 3" in sql


class TestUpdate:
    async def test_update_changes_mutable_fields(
        self, svc: TeamService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        team = make_team(tenant_id=tenant_id)
        fake_session.put(team)

        result = await svc.update(
            fake_session,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=actor_id,
            team_id=team.id,
            patch={"name": "Platform", "metadata": {"tier": "core"}},
        )

        assert result.name == "Platform"
        assert result.metadata_json == {"tier": "core"}
        assert result.updated_by == actor_id

    async def test_update_no_changes_skips_audit(
        self, svc: TeamService, fake_session, tenant_id: str, actor_id: str, request_id: str,
        audit_publisher: AsyncMock,
    ) -> None:
        team = make_team(tenant_id=tenant_id)
        fake_session.put(team)

        result = await svc.update(
            fake_session,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=actor_id,
            team_id=team.id,
            patch={"name": team.name},
        )

        assert result is team
        audit_publisher.publish.assert_not_awaited()


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

    async def test_add_member_reactivates_left_membership(
        self, svc: TeamService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        team = make_team(tenant_id=tenant_id)
        existing = make_team_membership(team_id=team.id, user_id="usr_new", left=True)
        fake_session.put(team)
        fake_session.put(existing)

        result = await svc.add_member(
            fake_session,
            tenant_id=tenant_id,
            request_id=request_id,
            actor_id=actor_id,
            team_id=team.id,
            user_id="usr_new",
            role_in_team="LEAD",
        )

        assert result is existing
        assert existing.left_at is None
        assert existing.role_in_team == "LEAD"
        assert existing.granted_by == actor_id

    async def test_list_members_excludes_left_by_default(
        self, svc: TeamService, fake_session, tenant_id: str,
    ) -> None:
        team = make_team(tenant_id=tenant_id)
        member = make_team_membership(tenant_id=tenant_id, team_id=team.id)
        fake_session.put(team)
        fake_session.queue_scalars([member])

        rows = await svc.list_members(fake_session, tenant_id=tenant_id, team_id=team.id)

        assert rows == [member]

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


class TestListTeamsForUser:
    async def test_returns_all_teams_user_belongs_to(
        self, svc: TeamService, fake_session, tenant_id: str,
    ) -> None:
        first = make_team(team_id="tm_01J00000000000000000000A1", tenant_id=tenant_id)
        second = make_team(team_id="tm_01J00000000000000000000A2", tenant_id=tenant_id)
        fake_session.queue_scalars([first, second])

        rows = await svc.list_teams_for_user(
            fake_session, tenant_id=tenant_id, user_id="usr_alice",
        )

        assert rows == [first, second]

    async def test_query_filters_active_membership_and_tenant_and_not_deleted(
        self, svc: TeamService, fake_session, tenant_id: str,
    ) -> None:
        captured = _capture_statement(fake_session)

        await svc.list_teams_for_user(
            fake_session, tenant_id=tenant_id, user_id="usr_alice",
        )

        sql = _compiled_where(captured)
        # active membership only (left_at filter applied by default)
        assert "left_at IS NULL" in sql
        # soft-deleted teams excluded
        assert "deleted_at IS NULL" in sql
        # tenant isolation on both sides of the join (caller's tenant only)
        assert sql.count(f"tenant_id = '{tenant_id}'") == 2
        # reverse lookup keyed on the requested user
        assert "user_id = 'usr_alice'" in sql

    async def test_include_left_drops_active_filter(
        self, svc: TeamService, fake_session, tenant_id: str,
    ) -> None:
        captured = _capture_statement(fake_session)

        await svc.list_teams_for_user(
            fake_session, tenant_id=tenant_id, user_id="usr_alice", include_left=True,
        )

        sql = _compiled_where(captured)
        assert "left_at IS NULL" not in sql
        # deleted-team exclusion still holds regardless of include_left
        assert "deleted_at IS NULL" in sql


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
        assert exc.value.error_code is TEAM_NOT_EMPTY
        assert exc.value.extra["reason"] == "has_members"
