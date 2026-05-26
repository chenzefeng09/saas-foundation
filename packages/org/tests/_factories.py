"""ORM-object factory helpers for org tests."""

from __future__ import annotations

from datetime import UTC, date, datetime

from foundation_org.domain.models import (
    OrgUnit,
    Team,
    UserMembership,
    UserTeamMembership,
)


def make_org_unit(
    *,
    ou_id: str = "ou_01J0000000000000000000OU01",
    tenant_id: str = "tnt_01J0000000000000000000TNT1",
    parent_id: str | None = None,
    code: str = "engineering",
    name: str = "Engineering",
    kind: str = "DEPARTMENT",
    depth: int = 0,
    path: str = "engineering",
    is_archived: bool = False,
    deleted: bool = False,
    manager_user_id: str | None = None,
) -> OrgUnit:
    now = datetime.now(UTC)
    return OrgUnit(
        id=ou_id,
        tenant_id=tenant_id,
        parent_id=parent_id,
        code=code,
        name=name,
        kind=kind,
        depth=depth,
        path=path,
        is_archived=is_archived,
        sort_order=0,
        created_at=now,
        updated_at=now,
        deleted_at=now if deleted else None,
        created_by="usr_01J0000000000000000000ACT1",
        updated_by="usr_01J0000000000000000000ACT1",
        manager_user_id=manager_user_id,
    )


def make_team(
    *,
    team_id: str = "tm_01J00000000000000000000TM1",
    tenant_id: str = "tnt_01J0000000000000000000TNT1",
    org_unit_id: str = "ou_01J0000000000000000000OU01",
    code: str = "backend",
    name: str = "Backend Team",
    is_archived: bool = False,
    deleted: bool = False,
) -> Team:
    now = datetime.now(UTC)
    return Team(
        id=team_id,
        tenant_id=tenant_id,
        org_unit_id=org_unit_id,
        code=code,
        name=name,
        kind="PROJECT",
        is_archived=is_archived,
        created_at=now,
        updated_at=now,
        deleted_at=now if deleted else None,
        created_by="usr_01J0000000000000000000ACT1",
        updated_by="usr_01J0000000000000000000ACT1",
    )


def make_membership(
    *,
    user_id: str = "usr_01J0000000000000000000USR1",
    tenant_id: str = "tnt_01J0000000000000000000TNT1",
    primary_org_unit_id: str = "ou_01J0000000000000000000OU01",
    employment_kind: str = "EMPLOYEE",
) -> UserMembership:
    now = datetime.now(UTC)
    return UserMembership(
        user_id=user_id,
        tenant_id=tenant_id,
        primary_org_unit_id=primary_org_unit_id,
        join_date=date.today(),
        employment_kind=employment_kind,
        created_at=now,
        updated_at=now,
        updated_by="usr_01J0000000000000000000ACT1",
    )


def make_team_membership(
    *,
    user_id: str = "usr_01J0000000000000000000USR1",
    team_id: str = "tm_01J00000000000000000000TM1",
    tenant_id: str = "tnt_01J0000000000000000000TNT1",
    role_in_team: str = "MEMBER",
    left: bool = False,
) -> UserTeamMembership:
    now = datetime.now(UTC)
    return UserTeamMembership(
        user_id=user_id,
        team_id=team_id,
        tenant_id=tenant_id,
        role_in_team=role_in_team,
        joined_at=now,
        left_at=None if not left else now,
        granted_by="usr_01J0000000000000000000ACT1",
    )
