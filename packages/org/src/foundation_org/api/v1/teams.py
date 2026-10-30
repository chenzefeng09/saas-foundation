"""Team CRUD + member management endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Path, Query, status
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_org.api.dependencies import (
    current_context,
    db_session,
    team_service,
)
from foundation_org.domain.base import FoundationContext
from foundation_org.errors import PERMISSION_DENIED, FoundationError
from foundation_org.schemas.common import OU_ID_PATTERN, TEAM_ID_PATTERN, USER_ID_PATTERN, CursorPage
from foundation_org.schemas.team import (
    AddTeamMemberRequest,
    CreateTeamRequest,
    TeamMemberRead,
    TeamRead,
    UpdateTeamRequest,
)
from foundation_org.services.team_service import TeamService

router = APIRouter(prefix="/teams", tags=["teams"])


def _require_actor(ctx: FoundationContext) -> str:
    if ctx.user_id is None:
        raise FoundationError(PERMISSION_DENIED, detail="Actor user_id required")
    return ctx.user_id


@router.get("", response_model=CursorPage[TeamRead], operation_id="listTeams")
async def list_teams(
    org_unit_id: str | None = Query(
        default=None, alias="filter.org_unit_id", pattern=OU_ID_PATTERN
    ),
    legacy_org_unit_id: str | None = Query(
        default=None,
        alias="org_unit_id",
        pattern=OU_ID_PATTERN,
        deprecated=True,
        description="Deprecated alias of filter.org_unit_id (CONVENTIONS §2.5).",
    ),
    include_archived: bool = Query(default=False),
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: TeamService = Depends(team_service),
) -> CursorPage[TeamRead]:
    rows, next_cursor = await svc.list(
        session,
        tenant_id=ctx.tenant_id,
        org_unit_id=org_unit_id if org_unit_id is not None else legacy_org_unit_id,
        include_archived=include_archived,
        cursor=cursor,
        limit=limit,
    )
    return CursorPage[TeamRead](
        items=[TeamRead.model_validate(r) for r in rows],
        next_cursor=next_cursor,
    )


@router.post(
    "",
    response_model=TeamRead,
    status_code=status.HTTP_201_CREATED,
    operation_id="createTeam",
)
async def create_team(
    body: CreateTeamRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: TeamService = Depends(team_service),
) -> TeamRead:
    actor_id = _require_actor(ctx)
    team = await svc.create(
        session,
        tenant_id=ctx.tenant_id,
        request_id=ctx.request_id,
        actor_id=actor_id,
        org_unit_id=body.org_unit_id,
        code=body.code,
        name=body.name,
        description=body.description,
        lead_user_id=body.lead_user_id,
        kind=body.kind,
        metadata=body.metadata,
    )
    return TeamRead.model_validate(team)


@router.get("/{team_id}", response_model=TeamRead, operation_id="getTeam")
async def get_team(
    team_id: str = Path(pattern=TEAM_ID_PATTERN),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: TeamService = Depends(team_service),
) -> TeamRead:
    return TeamRead.model_validate(
        await svc.get(session, tenant_id=ctx.tenant_id, team_id=team_id, include_archived=True)
    )


@router.patch("/{team_id}", response_model=TeamRead, operation_id="updateTeam")
async def update_team(
    team_id: str = Path(pattern=TEAM_ID_PATTERN),
    body: UpdateTeamRequest = Body(...),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: TeamService = Depends(team_service),
) -> TeamRead:
    actor_id = _require_actor(ctx)
    return TeamRead.model_validate(
        await svc.update(
            session,
            tenant_id=ctx.tenant_id,
            request_id=ctx.request_id,
            actor_id=actor_id,
            team_id=team_id,
            patch=body.model_dump(exclude_unset=True),
        )
    )


@router.delete(
    "/{team_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="deleteTeam",
    response_class=Response,
)
async def delete_team(
    team_id: str = Path(pattern=TEAM_ID_PATTERN),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: TeamService = Depends(team_service),
) -> Response:
    actor_id = _require_actor(ctx)
    await svc.delete(
        session,
        tenant_id=ctx.tenant_id,
        request_id=ctx.request_id,
        actor_id=actor_id,
        team_id=team_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/{team_id}/members",
    response_model=list[TeamMemberRead],
    operation_id="listTeamMembers",
)
async def list_team_members(
    team_id: str = Path(pattern=TEAM_ID_PATTERN),
    include_left: bool = Query(default=False),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: TeamService = Depends(team_service),
) -> list[TeamMemberRead]:
    rows = await svc.list_members(
        session,
        tenant_id=ctx.tenant_id,
        team_id=team_id,
        include_left=include_left,
    )
    return [TeamMemberRead.model_validate(r) for r in rows]


@router.post(
    "/{team_id}/members",
    response_model=TeamMemberRead,
    status_code=status.HTTP_201_CREATED,
    operation_id="addTeamMember",
)
async def add_team_member(
    team_id: str = Path(pattern=TEAM_ID_PATTERN),
    body: AddTeamMemberRequest = Body(...),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: TeamService = Depends(team_service),
) -> TeamMemberRead:
    actor_id = _require_actor(ctx)
    row = await svc.add_member(
        session,
        tenant_id=ctx.tenant_id,
        request_id=ctx.request_id,
        actor_id=actor_id,
        team_id=team_id,
        user_id=body.user_id,
        role_in_team=body.role_in_team,
    )
    return TeamMemberRead.model_validate(row)


@router.delete(
    "/{team_id}/members/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="removeTeamMember",
    response_class=Response,
)
async def remove_team_member(
    team_id: str = Path(pattern=TEAM_ID_PATTERN),
    user_id: str = Path(pattern=USER_ID_PATTERN),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: TeamService = Depends(team_service),
) -> Response:
    actor_id = _require_actor(ctx)
    await svc.remove_member(
        session,
        tenant_id=ctx.tenant_id,
        request_id=ctx.request_id,
        actor_id=actor_id,
        team_id=team_id,
        user_id=user_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
