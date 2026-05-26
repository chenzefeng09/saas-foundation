"""Org-unit CRUD + move + archive + descendants/ancestors endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Path, Query, status
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_org.api.dependencies import (
    current_context,
    db_session,
    org_unit_service,
)
from foundation_org.domain.base import FoundationContext
from foundation_org.errors import PERMISSION_DENIED, FoundationError
from foundation_org.schemas.common import OU_ID_PATTERN, CursorPage
from foundation_org.schemas.org_unit import (
    ArchiveOrgUnitRequest,
    CreateOrgUnitRequest,
    MoveOrgUnitRequest,
    OrgUnitRead,
    UpdateOrgUnitRequest,
)
from foundation_org.services.org_unit_service import OrgUnitService

router = APIRouter(prefix="/org-units", tags=["org-units"])


def _require_actor(ctx: FoundationContext) -> str:
    if ctx.user_id is None:
        raise FoundationError(PERMISSION_DENIED, detail="Actor user_id required")
    return ctx.user_id


@router.get("", response_model=CursorPage[OrgUnitRead], operation_id="listOrgUnits")
async def list_org_units(
    parent_id: str | None = Query(default=None, pattern=OU_ID_PATTERN),
    include_archived: bool = Query(default=False),
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: OrgUnitService = Depends(org_unit_service),
) -> CursorPage[OrgUnitRead]:
    rows, next_cursor = await svc.list(
        session,
        tenant_id=ctx.tenant_id,
        parent_id=parent_id,
        include_archived=include_archived,
        cursor=cursor,
        limit=limit,
    )
    return CursorPage[OrgUnitRead](
        items=[OrgUnitRead.model_validate(r) for r in rows],
        next_cursor=next_cursor,
    )


@router.post(
    "",
    response_model=OrgUnitRead,
    status_code=status.HTTP_201_CREATED,
    operation_id="createOrgUnit",
)
async def create_org_unit(
    body: CreateOrgUnitRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: OrgUnitService = Depends(org_unit_service),
) -> OrgUnitRead:
    actor_id = _require_actor(ctx)
    ou = await svc.create(
        session,
        tenant_id=ctx.tenant_id,
        request_id=ctx.request_id,
        actor_id=actor_id,
        parent_id=body.parent_id,
        code=body.code,
        name=body.name,
        name_en=body.name_en,
        description=body.description,
        manager_user_id=body.manager_user_id,
        kind=body.kind,
        sort_order=body.sort_order,
        metadata=body.metadata,
    )
    return OrgUnitRead.model_validate(ou)


@router.get("/{ou_id}", response_model=OrgUnitRead, operation_id="getOrgUnit")
async def get_org_unit(
    ou_id: str = Path(pattern=OU_ID_PATTERN),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: OrgUnitService = Depends(org_unit_service),
) -> OrgUnitRead:
    return OrgUnitRead.model_validate(
        await svc.get(session, tenant_id=ctx.tenant_id, ou_id=ou_id, include_archived=True)
    )


@router.patch("/{ou_id}", response_model=OrgUnitRead, operation_id="updateOrgUnit")
async def update_org_unit(
    ou_id: str = Path(pattern=OU_ID_PATTERN),
    body: UpdateOrgUnitRequest = Body(...),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: OrgUnitService = Depends(org_unit_service),
) -> OrgUnitRead:
    actor_id = _require_actor(ctx)
    return OrgUnitRead.model_validate(
        await svc.update(
            session,
            tenant_id=ctx.tenant_id,
            request_id=ctx.request_id,
            actor_id=actor_id,
            ou_id=ou_id,
            patch=body.model_dump(exclude_unset=True),
        )
    )


@router.delete(
    "/{ou_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="deleteOrgUnit",
    response_class=Response,
)
async def delete_org_unit(
    ou_id: str = Path(pattern=OU_ID_PATTERN),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: OrgUnitService = Depends(org_unit_service),
) -> Response:
    actor_id = _require_actor(ctx)
    await svc.delete(
        session,
        tenant_id=ctx.tenant_id,
        request_id=ctx.request_id,
        actor_id=actor_id,
        ou_id=ou_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{ou_id}/move", response_model=OrgUnitRead, operation_id="moveOrgUnit")
async def move_org_unit(
    ou_id: str = Path(pattern=OU_ID_PATTERN),
    body: MoveOrgUnitRequest = Body(...),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: OrgUnitService = Depends(org_unit_service),
) -> OrgUnitRead:
    actor_id = _require_actor(ctx)
    return OrgUnitRead.model_validate(
        await svc.move(
            session,
            tenant_id=ctx.tenant_id,
            request_id=ctx.request_id,
            actor_id=actor_id,
            ou_id=ou_id,
            new_parent_id=body.new_parent_id,
            reason=body.reason,
        )
    )


@router.post(
    "/{ou_id}/archive", response_model=OrgUnitRead, operation_id="archiveOrgUnit"
)
async def archive_org_unit(
    ou_id: str = Path(pattern=OU_ID_PATTERN),
    body: ArchiveOrgUnitRequest = Body(default=ArchiveOrgUnitRequest()),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: OrgUnitService = Depends(org_unit_service),
) -> OrgUnitRead:
    actor_id = _require_actor(ctx)
    return OrgUnitRead.model_validate(
        await svc.archive(
            session,
            tenant_id=ctx.tenant_id,
            request_id=ctx.request_id,
            actor_id=actor_id,
            ou_id=ou_id,
            reason=body.reason,
        )
    )


@router.get(
    "/{ou_id}/descendants",
    response_model=list[OrgUnitRead],
    operation_id="listOrgUnitDescendants",
)
async def descendants(
    ou_id: str = Path(pattern=OU_ID_PATTERN),
    include_archived: bool = Query(default=False),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: OrgUnitService = Depends(org_unit_service),
) -> list[OrgUnitRead]:
    rows = await svc.descendants(
        session,
        tenant_id=ctx.tenant_id,
        ou_id=ou_id,
        include_archived=include_archived,
    )
    return [OrgUnitRead.model_validate(r) for r in rows]


@router.get(
    "/{ou_id}/ancestors",
    response_model=list[OrgUnitRead],
    operation_id="listOrgUnitAncestors",
)
async def ancestors(
    ou_id: str = Path(pattern=OU_ID_PATTERN),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: OrgUnitService = Depends(org_unit_service),
) -> list[OrgUnitRead]:
    rows = await svc.ancestors(
        session,
        tenant_id=ctx.tenant_id,
        ou_id=ou_id,
    )
    return [OrgUnitRead.model_validate(r) for r in rows]
