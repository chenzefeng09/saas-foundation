"""Role CRUD endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Path, Query, status
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_authz.api.dependencies import (
    current_context,
    db_session,
    role_service,
)
from foundation_authz.domain.base import FoundationContext
from foundation_authz.errors import PERMISSION_DENIED, FoundationError
from foundation_authz.schemas.common import CursorPage
from foundation_authz.schemas.role import (
    CreateRoleRequest,
    RoleRead,
    UpdateRoleRequest,
)
from foundation_authz.services.role_service import RoleService

router = APIRouter(prefix="/roles", tags=["roles"])


@router.get("", response_model=CursorPage[RoleRead], operation_id="listRoles")
async def list_roles(
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: RoleService = Depends(role_service),
) -> CursorPage[RoleRead]:
    rows, next_cursor = await svc.list_roles(
        session, tenant_id=ctx.tenant_id, cursor=cursor, limit=limit
    )
    return CursorPage[RoleRead](
        items=[RoleRead.model_validate(r) for r in rows],
        next_cursor=next_cursor,
    )


@router.post(
    "",
    response_model=RoleRead,
    status_code=status.HTTP_201_CREATED,
    operation_id="createRole",
)
async def create_role(
    body: CreateRoleRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: RoleService = Depends(role_service),
) -> RoleRead:
    if ctx.user_id is None:
        raise FoundationError(PERMISSION_DENIED, detail="Actor user_id required")
    role = await svc.create(
        session,
        tenant_id=ctx.tenant_id,
        request_id=ctx.request_id,
        actor_id=ctx.user_id,
        name=body.name,
        display_name=body.display_name,
        description=body.description,
        permissions=body.permissions,
    )
    return RoleRead.model_validate(role)


@router.get("/{role_id}", response_model=RoleRead, operation_id="getRole")
async def get_role(
    role_id: str = Path(pattern=r"^rol_[0-9A-Z]{26}$"),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: RoleService = Depends(role_service),
) -> RoleRead:
    return RoleRead.model_validate(
        await svc.get(session, tenant_id=ctx.tenant_id, role_id=role_id)
    )


@router.patch("/{role_id}", response_model=RoleRead, operation_id="updateRole")
async def update_role(
    role_id: str = Path(pattern=r"^rol_[0-9A-Z]{26}$"),
    body: UpdateRoleRequest = Body(...),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: RoleService = Depends(role_service),
) -> RoleRead:
    if ctx.user_id is None:
        raise FoundationError(PERMISSION_DENIED, detail="Actor user_id required")
    return RoleRead.model_validate(
        await svc.update(
            session,
            tenant_id=ctx.tenant_id,
            request_id=ctx.request_id,
            actor_id=ctx.user_id,
            role_id=role_id,
            patch=body.model_dump(exclude_unset=True),
        )
    )


@router.delete(
    "/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="deleteRole",
    response_class=Response,
)
async def delete_role(
    role_id: str = Path(pattern=r"^rol_[0-9A-Z]{26}$"),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: RoleService = Depends(role_service),
) -> Response:
    if ctx.user_id is None:
        raise FoundationError(PERMISSION_DENIED, detail="Actor user_id required")
    await svc.delete(
        session,
        tenant_id=ctx.tenant_id,
        request_id=ctx.request_id,
        actor_id=ctx.user_id,
        role_id=role_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
