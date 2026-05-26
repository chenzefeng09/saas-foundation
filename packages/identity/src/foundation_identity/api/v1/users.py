"""User CRUD + freeze / unfreeze / password-reset endpoints.

operationId values must match contracts/openapi/identity.yaml.
"""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Path, Query, status
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_identity.api.dependencies import current_context, db_session, user_service
from foundation_identity.domain.base import FoundationContext
from foundation_identity.schemas.common import CursorPage
from foundation_identity.schemas.user import (
    FreezeUserRequest,
    InviteUserRequest,
    UpdateUserRequest,
    UserRead,
)
from foundation_identity.services.user_service import UserService

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=CursorPage[UserRead], operation_id="listUsers")
async def list_users(
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    status_filter: str | None = Query(default=None, alias="filter.status"),
    email_filter: str | None = Query(default=None, alias="filter.email"),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: UserService = Depends(user_service),
) -> CursorPage[UserRead]:
    users, next_cursor = await svc.list_users(
        session,
        tenant_id=ctx.tenant_id,
        cursor=cursor,
        limit=limit,
        status_filter=status_filter,
        email_filter=email_filter,
    )
    return CursorPage[UserRead](
        items=[UserRead.model_validate(u) for u in users],
        next_cursor=next_cursor,
    )


@router.post(
    "",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    operation_id="inviteUser",
)
async def invite_user(
    body: InviteUserRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: UserService = Depends(user_service),
) -> UserRead:
    user = await svc.invite(
        session,
        tenant_id=ctx.tenant_id,
        request_id=ctx.request_id,
        actor_id=ctx.user_id,
        email=str(body.email),
        display_name=body.display_name,
        roles=body.roles,
        send_invite_email=body.send_invite_email,
    )
    return UserRead.model_validate(user)


@router.get("/{user_id}", response_model=UserRead, operation_id="getUser")
async def get_user(
    user_id: str = Path(pattern=r"^usr_[0-9A-Z]{26}$"),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: UserService = Depends(user_service),
) -> UserRead:
    user = await svc.get_user(session, tenant_id=ctx.tenant_id, user_id=user_id)
    return UserRead.model_validate(user)


@router.patch("/{user_id}", response_model=UserRead, operation_id="updateUser")
async def update_user(
    user_id: str = Path(pattern=r"^usr_[0-9A-Z]{26}$"),
    body: UpdateUserRequest = Body(...),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: UserService = Depends(user_service),
) -> UserRead:
    user = await svc.update(
        session,
        tenant_id=ctx.tenant_id,
        request_id=ctx.request_id,
        actor_id=ctx.user_id,
        user_id=user_id,
        patch=body.model_dump(exclude_unset=True),
    )
    return UserRead.model_validate(user)


@router.post(
    "/{user_id}/freeze",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="freezeUser",
    response_class=Response,
)
async def freeze_user(
    user_id: str = Path(pattern=r"^usr_[0-9A-Z]{26}$"),
    body: FreezeUserRequest = Body(...),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: UserService = Depends(user_service),
) -> Response:
    if ctx.user_id is None:
        from foundation_identity.errors import PERMISSION_DENIED, FoundationError
        raise FoundationError(PERMISSION_DENIED, detail="Actor user_id required")
    await svc.freeze(
        session,
        tenant_id=ctx.tenant_id,
        request_id=ctx.request_id,
        actor_id=ctx.user_id,
        user_id=user_id,
        reason=body.reason,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{user_id}/unfreeze",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="unfreezeUser",
    response_class=Response,
)
async def unfreeze_user(
    user_id: str = Path(pattern=r"^usr_[0-9A-Z]{26}$"),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: UserService = Depends(user_service),
) -> Response:
    if ctx.user_id is None:
        from foundation_identity.errors import PERMISSION_DENIED, FoundationError
        raise FoundationError(PERMISSION_DENIED, detail="Actor user_id required")
    await svc.unfreeze(
        session,
        tenant_id=ctx.tenant_id,
        request_id=ctx.request_id,
        actor_id=ctx.user_id,
        user_id=user_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{user_id}/password:reset",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="forcePasswordReset",
    response_class=Response,
)
async def force_password_reset(
    user_id: str = Path(pattern=r"^usr_[0-9A-Z]{26}$"),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: UserService = Depends(user_service),
) -> Response:
    if ctx.user_id is None:
        from foundation_identity.errors import PERMISSION_DENIED, FoundationError
        raise FoundationError(PERMISSION_DENIED, detail="Actor user_id required")
    await svc.force_password_reset(
        session,
        tenant_id=ctx.tenant_id,
        request_id=ctx.request_id,
        actor_id=ctx.user_id,
        user_id=user_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
