"""KEK lifecycle endpoints."""

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_crypto.api.dependencies import (
    current_context,
    current_request_id,
    db_session,
    kek_service,
)
from foundation_crypto.domain.base import FoundationContext
from foundation_crypto.schemas.common import CursorPage
from foundation_crypto.schemas.kek import (
    CreateKEKRequest,
    DestroyKEKRequest,
    KEKHistoryEntry,
    KEKRead,
    MarkForDestructionRequest,
    RotateKEKRequest,
)
from foundation_crypto.services.kek_service import KekService

router = APIRouter()


class AbortDestructionBody(BaseModel):
    reason: str = Field(min_length=10, max_length=500)


@router.get("", operation_id="listKeks")
async def list_keks(
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    filter_purpose: str | None = Query(default=None, alias="filter.purpose"),
    filter_status: str | None = Query(default=None, alias="filter.status"),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: KekService = Depends(kek_service),
) -> CursorPage[KEKRead]:
    items, next_cursor = await svc.list_keks(
        session,
        tenant_id=ctx.tenant_id,
        cursor=cursor,
        limit=limit,
        purpose=filter_purpose,
        status=filter_status,
    )
    return CursorPage(items=items, next_cursor=next_cursor)


@router.post("", status_code=201, operation_id="createKek")
async def create_kek(
    body: CreateKEKRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: KekService = Depends(kek_service),
    request_id: str = Depends(current_request_id),
) -> KEKRead:
    return await svc.create(
        session,
        tenant_id=ctx.tenant_id,
        request=body,
        actor_user_id=ctx.user_id or "",
        request_id=request_id,
    )


@router.get("/{kek_id}", operation_id="getKek")
async def get_kek(
    kek_id: str,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: KekService = Depends(kek_service),
) -> KEKRead:
    return await svc.get_kek(session, tenant_id=ctx.tenant_id, kek_id=kek_id)


@router.get("/{kek_id}/history", operation_id="getKekHistory")
async def get_kek_history(
    kek_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: KekService = Depends(kek_service),
) -> list[KEKHistoryEntry]:
    return await svc.get_kek_history(
        session, tenant_id=ctx.tenant_id, kek_id=kek_id, limit=limit,
    )


@router.post("/{kek_id}/rotate", operation_id="rotateKek")
async def rotate_kek(
    kek_id: str,
    body: RotateKEKRequest | None = None,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: KekService = Depends(kek_service),
    request_id: str = Depends(current_request_id),
) -> KEKRead:
    return await svc.rotate(
        session,
        tenant_id=ctx.tenant_id,
        kek_id=kek_id,
        request=body,
        actor_user_id=ctx.user_id or "",
        request_id=request_id,
    )


@router.post("/{kek_id}/mark-for-destruction", operation_id="markKekForDestruction")
async def mark_kek_for_destruction(
    kek_id: str,
    body: MarkForDestructionRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: KekService = Depends(kek_service),
    request_id: str = Depends(current_request_id),
) -> KEKRead:
    return await svc.mark_for_destruction(
        session,
        tenant_id=ctx.tenant_id,
        kek_id=kek_id,
        request=body,
        actor_user_id=ctx.user_id or "",
        request_id=request_id,
    )


@router.post("/{kek_id}/destroy", status_code=204, operation_id="destroyKek")
async def destroy_kek(
    kek_id: str,
    body: DestroyKEKRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: KekService = Depends(kek_service),
    request_id: str = Depends(current_request_id),
) -> None:
    await svc.destroy(
        session,
        tenant_id=ctx.tenant_id,
        kek_id=kek_id,
        request=body,
        actor_user_id=ctx.user_id or "",
        request_id=request_id,
    )


@router.post("/{kek_id}/abort-destruction", operation_id="abortKekDestruction")
async def abort_kek_destruction(
    kek_id: str,
    body: AbortDestructionBody,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: KekService = Depends(kek_service),
    request_id: str = Depends(current_request_id),
) -> KEKRead:
    return await svc.abort_destruction(
        session,
        tenant_id=ctx.tenant_id,
        kek_id=kek_id,
        reason=body.reason,
        actor_user_id=ctx.user_id or "",
        request_id=request_id,
    )
