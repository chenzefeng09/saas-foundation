"""Lifecycle API endpoints."""

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_lifecycle.api.dependencies import (
    current_context, current_request_id, db_session, lifecycle_service, legal_hold_service,
)
from foundation_lifecycle.domain.base import FoundationContext
from foundation_lifecycle.services.lifecycle_service import LifecycleService
from foundation_lifecycle.services.legal_hold_service import LegalHoldService

router = APIRouter()


class SoftDeleteRequest(BaseModel):
    resource_type_id: str; resource_id: str; resource_name: str | None = None

class RestoreRequest(BaseModel):
    restored_by: str | None = None

class HardDeleteRequest(BaseModel):
    destroyed_by: str; witness_user_id: str | None = None

class PlaceLegalHoldRequest(BaseModel):
    resource_type_id: str; resource_id: str
    reason: str = Field(min_length=10); case_reference: str | None = None

class ReleaseLegalHoldRequest(BaseModel):
    released_by: str


# -- Recycle Bin --
@router.post("/recycle-bin:soft-delete", status_code=201, operation_id="softDelete")
async def soft_delete(
    body: SoftDeleteRequest, ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session), svc: LifecycleService = Depends(lifecycle_service),
    request_id: str = Depends(current_request_id),
) -> dict:
    entry = await svc.soft_delete(session, tenant_id=ctx.tenant_id,
        resource_type_id=body.resource_type_id, resource_id=body.resource_id,
        resource_name=body.resource_name, deleted_by=ctx.user_id or "", request_id=request_id)
    return {"bin_id": entry.id, "expires_at": entry.expires_at.isoformat()}

@router.post("/recycle-bin/{bin_id}:restore", operation_id="restore")
async def restore(
    bin_id: str, body: RestoreRequest | None = None,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session), svc: LifecycleService = Depends(lifecycle_service),
    request_id: str = Depends(current_request_id),
) -> dict:
    await svc.restore(session, tenant_id=ctx.tenant_id, bin_id=bin_id,
        restored_by=body.restored_by if body else ctx.user_id or "", request_id=request_id)
    return {"restored": True}

@router.post("/recycle-bin/{bin_id}:hard-delete", operation_id="hardDelete")
async def hard_delete(
    bin_id: str, body: HardDeleteRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session), svc: LifecycleService = Depends(lifecycle_service),
    request_id: str = Depends(current_request_id),
) -> dict:
    await svc.hard_delete(session, tenant_id=ctx.tenant_id, bin_id=bin_id,
        destroyed_by=body.destroyed_by, witness_user_id=body.witness_user_id, request_id=request_id)
    return {"destroyed": True}

@router.get("/recycle-bin", operation_id="listRecycleBin")
async def list_bin(
    cursor: str | None = Query(default=None), limit: int = Query(default=50, ge=1, le=200),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session), svc: LifecycleService = Depends(lifecycle_service),
) -> dict:
    items, next_cursor = await svc.list_recycle_bin(session, tenant_id=ctx.tenant_id, cursor=cursor, limit=limit)
    return {"items": [{"id": i.id, "resource_type": i.resource_type_id, "resource_id": i.resource_id,
                        "deleted_at": i.deleted_at.isoformat(), "expires_at": i.expires_at.isoformat()} for i in items],
            "next_cursor": next_cursor}

@router.post("/sweep", operation_id="sweepExpired")
async def sweep(
    session: AsyncSession = Depends(db_session), svc: LifecycleService = Depends(lifecycle_service),
) -> dict:
    count = await svc.sweep_expired(session)
    return {"destroyed": count}

# -- Legal Hold --
@router.post("/legal-holds", status_code=201, operation_id="placeLegalHold")
async def place_hold(
    body: PlaceLegalHoldRequest, ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session), svc: LegalHoldService = Depends(legal_hold_service),
    request_id: str = Depends(current_request_id),
) -> dict:
    hold = await svc.place(session, tenant_id=ctx.tenant_id, resource_type_id=body.resource_type_id,
        resource_id=body.resource_id, reason=body.reason, placed_by=ctx.user_id or "",
        case_reference=body.case_reference, request_id=request_id)
    return {"hold_id": hold.id, "status": "ACTIVE"}

@router.post("/legal-holds/{hold_id}:release", operation_id="releaseLegalHold")
async def release_hold(
    hold_id: str, body: ReleaseLegalHoldRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session), svc: LegalHoldService = Depends(legal_hold_service),
    request_id: str = Depends(current_request_id),
) -> dict:
    await svc.release(session, tenant_id=ctx.tenant_id, hold_id=hold_id,
        released_by=body.released_by, request_id=request_id)
    return {"released": True}

@router.get("/legal-holds:check", operation_id="checkLegalHold")
async def check_hold(
    resource_type_id: str = Query(...), resource_id: str = Query(...),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session), svc: LegalHoldService = Depends(legal_hold_service),
) -> dict:
    active = await svc.check(session, tenant_id=ctx.tenant_id,
                              resource_type_id=resource_type_id, resource_id=resource_id)
    return {"active": active}

@router.get("/legal-holds", operation_id="listLegalHolds")
async def list_holds(
    cursor: str | None = Query(default=None), limit: int = Query(default=50, ge=1, le=200),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session), svc: LegalHoldService = Depends(legal_hold_service),
) -> dict:
    items, next_cursor = await svc.list_holds(session, tenant_id=ctx.tenant_id, cursor=cursor, limit=limit)
    return {"items": [{"id": i.id, "resource_type": i.resource_type_id, "resource_id": i.resource_id,
                        "reason": i.reason, "placed_at": i.placed_at.isoformat()} for i in items],
            "next_cursor": next_cursor}
