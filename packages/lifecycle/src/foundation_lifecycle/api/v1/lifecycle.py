"""Lifecycle API endpoints."""

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_lifecycle.api.dependencies import (
    current_context, current_request_id, current_user_id, db_session, lifecycle_service,
    legal_hold_service,
)
from foundation_lifecycle.domain.base import FoundationContext
from foundation_lifecycle.services.lifecycle_service import LifecycleService
from foundation_lifecycle.services.legal_hold_service import LegalHoldService

router = APIRouter()


class SoftDeleteRequest(BaseModel):
    resource_type_id: str; resource_id: str; resource_name: str | None = None
    # Optional ``["bucket::key", ...]`` so lifecycle GC can clean S3 on
    # hard-delete; see storage-v1 §6.2.
    s3_location: list[str] | None = None

# Restore, hard-delete and release record the authenticated caller (``current_user_id``)
# as the one who acted, never a name from the body. Their bodies only keep the fields
# older clients still send (agent-platform's admin web sends destroyed_by / released_by),
# so those requests still validate; the values are ignored.
_IGNORED = "Deprecated and ignored: the service records the caller (X-User-Id)."

class RestoreRequest(BaseModel):
    restored_by: str | None = Field(default=None, deprecated=True, description=_IGNORED)

class HardDeleteRequest(BaseModel):
    destroyed_by: str | None = Field(default=None, deprecated=True, description=_IGNORED)
    # A witness the executor names has confirmed nothing. Until the witness can confirm
    # with a request of their own, a destruction certificate names no witness.
    witness_user_id: str | None = Field(
        default=None, deprecated=True,
        description="Deprecated and ignored: the certificate names no witness the caller picks.")

class PlaceLegalHoldRequest(BaseModel):
    resource_type_id: str; resource_id: str
    reason: str = Field(min_length=10); case_reference: str | None = None

class ReleaseLegalHoldRequest(BaseModel):
    released_by: str | None = Field(default=None, deprecated=True, description=_IGNORED)


# -- Recycle Bin --
@router.post("/recycle-bin:soft-delete", status_code=201, operation_id="softDelete")
async def soft_delete(
    body: SoftDeleteRequest, ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session), svc: LifecycleService = Depends(lifecycle_service),
    request_id: str = Depends(current_request_id),
) -> dict:
    entry = await svc.soft_delete(session, tenant_id=ctx.tenant_id,
        resource_type_id=body.resource_type_id, resource_id=body.resource_id,
        resource_name=body.resource_name, deleted_by=ctx.user_id or "", request_id=request_id,
        s3_location=body.s3_location)
    return {"bin_id": entry.id, "expires_at": entry.expires_at.isoformat()}

@router.post("/recycle-bin/{bin_id}:restore", operation_id="restore")
async def restore(
    bin_id: str, body: RestoreRequest | None = None,  # legacy fields only, ignored
    ctx: FoundationContext = Depends(current_context), actor: str = Depends(current_user_id),
    session: AsyncSession = Depends(db_session), svc: LifecycleService = Depends(lifecycle_service),
    request_id: str = Depends(current_request_id),
) -> dict:
    await svc.restore(session, tenant_id=ctx.tenant_id, bin_id=bin_id,
        restored_by=actor, request_id=request_id)
    return {"restored": True}

@router.post("/recycle-bin/{bin_id}:hard-delete", operation_id="hardDelete")
async def hard_delete(
    bin_id: str, body: HardDeleteRequest | None = None,  # legacy fields only, ignored
    ctx: FoundationContext = Depends(current_context), actor: str = Depends(current_user_id),
    session: AsyncSession = Depends(db_session), svc: LifecycleService = Depends(lifecycle_service),
    request_id: str = Depends(current_request_id),
) -> dict:
    await svc.hard_delete(session, tenant_id=ctx.tenant_id, bin_id=bin_id,
        destroyed_by=actor, witness_user_id=None, request_id=request_id)
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
    hold_id: str, body: ReleaseLegalHoldRequest | None = None,  # legacy field only, ignored
    ctx: FoundationContext = Depends(current_context), actor: str = Depends(current_user_id),
    session: AsyncSession = Depends(db_session), svc: LegalHoldService = Depends(legal_hold_service),
    request_id: str = Depends(current_request_id),
) -> dict:
    await svc.release(session, tenant_id=ctx.tenant_id, hold_id=hold_id,
        released_by=actor, request_id=request_id)
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
    resource_type_id: str | None = Query(default=None, alias="filter.resource_type"),
    resource_id: str | None = Query(default=None, alias="filter.resource_id"),
    cursor: str | None = Query(default=None), limit: int = Query(default=50, ge=1, le=200),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session), svc: LegalHoldService = Depends(legal_hold_service),
) -> dict:
    items, next_cursor = await svc.list_holds(session, tenant_id=ctx.tenant_id,
        resource_type_id=resource_type_id, resource_id=resource_id, cursor=cursor, limit=limit)
    return {"items": [{"id": i.id, "resource_type": i.resource_type_id, "resource_id": i.resource_id,
                        "reason": i.reason, "placed_at": i.placed_at.isoformat()} for i in items],
            "next_cursor": next_cursor}
