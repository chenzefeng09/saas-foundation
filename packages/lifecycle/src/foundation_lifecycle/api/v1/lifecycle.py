"""Lifecycle API endpoints."""

from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_lifecycle.api.dependencies import (
    approval_service, current_context, current_request_id, current_user_id, db_session,
    lifecycle_service, legal_hold_service,
)
from foundation_lifecycle.domain.base import FoundationContext
from foundation_lifecycle.domain.models import ApprovalRequest
from foundation_lifecycle.services.approval_service import ApprovalService, effective_status
from foundation_lifecycle.services.lifecycle_service import LifecycleService
from foundation_lifecycle.services.legal_hold_service import LegalHoldService

router = APIRouter()


class SoftDeleteRequest(BaseModel):
    resource_type_id: str; resource_id: str; resource_name: str | None = None
    # Optional ``["bucket::key", ...]`` so lifecycle GC can clean S3 on
    # hard-delete; see storage-v1 §6.2.
    s3_location: list[str] | None = None

# Restore, hard-delete and release record the authenticated caller (``current_user_id``)
# as the one who acted or asked, never a name from the body. Their bodies only keep the
# fields older clients still send (agent-platform's admin web sends destroyed_by /
# released_by), so those requests still validate; the values are ignored.
_IGNORED = "Deprecated and ignored: the service records the caller (X-User-Id)."

class RestoreRequest(BaseModel):
    restored_by: str | None = Field(default=None, deprecated=True, description=_IGNORED)

class HardDeleteRequest(BaseModel):
    destroyed_by: str | None = Field(default=None, deprecated=True, description=_IGNORED)
    # A witness the requester names has confirmed nothing: the witness is whoever
    # approves the request with a request of their own.
    witness_user_id: str | None = Field(
        default=None, deprecated=True,
        description="Deprecated and ignored: the witness is the user who approves the request.")

class PlaceLegalHoldRequest(BaseModel):
    resource_type_id: str; resource_id: str
    reason: str = Field(min_length=10); case_reference: str | None = None

class ReleaseLegalHoldRequest(BaseModel):
    released_by: str | None = Field(default=None, deprecated=True, description=_IGNORED)


def _approval(req: ApprovalRequest) -> dict:
    return {"id": req.id, "operation": req.operation, "target_id": req.target_id,
            "status": effective_status(req, datetime.now(UTC)),
            "requested_by": req.requested_by, "requested_at": req.requested_at.isoformat(),
            "expires_at": req.expires_at.isoformat(), "decided_by": req.decided_by,
            "decided_at": req.decided_at.isoformat() if req.decided_at else None}


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

# Hard-delete and release take a second person (lifecycle-v1 §4.4): these two routes only
# open an approval request (202); /approval-requests/{approval_id}/approve carries it out.
@router.post("/recycle-bin/{bin_id}:hard-delete", status_code=202, operation_id="hardDelete",
             responses={200: {"description": "Already destroyed"}})
async def hard_delete(
    bin_id: str, response: Response,
    body: HardDeleteRequest | None = None,  # legacy fields only, ignored
    ctx: FoundationContext = Depends(current_context), actor: str = Depends(current_user_id),
    session: AsyncSession = Depends(db_session), svc: ApprovalService = Depends(approval_service),
    request_id: str = Depends(current_request_id),
) -> dict:
    req = await svc.request_hard_delete(session, tenant_id=ctx.tenant_id, bin_id=bin_id,
        requested_by=actor, request_id=request_id)
    if req is None:
        response.status_code = 200
        return {"destroyed": True}
    return {"destroyed": False, "approval_request": _approval(req)}

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

@router.post("/legal-holds/{hold_id}:release", status_code=202, operation_id="releaseLegalHold",
             responses={200: {"description": "Already released"}})
async def release_hold(
    hold_id: str, response: Response,
    body: ReleaseLegalHoldRequest | None = None,  # legacy field only, ignored
    ctx: FoundationContext = Depends(current_context), actor: str = Depends(current_user_id),
    session: AsyncSession = Depends(db_session), svc: ApprovalService = Depends(approval_service),
    request_id: str = Depends(current_request_id),
) -> dict:
    req = await svc.request_release(session, tenant_id=ctx.tenant_id, hold_id=hold_id,
        requested_by=actor, request_id=request_id)
    if req is None:
        response.status_code = 200
        return {"released": True}
    return {"released": False, "approval_request": _approval(req)}

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

# -- Four-eyes approvals (lifecycle-v1 §4.4) --
@router.get("/approval-requests", operation_id="listApprovalRequests")
async def list_approval_requests(
    status: Literal["PENDING", "APPROVED", "REJECTED", "EXPIRED"] | None = Query(
        default=None, alias="filter.status"),
    operation: Literal["HARD_DELETE", "RELEASE_LEGAL_HOLD"] | None = Query(
        default=None, alias="filter.operation"),
    cursor: str | None = Query(default=None), limit: int = Query(default=50, ge=1, le=200),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session), svc: ApprovalService = Depends(approval_service),
) -> dict:
    items, next_cursor = await svc.list_requests(session, tenant_id=ctx.tenant_id,
        status=status, operation=operation, cursor=cursor, limit=limit)
    return {"items": [_approval(i) for i in items], "next_cursor": next_cursor}

@router.get("/approval-requests/{approval_id}", operation_id="getApprovalRequest")
async def get_approval_request(
    approval_id: str, ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session), svc: ApprovalService = Depends(approval_service),
) -> dict:
    return _approval(await svc.get(session, tenant_id=ctx.tenant_id, approval_id=approval_id))

@router.post("/approval-requests/{approval_id}/approve", operation_id="approveRequest")
async def approve_request(
    approval_id: str,
    ctx: FoundationContext = Depends(current_context), approver: str = Depends(current_user_id),
    session: AsyncSession = Depends(db_session), svc: ApprovalService = Depends(approval_service),
    request_id: str = Depends(current_request_id),
) -> dict:
    req = await svc.approve(session, tenant_id=ctx.tenant_id, approval_id=approval_id,
        approved_by=approver, request_id=request_id)
    return _approval(req)

@router.post("/approval-requests/{approval_id}/reject", operation_id="rejectRequest")
async def reject_request(
    approval_id: str,
    ctx: FoundationContext = Depends(current_context), actor: str = Depends(current_user_id),
    session: AsyncSession = Depends(db_session), svc: ApprovalService = Depends(approval_service),
    request_id: str = Depends(current_request_id),
) -> dict:
    req = await svc.reject(session, tenant_id=ctx.tenant_id, approval_id=approval_id,
        rejected_by=actor, request_id=request_id)
    return _approval(req)
