"""DLP + Classification API endpoints (dlp-classification-v1 §3)."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_dlp.api.dependencies import (
    TrustedUserClearance,
    current_context,
    current_request_id,
    db_session,
    dlp_service,
    is_management_actor,
    require_management_actor,
    trusted_user_clearance,
)
from foundation_dlp.domain.base import FoundationContext
from foundation_dlp.domain.models import SensitivityLevel
from foundation_dlp.services.dlp_service import DLPService

router = APIRouter()


class TagResourceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resource_type: str
    resource_id: str
    sensitivity: SensitivityLevel
    tags: list[str] | None = None
    reason: str | None = None


class CheckAccessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resource_type: str
    resource_id: str


class CheckDownloadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resource_type: str
    resource_id: str
    destination: str = "laptop"


class ScanContentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str
    resource_type: str
    resource_id: str


# -- Classification --
@router.post("/classification:tag", status_code=201, operation_id="tagResource")
async def tag_resource(
    body: TagResourceRequest,
    ctx: FoundationContext = Depends(require_management_actor),
    session: AsyncSession = Depends(db_session),
    svc: DLPService = Depends(dlp_service),
    request_id: str = Depends(current_request_id),
) -> dict:
    cls = await svc.tag_resource(
        session,
        tenant_id=ctx.tenant_id,
        resource_type=body.resource_type,
        resource_id=body.resource_id,
        sensitivity=body.sensitivity,
        tags=body.tags,
        reason=body.reason,
        tagged_by=ctx.user_id or "",
        request_id=request_id,
    )
    return {"id": cls.id, "sensitivity": cls.sensitivity, "tagged": True}


@router.get("/classification:get", operation_id="getClassification")
async def get_classification(
    resource_type: str = Query(...),
    resource_id: str = Query(...),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: DLPService = Depends(dlp_service),
) -> dict:
    cls = await svc.get_sensitivity(
        session, tenant_id=ctx.tenant_id, resource_type=resource_type, resource_id=resource_id
    )
    return {"sensitivity": cls.sensitivity, "tags": cls.tags, "downgradable": cls.downgradable}


# -- Access Checks --
@router.post("/check:read", operation_id="checkRead")
async def check_read(
    body: CheckAccessRequest,
    ctx: FoundationContext = Depends(current_context),
    trusted_user: TrustedUserClearance = Depends(trusted_user_clearance),
    session: AsyncSession = Depends(db_session),
    svc: DLPService = Depends(dlp_service),
    request_id: str = Depends(current_request_id),
) -> dict:
    return await svc.check_read(
        session,
        tenant_id=ctx.tenant_id,
        user_id=trusted_user.user_id,
        user_clearance=trusted_user.clearance,
        resource_type=body.resource_type,
        resource_id=body.resource_id,
        request_id=request_id,
    )


@router.post("/check:download", operation_id="checkDownload")
async def check_download(
    body: CheckDownloadRequest,
    ctx: FoundationContext = Depends(current_context),
    trusted_user: TrustedUserClearance = Depends(trusted_user_clearance),
    session: AsyncSession = Depends(db_session),
    svc: DLPService = Depends(dlp_service),
    request_id: str = Depends(current_request_id),
) -> dict:
    return await svc.check_download(
        session,
        tenant_id=ctx.tenant_id,
        user_id=trusted_user.user_id,
        user_clearance=trusted_user.clearance,
        resource_type=body.resource_type,
        resource_id=body.resource_id,
        destination=body.destination,
        request_id=request_id,
    )


@router.post("/scan", operation_id="scanContent")
async def scan_content(
    body: ScanContentRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: DLPService = Depends(dlp_service),
    request_id: str = Depends(current_request_id),
) -> dict:
    """Scan ``content`` for the resource and return ``{hits, max_sensitivity, action}``.

    Any tenant-scoped caller may scan: the verdict depends only on the content and
    the tenant's rules, and every hit is recorded as a DLP event either way.  Only a
    trusted SERVICE/ADMIN caller also persists the hit level as the resource's
    classification label.  That label drives ``check:read`` / ``check:download``,
    so an untrusted caller (for example a sandboxed agent worker scanning its own
    tool calls) must never be able to raise the label of an arbitrary resource id.
    """
    return await svc.scan_content(
        session,
        tenant_id=ctx.tenant_id,
        content=body.content,
        resource_type=body.resource_type,
        resource_id=body.resource_id,
        user_id=ctx.user_id,
        request_id=request_id,
        persist_classification=is_management_actor(ctx),
    )


# -- Governance / Oversight (read-only) --
def _parse_before(before: str | None) -> datetime | None:
    """Parse an ISO-8601 occurred_at cursor; tolerate a trailing 'Z'."""
    if not before:
        return None
    try:
        return datetime.fromisoformat(before.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"invalid 'before' cursor: {before}") from exc


@router.get("/events", operation_id="listDlpEvents")
async def list_events(
    check_type: str | None = Query(None),
    decision: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    before: str | None = Query(None, description="ISO occurred_at cursor (keyset, desc)"),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: DLPService = Depends(dlp_service),
) -> dict:
    rows = await svc.list_events(
        session,
        tenant_id=ctx.tenant_id,
        check_type=check_type,
        decision=decision,
        before=_parse_before(before),
        limit=limit,
    )
    items = [
        {
            "id": e.id,
            "check_type": e.check_type,
            "decision": e.decision,
            "user_id": e.user_id,
            "resource_type": e.resource_type,
            "resource_id": e.resource_id,
            "reason_code": e.reason_code,
            "detail": e.detail,
            "occurred_at": e.occurred_at.isoformat() if e.occurred_at else None,
            "request_id": e.request_id,
        }
        for e in rows
    ]
    next_before = (
        rows[-1].occurred_at.isoformat() if len(rows) == limit and rows[-1].occurred_at else None
    )
    return {"items": items, "next_before": next_before}


@router.get("/classifications", operation_id="listClassifications")
async def list_classifications(
    sensitivity: str | None = Query(None, pattern=r"^L[1-5]$"),
    resource_type: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    before: str | None = Query(None, description="ISO updated_at cursor (keyset, desc)"),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: DLPService = Depends(dlp_service),
) -> dict:
    rows = await svc.list_classifications(
        session,
        tenant_id=ctx.tenant_id,
        sensitivity=sensitivity,
        resource_type=resource_type,
        before=_parse_before(before),
        limit=limit,
    )
    items = [
        {
            "resource_type": c.resource_type,
            "resource_id": c.resource_id,
            "sensitivity": c.sensitivity,
            "tags": c.tags,
            "reason": c.reason,
            "tagged_by": c.tagged_by,
            "tagged_at": c.tagged_at.isoformat() if c.tagged_at else None,
            "updated_at": c.updated_at.isoformat() if c.updated_at else None,
            "downgradable": c.downgradable,
        }
        for c in rows
    ]
    next_before = (
        rows[-1].updated_at.isoformat() if len(rows) == limit and rows[-1].updated_at else None
    )
    return {"items": items, "next_before": next_before}


@router.get("/stats", operation_id="dlpStats")
async def dlp_stats(
    since: str | None = Query(None, description="ISO lower bound on occurred_at; default 30d ago"),
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: DLPService = Depends(dlp_service),
) -> dict:
    since_dt = _parse_before(since) or (datetime.now(UTC) - timedelta(days=30))
    return await svc.stats(session, tenant_id=ctx.tenant_id, since=since_dt)
