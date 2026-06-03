"""PAM API endpoints — elevations, sessions."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from foundation_pam.api.dependencies import (
    current_context, current_request_id, db_session, pam_service,
)
from foundation_pam.domain.base import FoundationContext
from foundation_pam.services.pam_service import PAMService

router = APIRouter()


class RequestElevationBody(BaseModel):
    reason: str
    duration_minutes: int = 60
    target_resources: list[str] = []


class ApproveElevationBody(BaseModel):
    justification: str = ""


@router.post("/elevations", status_code=201, tags=["pam"])
async def request_elevation(
    body: RequestElevationBody,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: PAMService = Depends(pam_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    req = await svc.request_elevation(
        session, tenant_id=ctx.tenant_id,
        user_id=ctx.user_id or "",
        reason=body.reason,
        target_permissions=body.target_resources,
        duration_minutes=body.duration_minutes,
        ticket_reference=None,
        request_id=request_id,
    )
    return {"id": req.id, "status": req.status, "reason": req.reason, "duration_minutes": req.duration_minutes, "expires_at": req.expires_at.isoformat() if req.expires_at else None}


@router.post("/elevations/{elevation_id}/approve", tags=["pam"])
async def approve_elevation(
    elevation_id: str,
    body: ApproveElevationBody,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: PAMService = Depends(pam_service),
) -> dict[str, Any]:
    req = await svc.approve(
        session, tenant_id=ctx.tenant_id,
        request_id_str=elevation_id,
        approver_id=ctx.user_id or "",
        reason=body.justification or None,
    )
    return {"id": req.id, "status": req.status, "approved_by": req.approved_by}


@router.post("/elevations/{elevation_id}/revoke", tags=["pam"])
async def revoke_elevation(
    elevation_id: str,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: PAMService = Depends(pam_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    # Revoke the session associated with the elevation by looking up by elevation_id
    from sqlalchemy import select
    from foundation_pam.domain.models import PAMSession
    pam_sess = await session.scalar(
        select(PAMSession).where(
            PAMSession.elevation_request_id == elevation_id,
            PAMSession.tenant_id == ctx.tenant_id,
            PAMSession.is_active.is_(True),
        ).limit(1)
    )
    if pam_sess:
        await svc.revoke(
            session, tenant_id=ctx.tenant_id,
            session_id=pam_sess.id,
            revoked_by=ctx.user_id or "SYSTEM",
            reason="Revoked via API",
        )
    return {"elevation_id": elevation_id, "revoked": True}


@router.get("/sessions", tags=["pam"])
async def list_active_sessions(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: PAMService = Depends(pam_service),
) -> dict[str, Any]:
    sessions = await svc.get_active_sessions(session, tenant_id=ctx.tenant_id)
    return {"items": [{"id": s.id, "user_id": s.user_id, "permissions": s.permissions, "expires_at": s.expires_at.isoformat() if s.expires_at else None} for s in sessions]}


@router.get("/elevations/pending", tags=["pam"])
async def list_pending_elevations(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    from sqlalchemy import select
    from foundation_pam.domain.models import PAMElevationRequest
    rows = list((await session.scalars(
        select(PAMElevationRequest).where(
            PAMElevationRequest.tenant_id == ctx.tenant_id,
            PAMElevationRequest.status == "PENDING",
        )
    )).all())
    return {"items": [{"id": r.id, "user_id": r.user_id, "reason": r.reason, "status": r.status} for r in rows]}


@router.get("/elevations/history", tags=["pam"])
async def get_elevation_history(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    from sqlalchemy import select
    from foundation_pam.domain.models import PAMElevationRequest
    rows = list((await session.scalars(
        select(PAMElevationRequest).where(
            PAMElevationRequest.tenant_id == ctx.tenant_id,
        ).order_by(PAMElevationRequest.requested_at.desc()).limit(100)
    )).all())
    return {"items": [{"id": r.id, "user_id": r.user_id, "reason": r.reason, "status": r.status, "requested_at": r.requested_at.isoformat() if r.requested_at else None} for r in rows]}
