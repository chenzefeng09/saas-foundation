"""Drill (演练) endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_security_ops.api.dependencies import (
    current_request_id,
    db_session,
    security_ops_service,
)
from foundation_security_ops.services.security_ops_service import SecurityOpsService

router = APIRouter()


def _drill_out(d: Any) -> dict[str, Any]:
    return {
        "id": d.id,
        "kind": d.kind,
        "scheduled_at": d.scheduled_at.isoformat() if d.scheduled_at else None,
        "status": d.status,
        "completed_at": d.completed_at.isoformat() if d.completed_at else None,
        "pir_s3_key": d.pir_s3_key,
        "participants": d.participants or [],
        "scenario_runbook": d.scenario_runbook,
    }


@router.get("/drills", tags=["drills"])
async def list_drills(
    filter_kind: str | None = Query(None, alias="filter.kind"),
    session: AsyncSession = Depends(db_session),
    svc: SecurityOpsService = Depends(security_ops_service),
) -> dict[str, Any]:
    drills = await svc.list_drills(session, kind=filter_kind)
    return {"items": [_drill_out(d) for d in drills], "next_cursor": None}


@router.delete(
    "/drills/{drill_id}",
    status_code=204,
    response_class=Response,
    tags=["drills"],
)
async def delete_drill(
    drill_id: str,
    session: AsyncSession = Depends(db_session),
    svc: SecurityOpsService = Depends(security_ops_service),
    request_id: str = Depends(current_request_id),
) -> Response:
    # storage-v1 §6.2: hand off retention + S3 GC to lifecycle.
    await svc.delete_drill(session, drill_id, request_id=request_id)
    return Response(status_code=204)


class ScheduleDrillRequest(BaseModel):
    id: str | None = None
    kind: str  # TABLETOP / PLAYBOOK_DRILL / RED_BLUE_TEAM
    scheduled_at: datetime
    status: str = "SCHEDULED"
    participants: list[str] = []
    scenario_runbook: str | None = None


@router.post("/drills", status_code=201, tags=["drills"])
async def schedule_drill(
    body: ScheduleDrillRequest,
    session: AsyncSession = Depends(db_session),
    svc: SecurityOpsService = Depends(security_ops_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    drill = await svc.schedule_drill(
        session,
        kind=body.kind,
        scheduled_at=body.scheduled_at,
        participants=body.participants,
        scenario_runbook=body.scenario_runbook,
        request_id=request_id,
    )
    return _drill_out(drill)
