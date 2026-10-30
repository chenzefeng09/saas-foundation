"""Incident response endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_security_ops.api.dependencies import (
    current_request_id,
    db_session,
    security_ops_service,
)
from foundation_security_ops.services.security_ops_service import SecurityOpsService

router = APIRouter()


def _incident_out(inc: Any) -> dict[str, Any]:
    return {
        "id": inc.id,
        "severity": inc.severity,
        "category": inc.category,
        "title": inc.title,
        "detected_at": inc.detected_at.isoformat() if inc.detected_at else None,
        "reported_by": inc.reported_by,
        "ic": inc.ic,
        "status": inc.status,
        "containment_at": inc.containment_at.isoformat() if inc.containment_at else None,
        "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None,
        "pir_s3_key": inc.pir_s3_key,
        "customers_notified": inc.customers_notified,
        "regulators_notified": inc.regulators_notified,
        "affected_tenants": inc.affected_tenants or [],
    }


@router.get("/incidents", tags=["incidents"])
async def list_incidents(
    filter_severity: str | None = Query(None, alias="filter.severity"),
    filter_status: str | None = Query(None, alias="filter.status"),
    session: AsyncSession = Depends(db_session),
    svc: SecurityOpsService = Depends(security_ops_service),
) -> dict[str, Any]:
    incidents = await svc.list_incidents(
        session,
        severity=filter_severity,
        status=filter_status,
    )
    return {"items": [_incident_out(i) for i in incidents], "next_cursor": None}


class DeclareIncidentRequest(BaseModel):
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW
    category: str  # DATA_BREACH / RANSOMWARE / DDOS / INSIDER / OUTAGE / OTHER
    title: str
    ic: str | None = None
    affected_tenants: list[str] = []


@router.post("/incidents", status_code=201, tags=["incidents"])
async def declare_incident(
    body: DeclareIncidentRequest,
    session: AsyncSession = Depends(db_session),
    svc: SecurityOpsService = Depends(security_ops_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    # reported_by: use request_id as proxy (real implementation would pull from auth context)
    inc = await svc.declare_incident(
        session,
        severity=body.severity,
        category=body.category,
        title=body.title,
        reported_by=request_id or "system",
        ic=body.ic,
        affected_tenants=body.affected_tenants,
        request_id=request_id,
    )
    return _incident_out(inc)


@router.delete(
    "/incidents/{inc_id}",
    status_code=204,
    response_class=Response,
    tags=["incidents"],
)
async def delete_incident(
    inc_id: str,
    session: AsyncSession = Depends(db_session),
    svc: SecurityOpsService = Depends(security_ops_service),
    request_id: str = Depends(current_request_id),
) -> Response:
    # storage-v1 §6.2: hand off retention + S3 GC to lifecycle.
    await svc.delete_incident(session, inc_id, request_id=request_id)
    return Response(status_code=204)


@router.get("/incidents/{inc_id}", tags=["incidents"])
async def get_incident(
    inc_id: str,
    session: AsyncSession = Depends(db_session),
    svc: SecurityOpsService = Depends(security_ops_service),
) -> dict[str, Any]:
    inc = await svc.get_incident(session, inc_id)
    return _incident_out(inc)


class UpdateIncidentRequest(BaseModel):
    status: str | None = None
    ic: str | None = None
    customers_notified: bool | None = None
    regulators_notified: bool | None = None


@router.patch("/incidents/{inc_id}", tags=["incidents"])
async def update_incident(
    inc_id: str,
    body: UpdateIncidentRequest,
    session: AsyncSession = Depends(db_session),
    svc: SecurityOpsService = Depends(security_ops_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    inc = await svc.update_incident(
        session,
        inc_id,
        status=body.status,
        ic=body.ic,
        customers_notified=body.customers_notified,
        regulators_notified=body.regulators_notified,
        request_id=request_id,
    )
    return _incident_out(inc)


class ResolveIncidentRequest(BaseModel):
    root_cause: str = Field(min_length=20)
    pir_s3_key: str


@router.post("/incidents/{inc_id}/resolve", tags=["incidents"])
async def resolve_incident(
    inc_id: str,
    body: ResolveIncidentRequest,
    session: AsyncSession = Depends(db_session),
    svc: SecurityOpsService = Depends(security_ops_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    inc = await svc.resolve_incident(
        session,
        inc_id,
        root_cause=body.root_cause,
        pir_s3_key=body.pir_s3_key,
        request_id=request_id,
    )
    return _incident_out(inc)
