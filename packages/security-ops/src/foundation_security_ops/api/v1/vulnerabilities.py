"""Vulnerability tracking endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_security_ops.api.dependencies import (
    current_request_id,
    db_session,
    security_ops_service,
)
from foundation_security_ops.services.security_ops_service import SecurityOpsService

router = APIRouter()


def _vuln_out(v: Any) -> dict[str, Any]:
    return {
        "id": v.id,
        "source": v.source,
        "source_ref": v.source_ref,
        "cve_id": v.cve_id,
        "title": v.title,
        "severity": v.severity,
        "cvss_score": float(v.cvss_score) if v.cvss_score is not None else None,
        "package_affected": v.package_affected,
        "status": v.status,
        "found_at": v.found_at.isoformat() if v.found_at else None,
        "due_at": v.due_at.isoformat() if v.due_at else None,
        "assignee": v.assignee,
        "fix_pr_url": v.fix_pr_url,
        "closed_at": v.closed_at.isoformat() if v.closed_at else None,
        "exception_id": v.exception_id,
        "risk_acceptance_id": v.risk_acceptance_id,
        "notes_md": v.notes_md,
    }


@router.get("/vulnerabilities/sla-dashboard", tags=["vulnerabilities"])
async def get_sla_dashboard(
    session: AsyncSession = Depends(db_session),
    svc: SecurityOpsService = Depends(security_ops_service),
) -> dict[str, Any]:
    return await svc.sla_dashboard(session)


@router.get("/vulnerabilities", tags=["vulnerabilities"])
async def list_vulnerabilities(
    filter_severity: str | None = Query(None, alias="filter.severity"),
    filter_status: str | None = Query(None, alias="filter.status"),
    filter_package: str | None = Query(None, alias="filter.package_affected"),
    filter_source: str | None = Query(None, alias="filter.source"),
    session: AsyncSession = Depends(db_session),
    svc: SecurityOpsService = Depends(security_ops_service),
) -> dict[str, Any]:
    vulns = await svc.list_vulnerabilities(
        session,
        severity=filter_severity,
        status=filter_status,
        package_affected=filter_package,
        source=filter_source,
    )
    return {"items": [_vuln_out(v) for v in vulns], "next_cursor": None}


@router.get("/vulnerabilities/{vuln_id}", tags=["vulnerabilities"])
async def get_vulnerability(
    vuln_id: str,
    session: AsyncSession = Depends(db_session),
    svc: SecurityOpsService = Depends(security_ops_service),
) -> dict[str, Any]:
    vuln = await svc.get_vulnerability(session, vuln_id)
    return _vuln_out(vuln)


class UpdateVulnerabilityRequest(BaseModel):
    status: str | None = None
    assignee: str | None = None
    fix_pr_url: str | None = None
    notes_md: str | None = None


@router.patch("/vulnerabilities/{vuln_id}", tags=["vulnerabilities"])
async def update_vulnerability(
    vuln_id: str,
    body: UpdateVulnerabilityRequest,
    session: AsyncSession = Depends(db_session),
    svc: SecurityOpsService = Depends(security_ops_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    vuln = await svc.update_vulnerability(
        session, vuln_id,
        status=body.status,
        assignee=body.assignee,
        fix_pr_url=body.fix_pr_url,
        notes_md=body.notes_md,
        request_id=request_id,
    )
    return _vuln_out(vuln)


class RiskAcceptanceRequest(BaseModel):
    rationale: str = Field(min_length=20)
    mitigations: list[str]
    expires_at: datetime | None = None


@router.post("/vulnerabilities/{vuln_id}/risk-accept", status_code=202, tags=["vulnerabilities"])
async def request_risk_acceptance(
    vuln_id: str,
    body: RiskAcceptanceRequest,
    session: AsyncSession = Depends(db_session),
    svc: SecurityOpsService = Depends(security_ops_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    approval_id = await svc.request_risk_acceptance(
        session, vuln_id,
        rationale=body.rationale,
        mitigations=body.mitigations,
        expires_at=body.expires_at,
        request_id=request_id,
    )
    return {"approval_id": approval_id}
