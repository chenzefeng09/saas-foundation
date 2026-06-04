"""Compliance API endpoints — ROPA, DPIA, DSAR, reports."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from foundation_compliance.api.dependencies import (
    compliance_service, current_context, current_request_id, db_session,
)
from foundation_compliance.domain.base import FoundationContext
from foundation_compliance.services.compliance_service import ComplianceService

router = APIRouter()


# ---------- ROPA ----------

class RecordProcessingRequest(BaseModel):
    service: str
    data_category: str
    purpose: str
    legal_basis: str
    data_subjects: list[str]
    recipients: list[str]
    retention_days: int = 365
    cross_border: bool = False
    destination_countries: list[str] = []


@router.post("/ropa", status_code=201, tags=["compliance"])
async def record_processing(
    body: RecordProcessingRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: ComplianceService = Depends(compliance_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    record = await svc.record_processing(
        session, tenant_id=ctx.tenant_id,
        service=body.service, data_category=body.data_category,
        purpose=body.purpose, legal_basis=body.legal_basis,
        data_subjects=body.data_subjects, recipients=body.recipients,
        retention_days=body.retention_days, cross_border=body.cross_border,
        destination_countries=body.destination_countries,
        request_id=request_id,
    )
    return {"id": record.id, "service": record.service, "purpose": record.purpose, "legal_basis": record.legal_basis}


@router.get("/ropa", tags=["compliance"])
async def list_ropa(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: ComplianceService = Depends(compliance_service),
) -> dict[str, Any]:
    rows = await svc.list_ropa(session, tenant_id=ctx.tenant_id)
    return {"items": [{"id": r.id, "service": r.service, "purpose": r.purpose, "legal_basis": r.legal_basis} for r in rows]}


# ---------- DPIA ----------

class AssessDPIARequest(BaseModel):
    project_name: str
    description: str
    data_categories: list[str]
    risks: list[dict[str, str]]
    mitigations: list[dict[str, str]]


class CompleteDPIARequest(BaseModel):
    conclusion: str
    residual_risks: str


@router.post("/dpia", status_code=201, tags=["compliance"])
async def assess_dpia(
    body: AssessDPIARequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: ComplianceService = Depends(compliance_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    dpia = await svc.assess_dpia(
        session, tenant_id=ctx.tenant_id,
        project_name=body.project_name, description=body.description,
        data_categories=body.data_categories, risks=body.risks,
        mitigations=body.mitigations,
        assessed_by=ctx.user_id or "",
        request_id=request_id,
    )
    return {"id": dpia.id, "project_name": dpia.project_name, "conclusion": dpia.conclusion}


@router.post("/dpia/{dpia_id}/complete", tags=["compliance"])
async def complete_dpia(
    dpia_id: str,
    body: CompleteDPIARequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: ComplianceService = Depends(compliance_service),
) -> dict[str, Any]:
    dpia = await svc.complete_dpia(
        session, tenant_id=ctx.tenant_id,
        dpia_id=dpia_id, conclusion=body.conclusion,
        residual_risks=body.residual_risks,
        approved_by=ctx.user_id or "",
    )
    return {"id": dpia.id, "conclusion": dpia.conclusion, "residual_risks": dpia.residual_risks}


# ---------- DSAR ----------

class RequestDSARRequest(BaseModel):
    user_id: str
    request_type: str
    details: str


@router.post("/dsar", status_code=201, tags=["compliance"])
async def request_dsar(
    body: RequestDSARRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: ComplianceService = Depends(compliance_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    dsar = await svc.request_dsar(
        session, tenant_id=ctx.tenant_id,
        user_id=body.user_id, request_type=body.request_type,
        details=body.details, request_id=request_id,
    )
    return {"id": dsar.id, "user_id": dsar.user_id, "request_type": dsar.request_type, "status": dsar.status}


@router.get("/dsar/{dsar_id}", tags=["compliance"])
async def get_dsar_status(
    dsar_id: str,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    from foundation_compliance.domain.models import DSARRequest
    dsar = await session.get(DSARRequest, dsar_id)
    if dsar is None or dsar.tenant_id != ctx.tenant_id:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="DSAR not found")
    return {"id": dsar.id, "user_id": dsar.user_id, "request_type": dsar.request_type, "status": dsar.status}


# ---------- Reports ----------

class GenerateReportRequest(BaseModel):
    report_type: str
    compliance_modes: list[str]


@router.post("/reports", status_code=201, tags=["compliance"])
async def generate_report(
    body: GenerateReportRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: ComplianceService = Depends(compliance_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    report = await svc.generate_report(
        session, tenant_id=ctx.tenant_id,
        report_type=body.report_type, compliance_modes=body.compliance_modes,
        generated_by=ctx.user_id or "",
        request_id=request_id,
    )
    return {"id": report.id, "report_type": report.report_type, "compliance_modes": report.compliance_modes, "content": report.content_json}


@router.get("/reports", tags=["compliance"])
async def list_reports(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    from sqlalchemy import select
    from foundation_compliance.domain.models import ComplianceReport
    rows = list((await session.scalars(
        select(ComplianceReport).where(ComplianceReport.tenant_id == ctx.tenant_id).order_by(ComplianceReport.generated_at.desc())
    )).all())
    return {"items": [{"id": r.id, "report_type": r.report_type, "compliance_modes": r.compliance_modes} for r in rows]}
