"""CI scan run endpoints — POST /scans/runs, GET /scans/runs."""

from __future__ import annotations

from datetime import datetime
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


class ReportScanRunRequest(BaseModel):
    id: str | None = None
    type: str  # SAST / SCA / DAST / IMAGE_VULN / IAC / SECRET / LICENSE
    tool: str
    target: str
    commit_sha: str | None = None
    pipeline_id: str | None = None
    started_at: datetime
    finished_at: datetime | None = None
    status: str  # RUNNING / PASSED / FAILED / ERRORED
    sarif_s3_key: str | None = None
    findings_count: dict[str, int] = Field(default_factory=dict)


def _scan_out(scan: Any) -> dict[str, Any]:
    return {
        "id": scan.id,
        "type": scan.type,
        "tool": scan.tool,
        "target": scan.target,
        "commit_sha": scan.commit_sha,
        "pipeline_id": scan.pipeline_id,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "status": scan.status,
        "sarif_s3_key": scan.sarif_s3_key,
        "findings_count": scan.findings_count,
    }


@router.get("/scans/runs", tags=["scans"])
async def list_scan_runs(
    filter_type: str | None = Query(None, alias="filter.type"),
    filter_status: str | None = Query(None, alias="filter.status"),
    session: AsyncSession = Depends(db_session),
    svc: SecurityOpsService = Depends(security_ops_service),
) -> dict[str, Any]:
    runs = await svc.list_scan_runs(
        session,
        type_filter=filter_type,
        status_filter=filter_status,
    )
    return {"items": [_scan_out(r) for r in runs], "next_cursor": None}


@router.delete(
    "/scans/runs/{scan_id}",
    status_code=204,
    response_class=Response,
    tags=["scans"],
)
async def delete_scan_run(
    scan_id: str,
    session: AsyncSession = Depends(db_session),
    svc: SecurityOpsService = Depends(security_ops_service),
    request_id: str = Depends(current_request_id),
) -> Response:
    # storage-v1 §6.2: hand off retention + S3 GC to lifecycle.
    await svc.delete_scan_run(session, scan_id, request_id=request_id)
    return Response(status_code=204)


@router.post("/scans/runs", status_code=201, tags=["scans"])
async def report_scan_run(
    body: ReportScanRunRequest,
    session: AsyncSession = Depends(db_session),
    svc: SecurityOpsService = Depends(security_ops_service),
    request_id: str = Depends(current_request_id),
) -> dict[str, Any]:
    scan, new_vulns = await svc.report_scan_run(
        session,
        type=body.type,
        tool=body.tool,
        target=body.target,
        commit_sha=body.commit_sha,
        pipeline_id=body.pipeline_id,
        started_at=body.started_at,
        finished_at=body.finished_at,
        status=body.status,
        sarif_s3_key=body.sarif_s3_key,
        findings_count=body.findings_count,
        request_id=request_id,
    )
    return {
        "scan_id": scan.id,
        "vulnerabilities_opened": len(new_vulns),
    }
