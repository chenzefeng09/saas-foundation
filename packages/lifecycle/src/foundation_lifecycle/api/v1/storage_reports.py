"""Storage admin reports endpoints (Phase 7 — storage-v1 §11.3).

Cross-tenant read-only API for ``lifecycle.orphan_reconcile_report``.
All endpoints sit behind ``require_scope("storage.admin")`` and run over
``admin_db_session`` (app_admin engine, actor=ADMIN).  No tenant context
is required because the table itself is cross-tenant.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_lifecycle.api.dependencies import (
    admin_db_session,
    require_scope,
    storage_report_service,
)
from foundation_lifecycle.services.storage_report_service import (
    StorageReportService,
)

router = APIRouter()


@router.get(
    "/orphan-reports",
    operation_id="listOrphanReports",
    dependencies=[Depends(require_scope("storage.admin"))],
)
async def list_orphan_reports(
    limit: int = Query(default=20, ge=1, le=100),
    before_id: str | None = Query(default=None),
    session: AsyncSession = Depends(admin_db_session),
    svc: StorageReportService = Depends(storage_report_service),
) -> dict[str, Any]:
    rows, next_cursor = await svc.list_reports(
        session, limit=limit, before_id=before_id
    )
    return {
        "items": [svc.serialize(r) for r in rows],
        "next_cursor": next_cursor,
    }


@router.get(
    "/orphan-reports/{report_id}",
    operation_id="getOrphanReport",
    dependencies=[Depends(require_scope("storage.admin"))],
)
async def get_orphan_report(
    report_id: str,
    session: AsyncSession = Depends(admin_db_session),
    svc: StorageReportService = Depends(storage_report_service),
) -> dict[str, Any]:
    row = await svc.get_report(session, report_id=report_id)
    if row is None:
        raise HTTPException(status_code=404, detail="report not found")
    return svc.serialize(row)
