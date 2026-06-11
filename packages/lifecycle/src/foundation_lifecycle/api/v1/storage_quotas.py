"""Storage quota CRUD endpoints (storage-v1 §5.4)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_lifecycle.api.dependencies import (
    current_context,
    db_session,
    require_scope,
    storage_quota_service,
)
from foundation_lifecycle.domain.base import FoundationContext
from foundation_lifecycle.services.storage_quota_service import StorageQuotaService

router = APIRouter()


class PatchQuotaRequest(BaseModel):
    limit_bytes: int | None = Field(default=None, ge=0)
    soft_warn_pct: int | None = Field(default=None, ge=0, le=100)


@router.get("/storage-quotas", operation_id="listStorageQuotas")
async def list_quotas(
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: StorageQuotaService = Depends(storage_quota_service),
) -> dict[str, Any]:
    rows = await svc.list_quotas(session, tenant_id=ctx.tenant_id)
    return {"items": [svc.serialize(r) for r in rows]}


@router.get(
    "/storage-quotas/{bucket_purpose}", operation_id="getStorageQuota"
)
async def get_quota(
    bucket_purpose: str,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: StorageQuotaService = Depends(storage_quota_service),
) -> dict[str, Any]:
    row = await svc.get_quota(
        session, tenant_id=ctx.tenant_id, bucket_purpose=bucket_purpose
    )
    if row is None:
        raise HTTPException(status_code=404, detail="quota not found")
    return svc.serialize(row)


@router.patch(
    "/storage-quotas/{bucket_purpose}",
    operation_id="upsertStorageQuota",
    dependencies=[Depends(require_scope("storage.quota.write"))],
)
async def upsert_quota(
    bucket_purpose: str,
    body: PatchQuotaRequest,
    ctx: FoundationContext = Depends(current_context),
    session: AsyncSession = Depends(db_session),
    svc: StorageQuotaService = Depends(storage_quota_service),
) -> dict[str, Any]:
    row = await svc.upsert_quota(
        session,
        tenant_id=ctx.tenant_id,
        bucket_purpose=bucket_purpose,
        limit_bytes=body.limit_bytes,
        soft_warn_pct=body.soft_warn_pct,
        actor=ctx.user_id or "",
    )
    return svc.serialize(row)
