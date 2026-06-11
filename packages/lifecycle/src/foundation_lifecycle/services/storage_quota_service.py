"""Storage quota CRUD service (storage-v1 §5.4).

Plain CRUD over ``lifecycle.tenant_storage_quota``. No outbox events —
quota adjustments are operator-level config, not domain events.
"""

from __future__ import annotations

from typing import Any

import ulid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_lifecycle.domain.models import TenantStorageQuota
from foundation_lifecycle.observability import get_logger

log = get_logger(__name__)

_QUOTA_ID_PREFIX = "sqt_"


class StorageQuotaService:
    """List, fetch, and upsert per-(tenant, bucket_purpose) storage quotas."""

    async def list_quotas(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
    ) -> list[TenantStorageQuota]:
        stmt = select(TenantStorageQuota).where(
            TenantStorageQuota.tenant_id == tenant_id
        )
        rows = list((await session.scalars(stmt)).all())
        return rows

    async def get_quota(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        bucket_purpose: str,
    ) -> TenantStorageQuota | None:
        stmt = select(TenantStorageQuota).where(
            TenantStorageQuota.tenant_id == tenant_id,
            TenantStorageQuota.bucket_purpose == bucket_purpose,
        )
        row: TenantStorageQuota | None = await session.scalar(stmt)
        return row

    async def upsert_quota(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        bucket_purpose: str,
        limit_bytes: int | None = None,
        soft_warn_pct: int | None = None,
        actor: str,
    ) -> TenantStorageQuota:
        """Create a quota row if missing, otherwise patch supplied fields."""
        existing = await self.get_quota(
            session, tenant_id=tenant_id, bucket_purpose=bucket_purpose
        )
        if existing is None:
            entry = TenantStorageQuota(
                id=f"{_QUOTA_ID_PREFIX}{ulid.new()!s}",
                tenant_id=tenant_id,
                bucket_purpose=bucket_purpose,
                limit_bytes=limit_bytes
                if limit_bytes is not None
                else 10_737_418_240,
                used_bytes=0,
                soft_warn_pct=soft_warn_pct if soft_warn_pct is not None else 80,
            )
            session.add(entry)
            await session.flush()
            log.info(
                "storage.quota.created",
                tenant_id=tenant_id,
                bucket_purpose=bucket_purpose,
                actor=actor,
            )
            return entry
        # Patch in place — used_bytes stays untouched, that's the reconcile
        # job's responsibility.
        if limit_bytes is not None:
            existing.limit_bytes = limit_bytes
        if soft_warn_pct is not None:
            existing.soft_warn_pct = soft_warn_pct
        await session.flush()
        log.info(
            "storage.quota.updated",
            tenant_id=tenant_id,
            bucket_purpose=bucket_purpose,
            actor=actor,
        )
        return existing

    @staticmethod
    def serialize(row: TenantStorageQuota) -> dict[str, Any]:
        """Render a quota row as a plain dict (DTO style — no Response Model)."""
        return {
            "id": row.id,
            "tenant_id": row.tenant_id,
            "bucket_purpose": row.bucket_purpose,
            "limit_bytes": row.limit_bytes,
            "used_bytes": row.used_bytes,
            "soft_warn_pct": row.soft_warn_pct,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        }
