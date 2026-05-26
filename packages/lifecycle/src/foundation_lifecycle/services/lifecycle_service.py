"""Recycle bin + retention enforcement service (lifecycle-v1 §4-5)."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

import ulid
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_lifecycle.domain.models import (
    DestructionCertificate,
    DestructionJob,
    LegalHold,
    RecycleBin,
    ResourceType,
    RetentionPolicyOverride,
    Outbox,
)
from foundation_lifecycle.errors import (
    LEGAL_HOLD_ACTIVE,
    RESOURCE_NOT_IN_BIN,
    RESOURCE_TYPE_NOT_FOUND,
    FoundationError,
)
from foundation_lifecycle.observability import get_logger

log = get_logger(__name__)

_BIN_ID_PREFIX = "bin_"
_CERT_ID_PREFIX = "crt_"
_JOB_ID_PREFIX = "dsj_"


class LifecycleService:
    """Core lifecycle operations: soft-delete, restore, hard-delete, retention."""

    # ------------------------------------------------------------------ Soft Delete → Recycle Bin
    async def soft_delete(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        resource_type_id: str,
        resource_id: str,
        resource_name: str | None,
        deleted_by: str,
        request_id: str,
    ) -> RecycleBin:
        # Verify resource type exists
        rt = await session.get(ResourceType, resource_type_id)
        if rt is None:
            raise FoundationError(RESOURCE_TYPE_NOT_FOUND, extra={"resource_type": resource_type_id})

        # Check for active legal hold
        active_lh = await session.scalar(
            select(LegalHold).where(
                LegalHold.tenant_id == tenant_id,
                LegalHold.resource_type_id == resource_type_id,
                LegalHold.resource_id == resource_id,
                LegalHold.released_at.is_(None),
            ).limit(1)
        )
        if active_lh is not None:
            raise FoundationError(
                LEGAL_HOLD_ACTIVE,
                extra={"resource_id": resource_id, "hold_id": active_lh.id,
                       "reason": active_lh.reason or ""},
            )

        # Determine retention from override or default
        recycle_days = rt.recycle_bin_days
        override = await session.scalar(
            select(RetentionPolicyOverride).where(
                RetentionPolicyOverride.tenant_id == tenant_id,
                RetentionPolicyOverride.resource_type_id == resource_type_id,
            ).limit(1)
        )
        if override is not None and override.recycle_bin_days is not None:
            recycle_days = override.recycle_bin_days

        expires_at = datetime.now(UTC) + timedelta(days=recycle_days)
        entry = RecycleBin(
            id=f"{_BIN_ID_PREFIX}{ulid.new()!s}",
            tenant_id=tenant_id,
            resource_type_id=resource_type_id,
            resource_id=resource_id,
            resource_name=resource_name,
            deleted_by=deleted_by,
            expires_at=expires_at,
        )
        session.add(entry)
        self._emit(session, tenant_id, "foundation.lifecycle.soft_deleted",
                   {"resource_type": resource_type_id, "resource_id": resource_id}, request_id)
        await session.flush()
        return entry

    # ------------------------------------------------------------------ Restore
    async def restore(
        self, session: AsyncSession, *, tenant_id: str, bin_id: str,
        restored_by: str, request_id: str,
    ) -> RecycleBin:
        entry = await session.get(RecycleBin, bin_id)
        if entry is None or entry.tenant_id != tenant_id or entry.restored_at is not None:
            raise FoundationError(RESOURCE_NOT_IN_BIN, extra={"bin_id": bin_id})
        entry.restored_at = datetime.now(UTC)
        entry.restored_by = restored_by
        self._emit(session, tenant_id, "foundation.lifecycle.restored",
                   {"resource_type": entry.resource_type_id, "resource_id": entry.resource_id}, request_id)
        await session.flush()
        return entry

    # ------------------------------------------------------------------ Hard Delete
    async def hard_delete(
        self, session: AsyncSession, *, tenant_id: str, bin_id: str,
        destroyed_by: str, witness_user_id: str | None, request_id: str,
    ) -> None:
        entry = await session.get(RecycleBin, bin_id)
        if entry is None or entry.tenant_id != tenant_id:
            raise FoundationError(RESOURCE_NOT_IN_BIN, extra={"bin_id": bin_id})
        if entry.hard_deleted_at is not None:
            return  # already destroyed

        # Check legal hold
        active_lh = await session.scalar(
            select(LegalHold).where(
                LegalHold.tenant_id == tenant_id,
                LegalHold.resource_type_id == entry.resource_type_id,
                LegalHold.resource_id == entry.resource_id,
                LegalHold.released_at.is_(None),
            ).limit(1)
        )
        if active_lh is not None:
            raise FoundationError(LEGAL_HOLD_ACTIVE, extra={"resource_id": entry.resource_id})

        rt = await session.get(ResourceType, entry.resource_type_id)
        destruction_method = rt.destruction_method if rt else "truncate"

        now = datetime.now(UTC)
        entry.hard_deleted_at = now

        # Generate destruction certificate if required
        if rt and rt.requires_destruction_certificate:
            cert = DestructionCertificate(
                id=f"{_CERT_ID_PREFIX}{ulid.new()!s}",
                tenant_id=tenant_id,
                resource_type_id=entry.resource_type_id,
                resource_ids=[entry.resource_id],
                destruction_method=destruction_method,
                destroyed_by=destroyed_by,
                witness_user_id=witness_user_id,
                destroyed_at=now,
                certificate_hash=hashlib.sha256(
                    f"{entry.resource_type_id}:{entry.resource_id}:{now.isoformat()}".encode()
                ).hexdigest(),
            )
            session.add(cert)

        self._emit(session, tenant_id, "foundation.lifecycle.hard_deleted",
                   {"resource_type": entry.resource_type_id, "resource_id": entry.resource_id,
                    "method": destruction_method}, request_id)
        await session.flush()

    # ------------------------------------------------------------------ Retention Cron
    async def sweep_expired(
        self, session: AsyncSession, *, limit: int = 500,
    ) -> int:
        """Hard-delete all recycle bin entries past their expiry. Returns count."""
        now = datetime.now(UTC)
        stmt = (
            select(RecycleBin)
            .where(
                RecycleBin.expires_at <= now,
                RecycleBin.restored_at.is_(None),
                RecycleBin.hard_deleted_at.is_(None),
            )
            .limit(limit)
        )
        expired = list((await session.scalars(stmt)).all())
        count = 0
        for entry in expired:
            # Skip legal holds
            active_lh = await session.scalar(
                select(LegalHold).where(
                    LegalHold.tenant_id == entry.tenant_id,
                    LegalHold.resource_type_id == entry.resource_type_id,
                    LegalHold.resource_id == entry.resource_id,
                    LegalHold.released_at.is_(None),
                ).limit(1)
            )
            if active_lh is not None:
                continue
            entry.hard_deleted_at = now
            count += 1

        if count > 0:
            job = DestructionJob(
                id=f"{_JOB_ID_PREFIX}{ulid.new()!s}",
                status="COMPLETED",
                started_at=now,
                completed_at=now,
                resources_destroyed=count,
            )
            session.add(job)

        await session.flush()
        return count

    # ------------------------------------------------------------------ Query
    async def list_recycle_bin(
        self, session: AsyncSession, *, tenant_id: str,
        cursor: str | None = None, limit: int = 50,
    ) -> tuple[list[RecycleBin], str | None]:
        stmt = select(RecycleBin).where(
            RecycleBin.tenant_id == tenant_id,
            RecycleBin.restored_at.is_(None),
            RecycleBin.hard_deleted_at.is_(None),
        )
        if cursor:
            stmt = stmt.where(RecycleBin.id > cursor)
        stmt = stmt.order_by(RecycleBin.deleted_at.desc()).limit(limit + 1)
        rows = list((await session.scalars(stmt)).all())
        next_cursor = rows[-1].id if len(rows) > limit else None
        return rows[:limit], next_cursor

    # ------------------------------------------------------------------ Helpers
    def _emit(self, session: AsyncSession, tenant_id: str, event_type: str,
              payload: dict[str, Any], request_id: str) -> None:
        session.add(Outbox(
            tenant_id=tenant_id, event_type=event_type,
            aggregate_id=payload.get("resource_id", ""),
            payload=payload, request_id=request_id,
        ))
