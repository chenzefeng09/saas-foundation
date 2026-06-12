"""Large-attachment entitlement service (two-layer BOOLEAN admission).

Gates whether a user may upload large attachments (which trigger the
large-memory sandbox tier). This is NOT a numeric byte quota — it is a
boolean admission model with two layers:

* Tenant layer — ``tenant_large_attachment_setting``: a tenant-wide switch
  (``large_attachment_enabled``) deciding whether ANY user in the tenant may
  use large attachments at all.
* User layer — ``user_large_attachment_allow``: a per-user allowlist row
  deciding which specific users are permitted, once the tenant switch is on.

Resolution: a user is allowed IFF
``tenant.large_attachment_enabled == true`` AND a user allow-row exists with
``allowed == true``. Tenant off → everyone denied regardless of user rows.

Plain CRUD over the two tables — no outbox events; these are operator-level
config, not domain events (same convention as StorageQuotaService).
"""

from __future__ import annotations

from typing import Any

import ulid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_lifecycle.domain.models import (
    TenantLargeAttachmentSetting,
    UserLargeAttachmentAllow,
)
from foundation_lifecycle.observability import get_logger

log = get_logger(__name__)

_SETTING_ID_PREFIX = "tla_"
_ALLOW_ID_PREFIX = "ula_"


class LargeAttachmentService:
    """Tenant switch + per-user allowlist for large-attachment admission."""

    # ── tenant layer ─────────────────────────────────────────────────────────
    async def get_tenant_setting(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
    ) -> TenantLargeAttachmentSetting | None:
        stmt = select(TenantLargeAttachmentSetting).where(
            TenantLargeAttachmentSetting.tenant_id == tenant_id
        )
        row: TenantLargeAttachmentSetting | None = await session.scalar(stmt)
        return row

    async def upsert_tenant_setting(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        enabled: bool,
        actor: str,
    ) -> TenantLargeAttachmentSetting:
        """Create the tenant row if missing, otherwise flip the switch."""
        existing = await self.get_tenant_setting(session, tenant_id=tenant_id)
        if existing is None:
            entry = TenantLargeAttachmentSetting(
                id=f"{_SETTING_ID_PREFIX}{ulid.new()!s}",
                tenant_id=tenant_id,
                large_attachment_enabled=enabled,
                updated_by=actor,
            )
            session.add(entry)
            await session.flush()
            log.info(
                "large_attachment.tenant_setting.created",
                tenant_id=tenant_id,
                enabled=enabled,
                actor=actor,
            )
            return entry
        existing.large_attachment_enabled = enabled
        existing.updated_by = actor
        await session.flush()
        log.info(
            "large_attachment.tenant_setting.updated",
            tenant_id=tenant_id,
            enabled=enabled,
            actor=actor,
        )
        return existing

    # ── user layer ───────────────────────────────────────────────────────────
    async def list_user_allows(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
    ) -> list[UserLargeAttachmentAllow]:
        stmt = select(UserLargeAttachmentAllow).where(
            UserLargeAttachmentAllow.tenant_id == tenant_id
        )
        rows = list((await session.scalars(stmt)).all())
        return rows

    async def get_user_allow(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        user_id: str,
    ) -> UserLargeAttachmentAllow | None:
        stmt = select(UserLargeAttachmentAllow).where(
            UserLargeAttachmentAllow.tenant_id == tenant_id,
            UserLargeAttachmentAllow.user_id == user_id,
        )
        row: UserLargeAttachmentAllow | None = await session.scalar(stmt)
        return row

    async def upsert_user_allow(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        user_id: str,
        allowed: bool,
        actor: str,
    ) -> UserLargeAttachmentAllow:
        """Create an allow row if missing, otherwise patch ``allowed``."""
        existing = await self.get_user_allow(
            session, tenant_id=tenant_id, user_id=user_id
        )
        if existing is None:
            entry = UserLargeAttachmentAllow(
                id=f"{_ALLOW_ID_PREFIX}{ulid.new()!s}",
                tenant_id=tenant_id,
                user_id=user_id,
                allowed=allowed,
                updated_by=actor,
            )
            session.add(entry)
            await session.flush()
            log.info(
                "large_attachment.user_allow.created",
                tenant_id=tenant_id,
                user_id=user_id,
                allowed=allowed,
                actor=actor,
            )
            return entry
        existing.allowed = allowed
        existing.updated_by = actor
        await session.flush()
        log.info(
            "large_attachment.user_allow.updated",
            tenant_id=tenant_id,
            user_id=user_id,
            allowed=allowed,
            actor=actor,
        )
        return existing

    async def delete_user_allow(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        user_id: str,
    ) -> bool:
        """Remove a user allow row. Returns True if a row was deleted."""
        existing = await self.get_user_allow(
            session, tenant_id=tenant_id, user_id=user_id
        )
        if existing is None:
            return False
        await session.delete(existing)
        await session.flush()
        log.info(
            "large_attachment.user_allow.deleted",
            tenant_id=tenant_id,
            user_id=user_id,
        )
        return True

    # ── resolution ───────────────────────────────────────────────────────────
    async def resolve(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        user_id: str,
    ) -> dict[str, bool]:
        """Resolve large-attachment admission for ``user_id``.

        allowed IFF tenant switch on AND a user allow-row with allowed == true.
        """
        setting = await self.get_tenant_setting(session, tenant_id=tenant_id)
        tenant_enabled = bool(
            setting is not None and setting.large_attachment_enabled
        )

        allow = await self.get_user_allow(
            session, tenant_id=tenant_id, user_id=user_id
        )
        user_allowed = bool(allow is not None and allow.allowed)

        return {
            "allowed": tenant_enabled and user_allowed,
            "tenant_enabled": tenant_enabled,
            "user_allowed": user_allowed,
        }

    # ── serialization ────────────────────────────────────────────────────────
    @staticmethod
    def serialize_setting(row: TenantLargeAttachmentSetting) -> dict[str, Any]:
        return {
            "id": row.id,
            "tenant_id": row.tenant_id,
            "large_attachment_enabled": row.large_attachment_enabled,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
            "updated_by": row.updated_by,
        }

    @staticmethod
    def serialize_allow(row: UserLargeAttachmentAllow) -> dict[str, Any]:
        return {
            "id": row.id,
            "tenant_id": row.tenant_id,
            "user_id": row.user_id,
            "allowed": row.allowed,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
            "updated_by": row.updated_by,
        }
