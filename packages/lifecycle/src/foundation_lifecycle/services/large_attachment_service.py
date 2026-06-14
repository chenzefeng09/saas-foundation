"""Large-attachment entitlement service (two-layer BOOLEAN admission).

Gates whether a user may upload large attachments (which trigger the
large-memory sandbox tier). This is NOT a numeric byte quota — it is a
boolean admission model with two layers:

* Tenant layer — ``tenant_large_attachment_setting``: a tenant-wide switch
  (``large_attachment_enabled``) deciding whether ANY user in the tenant may
  use large attachments at all.
* User layer — ``user_large_attachment_allow``: a per-user allowlist row
  deciding which specific users are permitted, once the tenant switch is on.

Resolution (generalized — design §4): a user is admitted IFF the tenant
switch is on AND at least one allow-row grants them via the subject hierarchy,
with a USER-level explicit deny acting as a veto:

* Tenant off → everyone denied.
* USER row ``allowed == false`` → denied (veto; overrides any group allow).
* USER row ``allowed == true`` → allowed.
* else any TEAM the user belongs to with ``allowed == true`` → allowed.
* else any ORG_UNIT the user belongs to (incl. ancestor inheritance) with
  ``allowed == true`` → allowed.
* else → denied (not listed).

Storage is unified on the NEW ``large_attachment_subject_allow`` table
(subject_type ∈ {USER, TEAM, ORG_UNIT}). The legacy
``user_large_attachment_allow`` table is frozen — the back-compat ``user_*``
methods now read/write the subject table as ``subject_type='USER'`` so the
legacy routes keep returning the same JSON shape.

Plain CRUD — no outbox events; these are operator-level config, not domain
events (same convention as StorageQuotaService).
"""

from __future__ import annotations

from typing import Any

import ulid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_lifecycle.adapters.org_client import OrgClient
from foundation_lifecycle.domain.models import (
    SubjectLargeAttachmentAllow,
    TenantLargeAttachmentSetting,
    UserLargeAttachmentAllow,
)
from foundation_lifecycle.observability import get_logger

log = get_logger(__name__)

_SETTING_ID_PREFIX = "tla_"
_ALLOW_ID_PREFIX = "ula_"
_SUBJECT_ID_PREFIX = "las_"

SUBJECT_TYPES = frozenset({"USER", "TEAM", "ORG_UNIT"})


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

    # ── subject layer (generalized USER / TEAM / ORG_UNIT) ───────────────────
    async def list_subject_allows(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
    ) -> list[SubjectLargeAttachmentAllow]:
        stmt = select(SubjectLargeAttachmentAllow).where(
            SubjectLargeAttachmentAllow.tenant_id == tenant_id
        )
        rows = list((await session.scalars(stmt)).all())
        return rows

    async def get_subject_allow(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        subject_type: str,
        subject_id: str,
    ) -> SubjectLargeAttachmentAllow | None:
        stmt = select(SubjectLargeAttachmentAllow).where(
            SubjectLargeAttachmentAllow.tenant_id == tenant_id,
            SubjectLargeAttachmentAllow.subject_type == subject_type,
            SubjectLargeAttachmentAllow.subject_id == subject_id,
        )
        row: SubjectLargeAttachmentAllow | None = await session.scalar(stmt)
        return row

    async def upsert_subject_allow(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        subject_type: str,
        subject_id: str,
        allowed: bool,
        actor: str,
    ) -> SubjectLargeAttachmentAllow:
        """Create a subject allow row if missing, otherwise patch ``allowed``.

        Raises ``ValueError`` if ``subject_type`` is not USER / TEAM / ORG_UNIT;
        the router translates it to a 400 (there is no domain-error layer in
        this service — the existing routes use plain ``HTTPException``).
        """
        if subject_type not in SUBJECT_TYPES:
            raise ValueError(
                f"invalid subject_type: {subject_type!r} "
                f"(expected one of {sorted(SUBJECT_TYPES)})"
            )
        existing = await self.get_subject_allow(
            session,
            tenant_id=tenant_id,
            subject_type=subject_type,
            subject_id=subject_id,
        )
        if existing is None:
            entry = SubjectLargeAttachmentAllow(
                id=f"{_SUBJECT_ID_PREFIX}{ulid.new()!s}",
                tenant_id=tenant_id,
                subject_type=subject_type,
                subject_id=subject_id,
                allowed=allowed,
                updated_by=actor,
            )
            session.add(entry)
            await session.flush()
            log.info(
                "large_attachment.subject_allow.created",
                tenant_id=tenant_id,
                subject_type=subject_type,
                subject_id=subject_id,
                allowed=allowed,
                actor=actor,
            )
            return entry
        existing.allowed = allowed
        existing.updated_by = actor
        await session.flush()
        log.info(
            "large_attachment.subject_allow.updated",
            tenant_id=tenant_id,
            subject_type=subject_type,
            subject_id=subject_id,
            allowed=allowed,
            actor=actor,
        )
        return existing

    async def delete_subject_allow(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        subject_type: str,
        subject_id: str,
    ) -> bool:
        """Remove a subject allow row. Returns True if a row was deleted."""
        existing = await self.get_subject_allow(
            session,
            tenant_id=tenant_id,
            subject_type=subject_type,
            subject_id=subject_id,
        )
        if existing is None:
            return False
        await session.delete(existing)
        await session.flush()
        log.info(
            "large_attachment.subject_allow.deleted",
            tenant_id=tenant_id,
            subject_type=subject_type,
            subject_id=subject_id,
        )
        return True

    # ── user layer (back-compat — delegates to subject table as USER) ────────
    # The legacy ``user_large_attachment_allow`` table is frozen; these methods
    # operate on the unified subject table with ``subject_type='USER'`` so the
    # old per-user routes keep returning the same JSON (via ``serialize_allow``).
    async def list_user_allows(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
    ) -> list[SubjectLargeAttachmentAllow]:
        stmt = select(SubjectLargeAttachmentAllow).where(
            SubjectLargeAttachmentAllow.tenant_id == tenant_id,
            SubjectLargeAttachmentAllow.subject_type == "USER",
        )
        rows = list((await session.scalars(stmt)).all())
        return rows

    async def get_user_allow(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        user_id: str,
    ) -> SubjectLargeAttachmentAllow | None:
        return await self.get_subject_allow(
            session,
            tenant_id=tenant_id,
            subject_type="USER",
            subject_id=user_id,
        )

    async def upsert_user_allow(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        user_id: str,
        allowed: bool,
        actor: str,
    ) -> SubjectLargeAttachmentAllow:
        """Create/patch the USER subject row (back-compat user shape)."""
        return await self.upsert_subject_allow(
            session,
            tenant_id=tenant_id,
            subject_type="USER",
            subject_id=user_id,
            allowed=allowed,
            actor=actor,
        )

    async def delete_user_allow(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        user_id: str,
    ) -> bool:
        """Remove the USER subject row. Returns True if a row was deleted."""
        return await self.delete_subject_allow(
            session,
            tenant_id=tenant_id,
            subject_type="USER",
            subject_id=user_id,
        )

    # ── resolution (union over USER / TEAM / ORG_UNIT) ───────────────────────
    async def resolve(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        user_id: str,
        org_client: OrgClient,
    ) -> dict[str, Any]:
        """Resolve large-attachment admission for ``user_id`` (design §4).

        Decision order:
          1. tenant switch off → denied (``tenant_disabled``).
          2. USER row ``allowed=false`` → denied veto (``user_denied``).
          3. USER row ``allowed=true`` → allowed (``user``).
          4. any TEAM the user is in with ``allowed=true`` → allowed (``team``).
          5. any ORG_UNIT the user is in, incl. ancestors, with ``allowed=true``
             → allowed (``org_unit``).
          6. else → denied (``not_listed``).

        ``org_client`` is injected so the path is testable without network; the
        router builds one from ``settings.org_url``. Org enrichment is
        best-effort — if org is unreachable the team/ou lookups degrade to
        empty and the user ends up ``not_listed`` (fail-CLOSED on admission).

        Return dict keeps the legacy keys (``allowed``, ``tenant_enabled``,
        ``user_allowed``) that BFF/consumers may read, and adds ``reason`` and
        an optional ``via`` (the team/org-unit id that granted access).
        """
        setting = await self.get_tenant_setting(session, tenant_id=tenant_id)
        tenant_enabled = bool(
            setting is not None and setting.large_attachment_enabled
        )
        if not tenant_enabled:
            return {
                "allowed": False,
                "tenant_enabled": False,
                "user_allowed": False,
                "reason": "tenant_disabled",
            }

        # 2/3 — USER row is authoritative: explicit deny vetoes any group allow.
        user_row = await self.get_subject_allow(
            session, tenant_id=tenant_id, subject_type="USER", subject_id=user_id
        )
        if user_row is not None and user_row.allowed is False:
            return {
                "allowed": False,
                "tenant_enabled": True,
                "user_allowed": False,
                "reason": "user_denied",
            }
        if user_row is not None and user_row.allowed is True:
            return {
                "allowed": True,
                "tenant_enabled": True,
                "user_allowed": True,
                "reason": "user",
            }

        # 4 — TEAM union.
        teams = await org_client.teams_of(tenant_id=tenant_id, user_id=user_id)
        for team_id in teams:
            row = await self.get_subject_allow(
                session,
                tenant_id=tenant_id,
                subject_type="TEAM",
                subject_id=team_id,
            )
            if row is not None and row.allowed is True:
                return {
                    "allowed": True,
                    "tenant_enabled": True,
                    "user_allowed": False,
                    "reason": "team",
                    "via": team_id,
                }

        # 5 — ORG_UNIT union (incl. ancestor inheritance).
        org_units = await org_client.org_units_of(
            tenant_id=tenant_id, user_id=user_id
        )
        for ou_id in org_units:
            row = await self.get_subject_allow(
                session,
                tenant_id=tenant_id,
                subject_type="ORG_UNIT",
                subject_id=ou_id,
            )
            if row is not None and row.allowed is True:
                return {
                    "allowed": True,
                    "tenant_enabled": True,
                    "user_allowed": False,
                    "reason": "org_unit",
                    "via": ou_id,
                }

        # 6 — nothing granted access.
        return {
            "allowed": False,
            "tenant_enabled": True,
            "user_allowed": False,
            "reason": "not_listed",
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
    def serialize_allow(
        row: SubjectLargeAttachmentAllow | UserLargeAttachmentAllow,
    ) -> dict[str, Any]:
        """Legacy per-user shape (``user_id`` key).

        Accepts a unified ``SubjectLargeAttachmentAllow`` (the back-compat
        ``user_*`` methods return these as ``subject_type='USER'``) and projects
        ``subject_id`` to ``user_id``; also still accepts a legacy
        ``UserLargeAttachmentAllow`` for safety.
        """
        user_id = getattr(row, "subject_id", None) or getattr(row, "user_id", None)
        return {
            "id": row.id,
            "tenant_id": row.tenant_id,
            "user_id": user_id,
            "allowed": row.allowed,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
            "updated_by": row.updated_by,
        }

    @staticmethod
    def serialize_subject_allow(
        row: SubjectLargeAttachmentAllow,
    ) -> dict[str, Any]:
        """Generalized subject shape (design's SubjectAllow)."""
        return {
            "id": row.id,
            "tenant_id": row.tenant_id,
            "subject_type": row.subject_type,
            "subject_id": row.subject_id,
            "allowed": row.allowed,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
            "updated_by": row.updated_by,
        }
