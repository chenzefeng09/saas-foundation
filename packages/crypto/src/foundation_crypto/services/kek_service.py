"""KEK lifecycle service (crypto-v1 §4, §7.3-7.4).

State machine:
    (create) → ACTIVE
              ├─ rotate ─────────────────────────────────────────→ ACTIVE (version++)
              ├─ mark_for_destruction ────────────────────────────→ MARKED_FOR_DESTRUCTION
              │     └─ abort_destruction ──→ ACTIVE
              │     └─ cooling-off expired → destroy ─────────────→ DESTROYED
              ├─ suspend ──────────────────────────────────────────→ SUSPENDED
              └─ resume ───────────────────────────────────────────→ ACTIVE

Security rules:
  - destroy requires: status == MARKED_FOR_DESTRUCTION + four-eyes (approver != actor)
  - abort_destruction requires: status == MARKED_FOR_DESTRUCTION + reason
  - A DESTROYED KEK can never be recovered → all ciphertext encrypted with it is lost.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import ulid
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_crypto.adapters.key_provider import KeyProvider
from foundation_crypto.domain.models import Algorithm, KEK, KEKHistory, Outbox
from foundation_crypto.errors import (
    ALGORITHM_NOT_FOUND,
    KEK_ALREADY_MARKED,
    KEK_DESTROYED,
    KEK_LABEL_CONFLICT,
    KEK_NOT_ACTIVE,
    KEK_NOT_DESTRUCTIBLE,
    KEK_NOT_FOUND,
    FOUR_EYES_REQUIRED,
    FoundationError,
)
from foundation_crypto.observability import get_logger
from foundation_crypto.schemas.kek import (
    CreateKEKRequest,
    DestroyKEKRequest,
    KEKHistoryEntry,
    KEKRead,
    MarkForDestructionRequest,
    RotateKEKRequest,
)

log = get_logger(__name__)

KEK_ID_PREFIX = "kek_"


class KekService:
    """Manage KEK lifecycle: create, rotate, mark-for-destruction, destroy, abort."""

    def __init__(self, key_provider: KeyProvider) -> None:
        self._kp = key_provider

    # ------------------------------------------------------------------ Query

    async def list_keks(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        cursor: str | None = None,
        limit: int = 50,
        purpose: str | None = None,
        status: str | None = None,
    ) -> tuple[list[KEKRead], str | None]:
        stmt = select(KEK).where(KEK.tenant_id == tenant_id)
        if purpose:
            stmt = stmt.where(KEK.purpose == purpose)
        if status:
            stmt = stmt.where(KEK.status == status)
        if cursor:
            stmt = stmt.where(KEK.id > cursor)
        stmt = stmt.order_by(KEK.id).limit(limit + 1)
        rows = list((await session.execute(stmt)).scalars().all())
        has_more = len(rows) > limit
        items = rows[:limit]
        next_cursor = items[-1].id if has_more else None
        return ([KEKRead.model_validate(r) for r in items], next_cursor)

    async def get_kek(self, session: AsyncSession, *, tenant_id: str, kek_id: str) -> KEKRead:
        kek = await self._get(session, tenant_id, kek_id)
        return KEKRead.model_validate(kek)

    async def get_kek_history(
        self, session: AsyncSession, *, tenant_id: str, kek_id: str,
        limit: int = 50,
    ) -> list[KEKHistoryEntry]:
        # Verify kek exists
        await self._get(session, tenant_id, kek_id)
        stmt = (
            select(KEKHistory)
            .where(KEKHistory.tenant_id == tenant_id, KEKHistory.kek_id == kek_id)
            .order_by(KEKHistory.changed_at.desc())
            .limit(limit)
        )
        rows = (await session.execute(stmt)).scalars().all()
        return [KEKHistoryEntry.model_validate(r) for r in rows]

    # ------------------------------------------------------------------ Create

    async def create(
        self, session: AsyncSession, *, tenant_id: str, request: CreateKEKRequest,
        actor_user_id: str, request_id: str,
    ) -> KEKRead:
        # 1. Validate algorithm exists
        algo = await session.get(Algorithm, request.algorithm_id)
        if algo is None:
            raise FoundationError(ALGORITHM_NOT_FOUND, detail=f"Algorithm {request.algorithm_id} not registered")

        # 2. Check label uniqueness within tenant
        existing = (await session.execute(
            select(KEK).where(KEK.tenant_id == tenant_id, KEK.label == request.label)
        )).scalar_one_or_none()
        if existing is not None:
            raise FoundationError(KEK_LABEL_CONFLICT, detail=f"KEK label '{request.label}' already exists")

        # 3. Build KEK ID and vault path
        kek_id = f"{KEK_ID_PREFIX}{ulid.new()!s}"
        vault_path = f"transit/keys/{request.label}_{kek_id}"

        # 4. Create key in Vault/HSM
        await self._kp.create_key(vault_path=vault_path, algorithm=request.algorithm_id)

        # 5. Persist KEK metadata
        now = datetime.now(UTC)
        kek = KEK(
            id=kek_id,
            tenant_id=tenant_id,
            label=request.label,
            purpose=request.purpose,
            algorithm_id=request.algorithm_id,
            vault_path=vault_path,
            current_version=1,
            min_decryption_version=1,
            auto_rotate_days=request.auto_rotate_days,
            last_rotated_at=now,
            status="ACTIVE",
            created_at=now,
            updated_at=now,
            created_by=actor_user_id,
        )
        session.add(kek)

        # 6. Record history
        self._add_history(
            session, tenant_id, kek_id, transition="CREATED",
            from_status=None, to_status="ACTIVE",
            changed_by=actor_user_id, request_id=request_id,
        )

        # 7. Emit event
        self._emit_event(
            session, tenant_id, "foundation.crypto.kek.created",
            {"kek_id": kek_id, "label": request.label, "purpose": request.purpose},
            request_id=request_id,
        )

        await session.flush()
        return KEKRead.model_validate(kek)

    # ------------------------------------------------------------------ Rotate

    async def rotate(
        self, session: AsyncSession, *, tenant_id: str, kek_id: str,
        request: RotateKEKRequest | None, actor_user_id: str, request_id: str,
    ) -> KEKRead:
        kek = await self._get(session, tenant_id, kek_id)
        if kek.status != "ACTIVE":
            raise FoundationError(KEK_NOT_ACTIVE, detail=f"KEK {kek_id} is {kek.status}, not ACTIVE")

        new_version = await self._kp.rotate_key(vault_path=kek.vault_path)
        old_version = kek.current_version
        kek.current_version = new_version
        kek.last_rotated_at = datetime.now(UTC)
        kek.updated_at = datetime.now(UTC)

        self._add_history(
            session, tenant_id, kek_id, transition="ROTATED",
            from_status=kek.status, to_status=kek.status,
            changed_by=actor_user_id, reason=request.reason if request else None,
            request_id=request_id,
        )
        self._emit_event(
            session, tenant_id, "foundation.crypto.kek.rotated",
            {"kek_id": kek_id, "old_version": old_version, "new_version": new_version},
            request_id=request_id,
        )
        await session.flush()
        return KEKRead.model_validate(kek)

    # ------------------------------------------------------------------ Mark for Destruction

    async def mark_for_destruction(
        self, session: AsyncSession, *, tenant_id: str, kek_id: str,
        request: MarkForDestructionRequest, actor_user_id: str, request_id: str,
    ) -> KEKRead:
        kek = await self._get(session, tenant_id, kek_id)
        if kek.status == "MARKED_FOR_DESTRUCTION":
            raise FoundationError(KEK_ALREADY_MARKED)
        if kek.status == "DESTROYED":
            raise FoundationError(KEK_DESTROYED, detail="KEK already destroyed")

        from foundation_crypto.config import get_settings
        settings = get_settings()
        cooling_days = request.cooling_off_days_override or settings.kek_destruction_cooling_off_days
        cooling_ends = datetime.now(UTC) + timedelta(days=cooling_days)

        kek.status = "MARKED_FOR_DESTRUCTION"
        kek.destruction_scheduled_at = cooling_ends
        kek.destruction_marked_by = actor_user_id
        kek.destruction_marked_reason = request.reason

        self._add_history(
            session, tenant_id, kek_id, transition="MARKED_FOR_DESTRUCTION",
            from_status="ACTIVE" if kek.status != "SUSPENDED" else "SUSPENDED",
            to_status="MARKED_FOR_DESTRUCTION",
            changed_by=actor_user_id, reason=request.reason, request_id=request_id,
        )
        self._emit_event(
            session, tenant_id, "foundation.crypto.kek.marked_for_destruction",
            {"kek_id": kek_id, "cooling_ends_at": cooling_ends.isoformat(), "reason": request.reason},
            request_id=request_id,
        )
        await session.flush()
        return KEKRead.model_validate(kek)

    # ------------------------------------------------------------------ Destroy

    async def destroy(
        self, session: AsyncSession, *, tenant_id: str, kek_id: str,
        request: DestroyKEKRequest, actor_user_id: str, request_id: str,
    ) -> None:
        kek = await self._get(session, tenant_id, kek_id)

        # Guard: must be MARKED_FOR_DESTRUCTION
        if kek.status != "MARKED_FOR_DESTRUCTION":
            raise FoundationError(
                KEK_NOT_DESTRUCTIBLE,
                detail=f"KEK {kek_id} must be marked for destruction first. Current: {kek.status}",
            )
        if kek.status == "DESTROYED":
            raise FoundationError(KEK_DESTROYED)

        # Guard: four-eyes
        if request.approver_user_id == actor_user_id:
            raise FoundationError(
                FOUR_EYES_REQUIRED,
                detail="Destroy requires a distinct approver (four-eyes principle)",
            )

        # Guard: cooling-off (unless config allows override)
        from foundation_crypto.config import get_settings
        settings = get_settings()
        if settings.kek_destruction_cooling_off_days > 0 and kek.destruction_scheduled_at:
            if datetime.now(UTC) < kek.destruction_scheduled_at:
                raise FoundationError(
                    KEK_NOT_DESTRUCTIBLE,
                    detail=f"Cooling-off period not yet expired (ends {kek.destruction_scheduled_at.isoformat()})",
                )

        # Execute: delete key from Vault/HSM
        await self._kp.delete_key(vault_path=kek.vault_path)

        # Mark as DESTROYED
        kek.status = "DESTROYED"

        self._add_history(
            session, tenant_id, kek_id, transition="DESTROYED",
            from_status="MARKED_FOR_DESTRUCTION", to_status="DESTROYED",
            changed_by=actor_user_id,
            approver_user_id=request.approver_user_id,
            reason=request.confirmation_phrase,
            request_id=request_id,
        )
        self._emit_event(
            session, tenant_id, "foundation.crypto.kek.destroyed",
            {
                "kek_id": kek_id, "label": kek.label,
                "destroyed_by": actor_user_id, "approved_by": request.approver_user_id,
            },
            request_id=request_id,
        )
        await session.flush()

    # ------------------------------------------------------------------ Abort Destruction

    async def abort_destruction(
        self, session: AsyncSession, *, tenant_id: str, kek_id: str,
        reason: str, actor_user_id: str, request_id: str,
    ) -> KEKRead:
        kek = await self._get(session, tenant_id, kek_id)
        if kek.status != "MARKED_FOR_DESTRUCTION":
            raise FoundationError(
                KEK_NOT_DESTRUCTIBLE,
                detail=f"KEK {kek_id} is not marked for destruction. Current: {kek.status}",
            )

        prev_status = "MARKED_FOR_DESTRUCTION"
        kek.status = "ACTIVE"
        kek.destruction_scheduled_at = None

        self._add_history(
            session, tenant_id, kek_id, transition="DESTRUCTION_ABORTED",
            from_status=prev_status, to_status="ACTIVE",
            changed_by=actor_user_id, reason=reason, request_id=request_id,
        )
        self._emit_event(
            session, tenant_id, "foundation.crypto.kek.destruction_aborted",
            {"kek_id": kek_id, "reason": reason},
            request_id=request_id,
        )
        await session.flush()
        return KEKRead.model_validate(kek)

    # ------------------------------------------------------------------ Internal

    async def _get(self, session: AsyncSession, tenant_id: str, kek_id: str) -> KEK:
        stmt = select(KEK).where(KEK.id == kek_id, KEK.tenant_id == tenant_id).limit(1)
        row = (await session.execute(stmt)).scalar_one_or_none()
        if row is None:
            raise FoundationError(KEK_NOT_FOUND, detail=f"KEK {kek_id} not found")
        return row

    def _add_history(
        self,
        session: AsyncSession,
        tenant_id: str,
        kek_id: str,
        *,
        transition: str,
        from_status: str | None,
        to_status: str | None,
        changed_by: str,
        reason: str | None = None,
        approver_user_id: str | None = None,
        request_id: str | None = None,
    ) -> None:
        session.add(
            KEKHistory(
                tenant_id=tenant_id,
                kek_id=kek_id,
                transition=transition,
                from_status=from_status,
                to_status=to_status,
                changed_by=changed_by,
                reason=reason,
                approver_user_id=approver_user_id,
                audit_event_id=request_id,
            )
        )

    def _emit_event(
        self,
        session: AsyncSession,
        tenant_id: str,
        event_type: str,
        payload: dict[str, Any],
        *,
        request_id: str | None = None,
    ) -> None:
        session.add(
            Outbox(
                id=f"evt_{ulid.new()!s}",
                tenant_id=tenant_id,
                event_type=event_type,
                aggregate_id=payload.get("kek_id", ""),
                payload=payload,
                request_id=request_id,
            )
        )
