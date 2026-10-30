"""Legal Hold service (lifecycle-v1 §6)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import ulid
from sqlalchemy import select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_lifecycle.domain.models import LegalHold, Outbox
from foundation_lifecycle.errors import LEGAL_HOLD_NOT_FOUND, FoundationError
from foundation_lifecycle.services.pagination import decode_cursor, encode_cursor

_HOLD_ID_PREFIX = "lhd_"


class LegalHoldService:
    """Manage legal holds: place, release, check."""

    async def place(
        self, session: AsyncSession, *, tenant_id: str,
        resource_type_id: str, resource_id: str,
        reason: str, placed_by: str, case_reference: str | None,
        request_id: str,
    ) -> LegalHold:
        hold = LegalHold(
            id=f"{_HOLD_ID_PREFIX}{ulid.new()!s}",
            tenant_id=tenant_id,
            resource_type_id=resource_type_id,
            resource_id=resource_id,
            reason=reason,
            placed_by=placed_by,
            case_reference=case_reference,
        )
        session.add(hold)
        self._emit(session, tenant_id, "foundation.lifecycle.legal_hold.placed",
                   {"hold_id": hold.id, "resource_id": resource_id, "reason": reason}, request_id)
        await session.flush()
        return hold

    async def release(
        self, session: AsyncSession, *, tenant_id: str, hold_id: str,
        released_by: str, request_id: str,
    ) -> LegalHold:
        hold = await session.get(LegalHold, hold_id)
        if hold is None or hold.tenant_id != tenant_id:
            raise FoundationError(LEGAL_HOLD_NOT_FOUND, extra={"hold_id": hold_id})
        if hold.released_at is not None:
            return hold  # already released

        hold.released_at = datetime.now(UTC)
        hold.released_by = released_by
        self._emit(session, tenant_id, "foundation.lifecycle.legal_hold.released",
                   {"hold_id": hold_id, "resource_id": hold.resource_id}, request_id)
        await session.flush()
        return hold

    async def check(
        self, session: AsyncSession, *, tenant_id: str,
        resource_type_id: str, resource_id: str,
    ) -> bool:
        """Check if a resource has an active legal hold."""
        hold = await session.scalar(
            select(LegalHold).where(
                LegalHold.tenant_id == tenant_id,
                LegalHold.resource_type_id == resource_type_id,
                LegalHold.resource_id == resource_id,
                LegalHold.released_at.is_(None),
            ).limit(1)
        )
        return hold is not None

    async def list_holds(
        self, session: AsyncSession, *, tenant_id: str,
        cursor: str | None = None, limit: int = 50,
    ) -> tuple[list[LegalHold], str | None]:
        """Active holds, newest first, keyset-paged on (placed_at, id); see services.pagination."""
        stmt = select(LegalHold).where(
            LegalHold.tenant_id == tenant_id,
            LegalHold.released_at.is_(None),
        )
        if cursor:
            placed_at, hold_id = decode_cursor(cursor, id_prefix=_HOLD_ID_PREFIX)
            stmt = stmt.where(tuple_(LegalHold.placed_at, LegalHold.id) < (placed_at, hold_id))
        stmt = stmt.order_by(LegalHold.placed_at.desc(), LegalHold.id.desc()).limit(limit + 1)
        rows = list((await session.scalars(stmt)).all())
        page = rows[:limit]
        # The cursor is the sort key of the last row *returned*, never the lookahead row's.
        next_cursor = encode_cursor(page[-1].placed_at, page[-1].id) if len(rows) > limit else None
        return page, next_cursor

    def _emit(self, session: AsyncSession, tenant_id: str, event_type: str,
              payload: dict[str, Any], request_id: str) -> None:
        session.add(Outbox(
            tenant_id=tenant_id, event_type=event_type,
            aggregate_id=payload.get("resource_id", ""),
            payload=payload, request_id=request_id,
        ))
