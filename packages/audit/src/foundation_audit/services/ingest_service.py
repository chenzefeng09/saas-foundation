"""Audit event ingestion service.

Receives validated AuditEvent objects, writes them to the Postgres outbox
table for transactional durability, then returns 202 Accepted.

The batch worker (worker/batch_processor.py) picks up rows from the outbox
and writes them to ClickHouse with hash chain + signature.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_audit.config import get_settings
from foundation_audit.domain.models import Outbox
from foundation_audit.observability import get_logger
from foundation_audit.schemas.event import AuditEvent

log = get_logger(__name__)


class IngestService:
    """Accept events → validate → write outbox."""

    def __init__(self) -> None:
        self._settings = get_settings()

    async def ingest_one(self, session: AsyncSession, event: AuditEvent) -> None:
        """Write a single event to the outbox."""
        event_json = _canonical_json(event.model_dump(mode="json"))
        row = Outbox(
            tenant_id=event.tenant_id,
            event_json=event_json,
        )
        session.add(row)
        await session.flush()

    async def ingest_batch(self, session: AsyncSession, events: list[AuditEvent]) -> int:
        """Write multiple events to the outbox. Returns count."""
        for event in events:
            event_json = _canonical_json(event.model_dump(mode="json"))
            session.add(Outbox(tenant_id=event.tenant_id, event_json=event_json))
        await session.flush()
        return len(events)

    # ---- outbox → ClickHouse worker helpers ----

    async def fetch_pending(
        self, session: AsyncSession, *, limit: int = 1000,
    ) -> list[tuple[int, dict[str, Any]]]:
        """Fetch undelivered outbox rows ordered by id."""
        stmt = (
            select(Outbox.id, Outbox.event_json)
            .where(Outbox.delivered_at.is_(None))
            .order_by(Outbox.id)
            .limit(limit)
        )
        rows = (await session.execute(stmt)).all()
        return [(row.id, row.event_json) for row in rows]

    async def mark_delivered(
        self, session: AsyncSession, row_ids: list[int],
    ) -> None:
        """Mark outbox rows as delivered."""
        if not row_ids:
            return
        stmt = (
            update(Outbox)
            .where(Outbox.id.in_(row_ids))
            .values(delivered_at=datetime.now(UTC))
        )
        await session.execute(stmt)
        await session.flush()

    async def record_attempts(
        self,
        session: AsyncSession,
        row_ids: list[int],
        *,
        error: str,
    ) -> None:
        """Increment attempts counter + record last_error for failed rows.

        Called when ClickHouse write fails; leaves delivered_at=NULL so the
        worker will retry on the next poll cycle.
        """
        if not row_ids:
            return
        stmt = (
            update(Outbox)
            .where(Outbox.id.in_(row_ids))
            .values(
                attempts=Outbox.attempts + 1,
                last_error=error[:2000],  # truncate to avoid huge error strings
            )
        )
        await session.execute(stmt)
        await session.flush()


def _canonical_json(data: dict[str, Any]) -> dict[str, Any]:
    """Strip None values for compact JSON storage."""
    return {k: v for k, v in data.items() if v is not None}
