"""Storage admin reports (Phase 7 — storage-v1 §11.3).

Read-only access to ``lifecycle.orphan_reconcile_report``.  Sessions are
always opened via ``admin_session_scope`` by the caller — this service has
no tenant filter because the table is cross-tenant.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_lifecycle.domain.models import OrphanReconcileReport
from foundation_lifecycle.observability import get_logger

log = get_logger(__name__)


class StorageReportService:
    """List/get orphan reconcile reports for the admin UI.

    Cursor pagination uses the report id as the cursor because ids are
    ULID-based — lexicographic order matches started_at order.  Pages are
    returned newest first.
    """

    DEFAULT_LIMIT = 20
    MAX_LIMIT = 100

    async def list_reports(
        self,
        session: AsyncSession,
        *,
        limit: int | None = None,
        before_id: str | None = None,
    ) -> tuple[list[OrphanReconcileReport], str | None]:
        """Return one page newest first plus the cursor for the next call.

        ``before_id`` is the id of the last row of the previous page (so the
        next page starts at the row immediately older).  The returned cursor
        is the id of the last row of *this* page, or None when no more pages.
        """
        page_size = self._clamp_limit(limit)
        stmt = select(OrphanReconcileReport).order_by(
            OrphanReconcileReport.started_at.desc(),
            OrphanReconcileReport.id.desc(),
        ).limit(page_size + 1)
        if before_id is not None:
            stmt = stmt.where(OrphanReconcileReport.id < before_id)
        rows = list((await session.scalars(stmt)).all())
        next_cursor: str | None = None
        if len(rows) > page_size:
            # Strip the lookahead row but use its id as the next cursor.
            rows = rows[:page_size]
            next_cursor = rows[-1].id
        return rows, next_cursor

    async def get_report(
        self,
        session: AsyncSession,
        *,
        report_id: str,
    ) -> OrphanReconcileReport | None:
        return await session.get(OrphanReconcileReport, report_id)

    @staticmethod
    def serialize(row: OrphanReconcileReport) -> dict[str, Any]:
        return {
            "id": row.id,
            "started_at": row.started_at.isoformat() if row.started_at else None,
            "completed_at": (
                row.completed_at.isoformat() if row.completed_at else None
            ),
            "duration_ms": row.duration_ms,
            "dry_run": row.dry_run,
            "grace_period_days": row.grace_period_days,
            "direction_a_orphans": row.direction_a_orphans,
            "direction_a_deleted": row.direction_a_deleted,
            "direction_b_missing": row.direction_b_missing,
        }

    @classmethod
    def _clamp_limit(cls, limit: int | None) -> int:
        if limit is None:
            return cls.DEFAULT_LIMIT
        if limit < 1:
            return cls.DEFAULT_LIMIT
        return min(limit, cls.MAX_LIMIT)
