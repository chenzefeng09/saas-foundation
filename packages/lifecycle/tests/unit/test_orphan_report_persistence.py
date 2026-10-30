"""Phase 7: ``_run_orphan_reconcile_job`` must INSERT an OrphanReconcileReport
row after a successful sweep (storage-v1 §11.3).

The job runs under APScheduler with no request-scoped FoundationContext, so
both the cross-tenant sweep and the report insert go through
``admin_session_scope`` (actor=ADMIN, admin_all RLS policies).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import ANY, AsyncMock, patch

from foundation_lifecycle.domain.models import OrphanReconcileReport


class _Recorder:
    """Stand-in for an async session yielded by ``admin_session_scope``."""

    def __init__(self) -> None:
        self.added: list[Any] = []
        self.committed = False

    def add(self, obj: Any) -> None:
        self.added.append(obj)


def _admin_session_scope(sessions: list[_Recorder]) -> Any:
    """Fake ``admin_session_scope``: a fresh ``_Recorder`` per transaction,
    marked committed only when the block exits cleanly (the real scope rolls
    back when it raises)."""

    @asynccontextmanager
    async def scope(*, tenant_id: str = "", user_id: str = "PLATFORM"):
        session = _Recorder()
        sessions.append(session)
        yield session
        session.committed = True

    return scope


async def test_run_orphan_reconcile_job_persists_report() -> None:
    """The scheduler entrypoint should sweep on an admin session, then add a
    single ``OrphanReconcileReport`` row in a committed admin transaction,
    matching the values returned by ``reconcile_orphans``."""
    from foundation_lifecycle.main import _run_orphan_reconcile_job
    from foundation_lifecycle.services.storage_orphan_reconcile import (
        OrphanReconcileReport as ReconcileResult,
    )

    sessions: list[_Recorder] = []

    fake_result = ReconcileResult(
        direction_a_orphans=3,
        direction_a_deleted=2,
        direction_b_missing=1,
    )

    with (
        patch(
            "foundation_lifecycle.domain.db.admin_session_scope",
            _admin_session_scope(sessions),
        ),
        patch(
            "foundation_lifecycle.services.storage_orphan_reconcile."
            "reconcile_orphans",
            autospec=True,
            return_value=fake_result,
        ) as reconcile,
        patch(
            "foundation_storage.StorageClient.as_system",
            return_value=AsyncMock(),
        ) as as_system,
        patch("foundation_lifecycle.main.log") as log,
    ):
        await _run_orphan_reconcile_job(dry_run=True, grace_period_days=7)

    log.error.assert_not_called()
    added = [(session, obj) for session in sessions for obj in session.added]
    assert len(added) == 1
    holder, row = added[0]
    assert isinstance(row, OrphanReconcileReport)
    assert holder.committed
    # The sweep ran on the first admin session, tagged with the row's id.
    reconcile.assert_awaited_once_with(
        sessions[0],
        as_system.return_value,
        dry_run=True,
        grace_period_days=7,
        run_id=row.id,
    )
    assert row.id.startswith("orr_")
    assert row.dry_run is True
    assert row.grace_period_days == 7
    assert row.direction_a_orphans == 3
    assert row.direction_a_deleted == 2
    assert row.direction_b_missing == 1
    assert row.duration_ms >= 0
    assert row.completed_at >= row.started_at


async def test_run_orphan_reconcile_job_swallows_errors() -> None:
    """Phase 4 contract preserved: a failed sweep logs and returns — does
    NOT raise out of the scheduler thread."""
    from foundation_lifecycle.main import _run_orphan_reconcile_job

    sessions: list[_Recorder] = []

    with (
        patch(
            "foundation_lifecycle.domain.db.admin_session_scope",
            _admin_session_scope(sessions),
        ),
        patch(
            "foundation_lifecycle.services.storage_orphan_reconcile."
            "reconcile_orphans",
            autospec=True,
            side_effect=RuntimeError("S3 timeout"),
        ) as reconcile,
        patch(
            "foundation_storage.StorageClient.as_system",
            return_value=AsyncMock(),
        ),
        patch("foundation_lifecycle.main.log") as log,
    ):
        # Should NOT raise
        await _run_orphan_reconcile_job(dry_run=False, grace_period_days=14)

    # The sweep that failed ran on an admin session, with the job's arguments.
    assert sessions, "the sweep did not open an admin session"
    reconcile.assert_awaited_once_with(
        sessions[0],
        ANY,
        dry_run=False,
        grace_period_days=14,
        run_id=ANY,
    )
    log.error.assert_called_once_with(
        "storage.orphan.reconcile_error",
        run_id=reconcile.await_args.kwargs["run_id"],
        error="S3 timeout",
    )
    # Failures must not write a half-populated row.
    assert [obj for session in sessions for obj in session.added] == []
