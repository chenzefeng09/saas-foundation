"""Phase 7: ``_run_orphan_reconcile_job`` must INSERT an OrphanReconcileReport
row after a successful sweep (storage-v1 §11.3)."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, patch

from foundation_lifecycle.domain.models import OrphanReconcileReport


class _Recorder:
    """Stand-in for an async session used by ``admin_session_scope``."""

    def __init__(self) -> None:
        self.added: list[Any] = []

    def add(self, obj: Any) -> None:
        self.added.append(obj)


@asynccontextmanager
async def _fake_session_scope():
    yield AsyncMock()


async def test_run_orphan_reconcile_job_persists_report() -> None:
    """The scheduler entrypoint should add a single ``OrphanReconcileReport``
    row matching the values returned by ``reconcile_orphans``."""
    from foundation_lifecycle.main import _run_orphan_reconcile_job
    from foundation_lifecycle.services.storage_orphan_reconcile import (
        OrphanReconcileReport as ReconcileResult,
    )

    recorder = _Recorder()

    @asynccontextmanager
    async def fake_admin_session_scope():
        yield recorder

    fake_result = ReconcileResult(
        direction_a_orphans=3,
        direction_a_deleted=2,
        direction_b_missing=1,
    )

    with (
        patch(
            "foundation_lifecycle.main.session_scope",
            _fake_session_scope,
        ),
        patch(
            "foundation_lifecycle.domain.db.admin_session_scope",
            fake_admin_session_scope,
        ),
        patch(
            "foundation_lifecycle.services.storage_orphan_reconcile."
            "reconcile_orphans",
            AsyncMock(return_value=fake_result),
        ),
        patch(
            "foundation_storage.StorageClient.as_system",
            return_value=AsyncMock(),
        ),
    ):
        await _run_orphan_reconcile_job(dry_run=True, grace_period_days=7)

    assert len(recorder.added) == 1
    row = recorder.added[0]
    assert isinstance(row, OrphanReconcileReport)
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

    recorder = _Recorder()

    @asynccontextmanager
    async def fake_admin_session_scope():
        yield recorder

    with (
        patch(
            "foundation_lifecycle.main.session_scope",
            _fake_session_scope,
        ),
        patch(
            "foundation_lifecycle.domain.db.admin_session_scope",
            fake_admin_session_scope,
        ),
        patch(
            "foundation_lifecycle.services.storage_orphan_reconcile."
            "reconcile_orphans",
            AsyncMock(side_effect=RuntimeError("S3 timeout")),
        ),
        patch(
            "foundation_storage.StorageClient.as_system",
            return_value=AsyncMock(),
        ),
    ):
        # Should NOT raise
        await _run_orphan_reconcile_job(dry_run=False, grace_period_days=14)

    # Failures must not write a half-populated row.
    assert recorder.added == []
