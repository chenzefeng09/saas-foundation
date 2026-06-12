"""HTTP-level tests for the Phase 7 storage admin endpoints.

Covers:
* ``GET  /storage-quotas/admin/summary``  — require_scope + cross-tenant list
* ``PATCH /storage-quotas/admin/{tid}/{purpose}`` — 200 + 404
* ``GET  /orphan-reports``                — pagination + cursor
* ``GET  /orphan-reports/{id}``            — 404
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from fastapi.testclient import TestClient

from foundation_lifecycle.api import dependencies
from foundation_lifecycle.domain.models import (
    OrphanReconcileReport,
    TenantStorageQuota,
)
from foundation_lifecycle.main import create_app


# --------------------------------------------------------------------------- #
# Fakes                                                                       #
# --------------------------------------------------------------------------- #
class _FakeAdminSession:
    """Just enough surface for the admin services."""

    def __init__(
        self,
        *,
        quotas: list[TenantStorageQuota] | None = None,
        reports: list[OrphanReconcileReport] | None = None,
    ) -> None:
        self._quotas = list(quotas or [])
        self._reports = list(reports or [])

    async def scalars(self, stmt: Any) -> Any:
        compiled = str(stmt)
        if "tenant_storage_quota" in compiled.lower():
            rows = self._quotas
        elif "orphan_reconcile_report" in compiled.lower():
            # honour limit set in the statement
            rows = self._reports
            limit = getattr(stmt, "_limit", None)
            if isinstance(limit, int):
                rows = rows[:limit]
        else:
            rows = []
        return _FakeScalars(rows)

    async def scalar(self, stmt: Any) -> Any:
        # Patch endpoint looks up a single quota by tenant + purpose.
        # We piggyback on whichever quota the test queued first.
        return self._quotas[0] if self._quotas else None

    async def get(self, model: type, key: Any) -> Any:
        for r in self._reports:
            if r.id == key:
                return r
        return None

    async def flush(self) -> None:
        pass


class _FakeScalars:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return self._rows


# --------------------------------------------------------------------------- #
# Fixtures                                                                    #
# --------------------------------------------------------------------------- #
def _quota(
    tenant_id: str = "tnt_a",
    purpose: str = "workspace",
    used: int = 500,
    limit: int = 1_000,
) -> TenantStorageQuota:
    return TenantStorageQuota(
        id=f"sqt_{tenant_id}_{purpose}",
        tenant_id=tenant_id,
        bucket_purpose=purpose,
        limit_bytes=limit,
        used_bytes=used,
        soft_warn_pct=80,
        updated_at=datetime(2026, 6, 12, tzinfo=UTC),
    )


def _report(rid: str, *, dry_run: bool = True) -> OrphanReconcileReport:
    return OrphanReconcileReport(
        id=rid,
        started_at=datetime(2026, 6, 12, 10, 0, tzinfo=UTC),
        completed_at=datetime(2026, 6, 12, 10, 1, tzinfo=UTC),
        duration_ms=60_000,
        dry_run=dry_run,
        grace_period_days=7,
        direction_a_orphans=2,
        direction_a_deleted=0 if dry_run else 2,
        direction_b_missing=1,
    )


def _client_with_session(session: _FakeAdminSession) -> TestClient:
    app = create_app()

    async def _admin_dep() -> AsyncIterator[_FakeAdminSession]:
        yield session

    app.dependency_overrides[dependencies.admin_db_session] = _admin_dep
    return TestClient(app, raise_server_exceptions=True)


_PREFIX = "/api/lifecycle/v1"
_ADMIN_HEADER = {"X-Foundation-Scopes": "storage.admin"}


# --------------------------------------------------------------------------- #
# /storage-quotas/admin/summary                                               #
# --------------------------------------------------------------------------- #
def test_admin_summary_requires_scope() -> None:
    client = _client_with_session(_FakeAdminSession())
    resp = client.get(f"{_PREFIX}/storage-quotas/admin/summary")
    assert resp.status_code == 403


def test_admin_summary_returns_used_pct() -> None:
    session = _FakeAdminSession(
        quotas=[
            _quota("tnt_a", "workspace", used=200, limit=1_000),
            _quota("tnt_b", "kb_raw", used=0, limit=0),
        ]
    )
    client = _client_with_session(session)
    resp = client.get(
        f"{_PREFIX}/storage-quotas/admin/summary",
        headers=_ADMIN_HEADER,
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload["total"] == 2
    items = {item["tenant_id"]: item for item in payload["items"]}
    assert items["tnt_a"]["used_pct"] == 20.0
    # limit==0 → used_pct is None (UI renders "n/a")
    assert items["tnt_b"]["used_pct"] is None


# --------------------------------------------------------------------------- #
# PATCH /storage-quotas/admin/{tid}/{purpose}                                 #
# --------------------------------------------------------------------------- #
def test_admin_patch_returns_404_when_missing() -> None:
    client = _client_with_session(_FakeAdminSession(quotas=[]))
    resp = client.patch(
        f"{_PREFIX}/storage-quotas/admin/tnt_x/workspace",
        json={"limit_bytes": 2_000},
        headers=_ADMIN_HEADER,
    )
    assert resp.status_code == 404


def test_admin_patch_updates_existing() -> None:
    quota = _quota("tnt_a", "workspace", used=500, limit=1_000)
    client = _client_with_session(_FakeAdminSession(quotas=[quota]))
    resp = client.patch(
        f"{_PREFIX}/storage-quotas/admin/tnt_a/workspace",
        json={"limit_bytes": 5_000, "soft_warn_pct": 90},
        headers=_ADMIN_HEADER,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["limit_bytes"] == 5_000
    assert body["soft_warn_pct"] == 90
    # used_bytes is NOT touched by the admin patch — reconcile owns it.
    assert body["used_bytes"] == 500
    assert body["used_pct"] == round(500 * 100 / 5_000, 2)


# --------------------------------------------------------------------------- #
# /orphan-reports                                                             #
# --------------------------------------------------------------------------- #
def test_orphan_reports_requires_scope() -> None:
    client = _client_with_session(_FakeAdminSession())
    resp = client.get(f"{_PREFIX}/orphan-reports")
    assert resp.status_code == 403


def test_orphan_reports_pagination_returns_cursor() -> None:
    # Insert page_size + 1 → expect cursor of page_size'th row.
    reports = [_report(f"orr_{i:02d}") for i in range(25)]
    # service sorts started_at desc; our fake just returns the slice
    session = _FakeAdminSession(reports=reports)
    client = _client_with_session(session)
    resp = client.get(
        f"{_PREFIX}/orphan-reports",
        params={"limit": 20},
        headers=_ADMIN_HEADER,
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert len(payload["items"]) == 20
    assert payload["next_cursor"] == payload["items"][-1]["id"]


def test_orphan_report_get_returns_404_when_missing() -> None:
    client = _client_with_session(_FakeAdminSession(reports=[]))
    resp = client.get(
        f"{_PREFIX}/orphan-reports/orr_missing",
        headers=_ADMIN_HEADER,
    )
    assert resp.status_code == 404


def test_orphan_report_get_returns_row() -> None:
    rpt = _report("orr_test")
    client = _client_with_session(_FakeAdminSession(reports=[rpt]))
    resp = client.get(
        f"{_PREFIX}/orphan-reports/orr_test",
        headers=_ADMIN_HEADER,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["id"] == "orr_test"
    assert body["dry_run"] is True
    assert body["direction_a_orphans"] == 2
    assert body["direction_a_deleted"] == 0
    assert body["direction_b_missing"] == 1
