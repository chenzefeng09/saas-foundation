"""Unit tests for the daily storage quota reconcile job."""

from __future__ import annotations

from typing import Any

from foundation_lifecycle.domain.models import TenantStorageQuota

# Phase 4: foundation_storage is now a proper path-dep (chore commit dropped the
# late-import stub).  Tests construct a real BucketPurpose-aware fake client.


def _row(
    *,
    tenant_id: str,
    purpose: str = "workspace",
    used_bytes: int = 1_000,
    limit_bytes: int = 10_000,
) -> TenantStorageQuota:
    return TenantStorageQuota(
        id=f"sqt_{tenant_id}_{purpose}",
        tenant_id=tenant_id,
        bucket_purpose=purpose,
        limit_bytes=limit_bytes,
        used_bytes=used_bytes,
        soft_warn_pct=80,
    )


class _FakeStorageClient:
    def __init__(self, sizes: dict[tuple[str, str], int]) -> None:
        self._sizes = sizes
        self.calls: list[tuple[str, str]] = []

    async def compute_tenant_usage(self, tenant_id: str, purpose: Any) -> int:
        self.calls.append((tenant_id, str(purpose)))
        return self._sizes.get((tenant_id, str(purpose)), 0)


class TestReconcileUsedBytes:
    async def test_no_drift_does_not_flush(self, fake_session, tenant_id: str) -> None:
        from foundation_lifecycle.services.storage_quota_reconcile import (
            reconcile_used_bytes,
        )

        row = _row(tenant_id=tenant_id, used_bytes=500)
        fake_session.queue_scalars([row])
        client = _FakeStorageClient({(tenant_id, "workspace"): 500})

        report = await reconcile_used_bytes(
            fake_session, client, drift_alert_pct=1.0
        )

        assert report.quotas_scanned == 1
        assert report.drifts_corrected == 0
        assert report.total_drift_bytes == 0
        assert fake_session.flush_calls == 0
        assert row.used_bytes == 500  # unchanged

    async def test_drift_overwrites_and_flushes(
        self, fake_session, tenant_id: str
    ) -> None:
        from foundation_lifecycle.services.storage_quota_reconcile import (
            reconcile_used_bytes,
        )

        row = _row(tenant_id=tenant_id, used_bytes=500)
        fake_session.queue_scalars([row])
        client = _FakeStorageClient({(tenant_id, "workspace"): 800})

        report = await reconcile_used_bytes(
            fake_session, client, drift_alert_pct=1.0
        )

        assert report.quotas_scanned == 1
        assert report.drifts_corrected == 1
        assert report.total_drift_bytes == 300
        assert row.used_bytes == 800
        assert fake_session.flush_calls == 1

    async def test_storage_error_continues_to_next_row(
        self, fake_session, tenant_id: str
    ) -> None:
        from foundation_lifecycle.services.storage_quota_reconcile import (
            reconcile_used_bytes,
        )

        good = _row(tenant_id=tenant_id, used_bytes=100)
        bad = _row(
            tenant_id="tnt_BAD000000000000000000B1",
            purpose="kb_raw",
            used_bytes=200,
        )
        fake_session.queue_scalars([bad, good])

        client = _FakeStorageClient({(tenant_id, "workspace"): 150})
        # Make the first call raise; second should still succeed.
        original = client.compute_tenant_usage

        async def fail_first(t: str, p: Any) -> int:
            if t == "tnt_BAD000000000000000000B1":
                raise RuntimeError("S3 unavailable")
            return await original(t, p)

        client.compute_tenant_usage = fail_first  # type: ignore[assignment]

        report = await reconcile_used_bytes(
            fake_session, client, drift_alert_pct=1.0
        )

        # bad scanned but not corrected; good scanned and corrected.
        assert report.quotas_scanned == 2
        assert report.drifts_corrected == 1
        assert good.used_bytes == 150
        assert bad.used_bytes == 200  # untouched

    async def test_unknown_purpose_skipped(
        self, fake_session, tenant_id: str
    ) -> None:
        from foundation_lifecycle.services.storage_quota_reconcile import (
            reconcile_used_bytes,
        )

        row = _row(tenant_id=tenant_id, purpose="garbage", used_bytes=999)
        fake_session.queue_scalars([row])
        client = _FakeStorageClient({})

        report = await reconcile_used_bytes(
            fake_session, client, drift_alert_pct=1.0
        )

        assert report.quotas_scanned == 1
        assert report.drifts_corrected == 0
        assert row.used_bytes == 999  # untouched
        # The client must not have been called for an unknown purpose.
        assert client.calls == []
