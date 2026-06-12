"""Daily storage quota reconcile job (storage-v1 §5.3).

Walks ``lifecycle.tenant_storage_quota``, asks foundation_storage to
recompute the actual used bytes for each (tenant, bucket_purpose), and
overwrites ``used_bytes`` when it drifts. Drift over
``reconcile_drift_alert_pct`` is logged as a warning so operators see
when the live counter is leaking.
"""

from __future__ import annotations

from dataclasses import dataclass

from foundation_storage import BucketPurpose, StorageClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_lifecycle.domain.models import TenantStorageQuota
from foundation_lifecycle.observability import get_logger, get_meter

log = get_logger(__name__)
_meter = get_meter(__name__)
# Phase 7 metrics — scraped by Prometheus via otel-collector's prometheus
# exporter.  Counters accumulate across reconcile runs; ``used_bytes`` /
# ``limit_bytes`` are pushed via UpDownCounter set/add semantics after the
# sweep finishes (point-in-time view).
_drift_count = _meter.create_counter(
    "storage.quota.reconcile.drift_count",
    unit="1",
    description="Tenants whose used_bytes drifted on the last reconcile",
)
_drift_bytes = _meter.create_counter(
    "storage.quota.reconcile.drift_bytes_total",
    unit="By",
    description="Cumulative absolute drift in bytes across all reconcile runs",
)
_used_bytes = _meter.create_up_down_counter(
    "storage.quota.used_bytes",
    unit="By",
    description="Per-(tenant, bucket_purpose) used bytes from last reconcile",
)
_limit_bytes = _meter.create_up_down_counter(
    "storage.quota.limit_bytes",
    unit="By",
    description="Per-(tenant, bucket_purpose) limit bytes from last reconcile",
)
# Track the last value we exported so the next sweep can publish a delta
# rather than re-add the absolute number (otherwise the up-down counter
# accumulates forever).
_last_used: dict[tuple[str, str], int] = {}
_last_limit: dict[tuple[str, str], int] = {}


def _publish_quota_gauges(
    *, tenant_id: str, purpose: str, used: int, limit: int
) -> None:
    """Push the (tenant, purpose) row's used + limit through the metrics
    UpDownCounters as a delta against whatever we last reported."""
    key = (tenant_id, purpose)
    attrs = {"tenant_id": tenant_id, "bucket_purpose": purpose}
    prev_used = _last_used.get(key, 0)
    if used != prev_used:
        _used_bytes.add(used - prev_used, attrs)
        _last_used[key] = used
    prev_limit = _last_limit.get(key, 0)
    if limit != prev_limit:
        _limit_bytes.add(limit - prev_limit, attrs)
        _last_limit[key] = limit


# Purpose strings stored in the table map onto BucketPurpose enum values
# in foundation_storage; foundation_storage is now a path-dep so we import
# the enum directly instead of duck-typing.
_KNOWN_PURPOSES = frozenset({"audit", "workspace", "kb_raw", "kb_derived"})


@dataclass(frozen=True)
class ReconcileReport:
    quotas_scanned: int
    drifts_corrected: int
    total_drift_bytes: int


async def reconcile_used_bytes(
    session: AsyncSession,
    storage_client: StorageClient,
    *,
    drift_alert_pct: float,
) -> ReconcileReport:
    """Reconcile every quota row's ``used_bytes`` against the live bucket.

    Caller constructs ``storage_client`` as ``StorageClient.as_system(...)``
    so it can iterate across tenants.
    """
    rows = list((await session.scalars(select(TenantStorageQuota))).all())
    scanned = 0
    drifts = 0
    total_drift = 0

    for row in rows:
        scanned += 1
        if row.bucket_purpose not in _KNOWN_PURPOSES:
            log.warning(
                "storage.quota.unknown_purpose",
                tenant_id=row.tenant_id,
                bucket_purpose=row.bucket_purpose,
            )
            continue
        purpose = BucketPurpose(row.bucket_purpose)
        try:
            actual = await storage_client.compute_tenant_usage(
                row.tenant_id, purpose
            )
        except Exception as exc:
            log.error(
                "storage.quota.reconcile_failed",
                tenant_id=row.tenant_id,
                bucket_purpose=row.bucket_purpose,
                error=str(exc),
            )
            continue

        recorded = row.used_bytes
        diff = actual - recorded
        if diff == 0:
            # Still surface gauge even for no-drift rows so dashboards
            # don't go blank when the system is healthy.
            _publish_quota_gauges(
                tenant_id=row.tenant_id,
                purpose=row.bucket_purpose,
                used=row.used_bytes,
                limit=row.limit_bytes,
            )
            continue

        # Drift detection: relative to the larger of recorded/actual so a
        # 0 → N transition doesn't divide by zero.
        denom = max(recorded, actual, 1)
        pct = abs(diff) * 100.0 / denom
        if pct >= drift_alert_pct:
            log.warning(
                "storage.quota.drift_detected",
                tenant_id=row.tenant_id,
                bucket_purpose=row.bucket_purpose,
                recorded=recorded,
                actual=actual,
                drift_pct=round(pct, 3),
            )
        row.used_bytes = actual
        drifts += 1
        total_drift += abs(diff)
        # Push corrected value + drift counters.
        _drift_count.add(
            1,
            {
                "tenant_id": row.tenant_id,
                "bucket_purpose": row.bucket_purpose,
            },
        )
        _drift_bytes.add(
            abs(diff),
            {
                "tenant_id": row.tenant_id,
                "bucket_purpose": row.bucket_purpose,
            },
        )
        _publish_quota_gauges(
            tenant_id=row.tenant_id,
            purpose=row.bucket_purpose,
            used=actual,
            limit=row.limit_bytes,
        )

    if drifts > 0:
        await session.flush()

    return ReconcileReport(
        quotas_scanned=scanned,
        drifts_corrected=drifts,
        total_drift_bytes=total_drift,
    )
