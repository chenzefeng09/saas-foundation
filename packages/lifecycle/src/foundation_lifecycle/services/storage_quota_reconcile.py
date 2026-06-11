"""Daily storage quota reconcile job (storage-v1 §5.3).

Walks ``lifecycle.tenant_storage_quota``, asks foundation_storage to
recompute the actual used bytes for each (tenant, bucket_purpose), and
overwrites ``used_bytes`` when it drifts. Drift over
``reconcile_drift_alert_pct`` is logged as a warning so operators see
when the live counter is leaking.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_lifecycle.domain.models import TenantStorageQuota
from foundation_lifecycle.observability import get_logger

log = get_logger(__name__)


# Purpose strings stored in the table map onto BucketPurpose enum values
# in foundation_storage. We don't import the enum eagerly to keep the
# lifecycle dependency footprint small.
_KNOWN_PURPOSES = frozenset({"audit", "workspace", "kb_raw", "kb_derived"})


@dataclass(frozen=True)
class ReconcileReport:
    quotas_scanned: int
    drifts_corrected: int
    total_drift_bytes: int


async def reconcile_used_bytes(
    session: AsyncSession,
    storage_client: object,  # foundation_storage.StorageClient (avoid hard import)
    *,
    drift_alert_pct: float,
) -> ReconcileReport:
    """Reconcile every quota row's ``used_bytes`` against the live bucket.

    ``storage_client`` is duck-typed as having
    ``async compute_tenant_usage(tenant_id, BucketPurpose) -> int``.
    Constructed by the caller as ``StorageClient.as_system(...)``.
    """
    from foundation_storage import BucketPurpose  # late import

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
            actual = await storage_client.compute_tenant_usage(  # type: ignore[attr-defined]
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

    if drifts > 0:
        await session.flush()

    return ReconcileReport(
        quotas_scanned=scanned,
        drifts_corrected=drifts,
        total_drift_bytes=total_drift,
    )
