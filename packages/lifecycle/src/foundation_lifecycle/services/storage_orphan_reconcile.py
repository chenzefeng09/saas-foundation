"""Daily S3 ↔ DB orphan reconcile (storage-v1 §6.3).

Two-direction sweep:

* **Direction A — S3 has it, DB doesn't.**  We iterate every tenant prefix
  in the workspace / kb-raw / kb-derived buckets, derive ``resource_id``
  from the key, and look it up in ``lifecycle.recycle_bin``.  An object
  older than the grace period whose resource_id has no recycle_bin row
  is an orphan; with ``dry_run=False`` we delete it via the StorageClient.

* **Direction B — DB has it, S3 doesn't.**  We scan
  ``recycle_bin`` rows that have been hard-deleted with a recorded
  ``original_location`` and ``head_object`` each key; a missing object
  with a hard_deleted_at after deleted_at is logged as
  ``storage.object_missing``.

The audit bucket is **not** swept — its WORM lock blocks deletion and
audit doesn't go through lifecycle today (storage-v1 §10.1).

Option X — for Direction A we trust ``recycle_bin`` as the *single*
truth source.  This is safe because every deletion now lands in the
recycle bin first (security-ops DELETE endpoints in this same phase,
direct lifecycle.soft_delete API for other services).  Pre-Phase-4
objects whose owners never had a recycle_bin row are by definition
orphans the moment grace_period_days elapses.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from foundation_storage import BucketPurpose
from foundation_storage.errors import ObjectNotFoundError, StorageError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_lifecycle.domain.models import RecycleBin
from foundation_lifecycle.observability import get_logger
from foundation_lifecycle.services.storage_location import parse_s3_location

if TYPE_CHECKING:
    from foundation_storage import StorageClient

log = get_logger(__name__)


# audit bucket is skipped — see module docstring + storage-v1 §10.1.
_SWEEP_PURPOSES: tuple[BucketPurpose, ...] = (
    BucketPurpose.WORKSPACE,
    BucketPurpose.KB_RAW,
    BucketPurpose.KB_DERIVED,
)


@dataclass(frozen=True)
class OrphanReconcileReport:
    direction_a_orphans: int
    direction_a_deleted: int
    direction_b_missing: int


def _resource_id_from_key(key: str) -> str | None:
    """Extract the resource_id segment from a tenant-scoped key.

    Layouts (storage-v1 §3.2):
      * workspace: ``tenants/{tid}/workspaces/{wid}/files/{fid}/...``
        — resource_id is ``{fid}``
      * workspace (security-ops): ``tenants/{tid}/security-ops/{type}/{rid}/...``
      * kb-raw:    ``tenants/{tid}/kbs/{kbid}/docs/{docid}/...``
        — resource_id is ``{docid}``
      * kb-derived: ``tenants/{tid}/kbs/{kbid}/derived/{docid}/...``

    Returns ``None`` for unrecognised layouts so the caller can skip
    rather than treat random objects as orphans.
    """
    parts = key.split("/")
    if len(parts) < 5 or parts[0] != "tenants":
        return None
    # parts[1] = tenant_id, parts[2] = container_kind ('workspaces'|'kbs'|'security-ops')
    if parts[2] == "workspaces" and len(parts) >= 6 and parts[4] == "files":
        return parts[5]
    if parts[2] == "kbs" and len(parts) >= 6 and parts[4] in ("docs", "derived"):
        return parts[5]
    if parts[2] == "security-ops" and len(parts) >= 5:
        return parts[4]
    return None


async def reconcile_orphans(
    session: AsyncSession,
    storage_client: StorageClient,
    *,
    dry_run: bool,
    grace_period_days: int,
) -> OrphanReconcileReport:
    """Run a single orphan reconcile pass.

    Returns counts; emits structured logs at WARNING for each orphan
    found (Direction A) and each missing object (Direction B) so ops can
    alert on either without consuming this dataclass.
    """
    from foundation_lifecycle.domain.models import TenantStorageQuota

    now = datetime.now(UTC)
    grace_cutoff = now - timedelta(days=grace_period_days)

    direction_a_orphans = 0
    direction_a_deleted = 0
    direction_b_missing = 0

    # ---- Direction A: S3 prefix → recycle_bin lookup --------------------
    tenant_rows = list(
        (await session.scalars(select(TenantStorageQuota))).all()
    )
    seen_tenant_purpose: set[tuple[str, str]] = set()
    for row in tenant_rows:
        if row.bucket_purpose == "audit":
            continue
        seen_tenant_purpose.add((row.tenant_id, row.bucket_purpose))

    for tenant_id, purpose_str in seen_tenant_purpose:
        try:
            purpose = BucketPurpose(purpose_str)
        except ValueError:
            continue
        if purpose not in _SWEEP_PURPOSES:
            continue
        try:
            # iter_prefix already scopes to ``tenants/{tenant_id}/``; pass an
            # empty prefix to walk every object under that tenant.
            async for meta in storage_client.iter_prefix(
                purpose, tenant_id, prefix_segments=()
            ):
                # Skip recently-written objects so creates don't race the sweep.
                if meta.last_modified and meta.last_modified > grace_cutoff:
                    continue
                resource_id = _resource_id_from_key(meta.key)
                if resource_id is None:
                    continue
                existing = await session.scalar(
                    select(RecycleBin)
                    .where(
                        RecycleBin.tenant_id == tenant_id,
                        RecycleBin.resource_id == resource_id,
                    )
                    .limit(1)
                )
                if existing is not None:
                    continue
                direction_a_orphans += 1
                log.warning(
                    "storage.orphan.detected",
                    tenant_id=tenant_id,
                    bucket_purpose=purpose_str,
                    key=meta.key,
                    dry_run=dry_run,
                )
                if not dry_run:
                    # Re-derive an ObjectKey via the wire format so we go
                    # through the same validation path as every other write.
                    bucket_map = (
                        storage_client.settings.bucket_to_purpose_map()
                    )
                    bucket_name = next(
                        (b for b, p in bucket_map.items() if p == purpose),
                        None,
                    )
                    if bucket_name is None:
                        continue
                    keys = parse_s3_location(
                        f'["{bucket_name}::{meta.key}"]',
                        settings=storage_client.settings,
                    )
                    if not keys:
                        continue
                    try:
                        await storage_client.delete_object(keys[0])
                        direction_a_deleted += 1
                    except StorageError as exc:
                        log.error(
                            "storage.orphan.delete_failed",
                            tenant_id=tenant_id,
                            key=meta.key,
                            error=str(exc),
                        )
        except StorageError as exc:
            log.error(
                "storage.orphan.list_failed",
                tenant_id=tenant_id,
                bucket_purpose=purpose_str,
                error=str(exc),
            )

    # ---- Direction B: recycle_bin → S3 head_object check ----------------
    hd_rows = list(
        (await session.scalars(
            select(RecycleBin)
            .where(
                RecycleBin.hard_deleted_at.is_not(None),
                RecycleBin.original_location.is_not(None),
            )
        )).all()
    )
    for entry in hd_rows:
        keys = parse_s3_location(entry.original_location, settings=storage_client.settings)
        for key in keys:
            try:
                await storage_client.head_object(key)
            except ObjectNotFoundError:
                # Object is missing post-hard-delete. Normal when hard_delete
                # already GC'd it; still logged at WARNING so an unexpected
                # leak path (somebody deleted in S3 outside lifecycle) is
                # visible on the dashboard.
                direction_b_missing += 1
                log.warning(
                    "storage.object_missing",
                    tenant_id=entry.tenant_id,
                    resource_id=entry.resource_id,
                    key=key.key,
                    deleted_at=entry.deleted_at.isoformat() if entry.deleted_at else None,
                    hard_deleted_at=(
                        entry.hard_deleted_at.isoformat()
                        if entry.hard_deleted_at
                        else None
                    ),
                )
            except StorageError as exc:
                log.error(
                    "storage.orphan.head_failed",
                    tenant_id=entry.tenant_id,
                    resource_id=entry.resource_id,
                    key=key.key,
                    error=str(exc),
                )

    return OrphanReconcileReport(
        direction_a_orphans=direction_a_orphans,
        direction_a_deleted=direction_a_deleted,
        direction_b_missing=direction_b_missing,
    )
