"""Unit tests for the daily S3 ↔ DB orphan reconcile job (storage-v1 §6.3)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

from foundation_lifecycle.domain.models import RecycleBin, TenantStorageQuota


def _quota_row(
    tenant_id: str, purpose: str = "workspace", used_bytes: int = 0
) -> TenantStorageQuota:
    return TenantStorageQuota(
        id=f"sqt_{tenant_id[:4]}_{purpose}",
        tenant_id=tenant_id,
        bucket_purpose=purpose,
        limit_bytes=10_000,
        used_bytes=used_bytes,
        soft_warn_pct=80,
    )


class _FakeObjectMeta:
    def __init__(
        self, key: str, last_modified: datetime, size: int = 100
    ) -> None:
        self.key = key
        self.last_modified = last_modified
        self.size = size
        self.content_type = "application/octet-stream"
        self.metadata: dict[str, str] = {}


class _FakeSettings:
    """Mirror StorageSettings just enough for the reconcile code path."""

    bucket_audit = "foundation-audit"
    bucket_workspace = "foundation-workspace"
    bucket_kb_raw = "foundation-kb-raw"
    bucket_kb_derived = "foundation-kb-derived"

    def bucket_to_purpose_map(self) -> dict[str, Any]:
        from foundation_storage.keys import BucketPurpose

        return {
            self.bucket_audit: BucketPurpose.AUDIT,
            self.bucket_workspace: BucketPurpose.WORKSPACE,
            self.bucket_kb_raw: BucketPurpose.KB_RAW,
            self.bucket_kb_derived: BucketPurpose.KB_DERIVED,
        }


class _FakeStorageClient:
    """Duck-typed StorageClient for orphan reconcile tests."""

    def __init__(
        self,
        *,
        objects_per_tenant: dict[tuple[str, str], list[_FakeObjectMeta]] | None = None,
        existing_keys: set[str] | None = None,
    ) -> None:
        # objects_per_tenant: (tenant_id, purpose_str) -> [ObjectMeta...]
        self._objects = objects_per_tenant or {}
        # existing_keys: keys that head_object reports as present
        self._existing = existing_keys if existing_keys is not None else set()
        self.deleted: list[str] = []
        self.head_calls: list[str] = []
        self.settings = _FakeSettings()

    async def iter_prefix(
        self,
        purpose: Any,
        tenant_id: str,
        prefix_segments: tuple[str, ...] = (),
        page_size: int = 1000,
    ) -> AsyncIterator[_FakeObjectMeta]:
        for meta in self._objects.get((tenant_id, str(purpose)), []):
            yield meta

    async def delete_object(self, key: Any) -> None:
        self.deleted.append(key.key if hasattr(key, "key") else str(key))

    async def head_object(self, key: Any) -> _FakeObjectMeta:
        from foundation_storage.errors import OBJECT_NOT_FOUND, ObjectNotFoundError

        key_str = key.key if hasattr(key, "key") else str(key)
        self.head_calls.append(key_str)
        if key_str in self._existing:
            return _FakeObjectMeta(key_str, datetime.now(UTC))
        raise ObjectNotFoundError(OBJECT_NOT_FOUND, detail=f"not found: {key_str}")


def _stale(days_ago: int) -> datetime:
    return datetime.now(UTC) - timedelta(days=days_ago)


class TestOrphanDirectionA:
    """DB has no recycle_bin record but the S3 object exists → orphan."""

    async def test_audit_bucket_is_skipped(self, fake_session, tenant_id: str) -> None:
        from foundation_lifecycle.services.storage_orphan_reconcile import (
            reconcile_orphans,
        )

        # Only audit quota row → reconcile should find nothing.
        fake_session.queue_scalars([_quota_row(tenant_id, purpose="audit")])
        client = _FakeStorageClient()

        report = await reconcile_orphans(
            fake_session, client, dry_run=True, grace_period_days=7
        )

        assert report.direction_a_orphans == 0
        assert report.direction_a_deleted == 0
        # audit bucket must never be iterated
        assert client.deleted == []

    async def test_recent_objects_within_grace_period_are_ignored(
        self, fake_session, tenant_id: str
    ) -> None:
        from foundation_lifecycle.services.storage_orphan_reconcile import (
            reconcile_orphans,
        )

        # Object exists but was just created → still within grace, skip
        recent = _FakeObjectMeta(
            f"tenants/{tenant_id}/workspaces/ws_1/files/fil_RECENT/x.pdf",
            last_modified=_stale(1),  # 1 day old; grace=7
        )
        fake_session.queue_scalars([_quota_row(tenant_id, "workspace")])
        client = _FakeStorageClient(
            objects_per_tenant={(tenant_id, "workspace"): [recent]}
        )

        report = await reconcile_orphans(
            fake_session, client, dry_run=False, grace_period_days=7
        )

        assert report.direction_a_orphans == 0
        assert client.deleted == []

    async def test_orphan_object_dry_run_reports_but_does_not_delete(
        self, fake_session, tenant_id: str
    ) -> None:
        from foundation_lifecycle.services.storage_orphan_reconcile import (
            reconcile_orphans,
        )

        stale_obj = _FakeObjectMeta(
            f"tenants/{tenant_id}/workspaces/ws_1/files/fil_ORPHAN/old.pdf",
            last_modified=_stale(30),
        )
        fake_session.queue_scalars([_quota_row(tenant_id, "workspace")])
        # session.scalar(RecycleBin lookup) returns None → object has no record
        fake_session.queue_scalar(None)
        client = _FakeStorageClient(
            objects_per_tenant={(tenant_id, "workspace"): [stale_obj]}
        )

        report = await reconcile_orphans(
            fake_session, client, dry_run=True, grace_period_days=7
        )

        assert report.direction_a_orphans == 1
        assert report.direction_a_deleted == 0  # dry run: counted but untouched
        assert client.deleted == []

    async def test_orphan_object_live_run_deletes(
        self, fake_session, tenant_id: str
    ) -> None:
        from foundation_lifecycle.services.storage_orphan_reconcile import (
            reconcile_orphans,
        )

        stale_obj = _FakeObjectMeta(
            f"tenants/{tenant_id}/workspaces/ws_1/files/fil_KILLME/old.pdf",
            last_modified=_stale(30),
        )
        fake_session.queue_scalars([_quota_row(tenant_id, "workspace")])
        fake_session.queue_scalar(None)
        client = _FakeStorageClient(
            objects_per_tenant={(tenant_id, "workspace"): [stale_obj]}
        )

        report = await reconcile_orphans(
            fake_session, client, dry_run=False, grace_period_days=7
        )

        assert report.direction_a_orphans == 1
        assert report.direction_a_deleted == 1
        assert client.deleted == [stale_obj.key]

    async def test_object_with_matching_recycle_bin_record_is_not_orphan(
        self, fake_session, tenant_id: str
    ) -> None:
        from foundation_lifecycle.services.storage_orphan_reconcile import (
            reconcile_orphans,
        )

        stale_obj = _FakeObjectMeta(
            f"tenants/{tenant_id}/workspaces/ws_1/files/fil_LEGIT/x.pdf",
            last_modified=_stale(30),
        )
        fake_session.queue_scalars([_quota_row(tenant_id, "workspace")])
        # recycle_bin has a row → existing != None → skip
        fake_session.queue_scalar(
            RecycleBin(
                id="bin_01",
                tenant_id=tenant_id,
                resource_type_id="rt_security_ops_scan",
                resource_id="fil_LEGIT",
                resource_name="x.pdf",
                deleted_by="usr_x",
                deleted_at=_stale(2),
                expires_at=_stale(-30),
            )
        )
        client = _FakeStorageClient(
            objects_per_tenant={(tenant_id, "workspace"): [stale_obj]}
        )

        report = await reconcile_orphans(
            fake_session, client, dry_run=False, grace_period_days=7
        )

        assert report.direction_a_orphans == 0
        assert client.deleted == []


class TestOrphanDirectionB:
    """recycle_bin says it's hard-deleted but the S3 object is still there
    (or vice versa) — emit data-missing warning."""

    async def test_no_recycle_bin_rows_returns_zero(
        self, fake_session, tenant_id: str
    ) -> None:
        from foundation_lifecycle.services.storage_orphan_reconcile import (
            reconcile_orphans,
        )

        # Direction A: no quota rows → no work
        fake_session.queue_scalars([])
        # Direction B: no recycle_bin rows
        fake_session.queue_scalars([])
        client = _FakeStorageClient()

        report = await reconcile_orphans(
            fake_session, client, dry_run=True, grace_period_days=7
        )

        assert report.direction_b_missing == 0
