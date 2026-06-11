"""Unit tests for StorageQuotaService."""

from __future__ import annotations

import pytest

from foundation_lifecycle.domain.models import TenantStorageQuota
from foundation_lifecycle.services.storage_quota_service import StorageQuotaService


@pytest.fixture
def svc() -> StorageQuotaService:
    return StorageQuotaService()


class TestUpsertQuota:
    async def test_creates_new_row_when_missing(
        self, svc: StorageQuotaService, fake_session, tenant_id: str
    ) -> None:
        # get_quota → no row
        fake_session.queue_scalar(None)

        row = await svc.upsert_quota(
            fake_session,
            tenant_id=tenant_id,
            bucket_purpose="workspace",
            limit_bytes=5_000,
            soft_warn_pct=70,
            actor="usr_admin",
        )

        assert row.id.startswith("sqt_")
        assert row.tenant_id == tenant_id
        assert row.bucket_purpose == "workspace"
        assert row.limit_bytes == 5_000
        assert row.soft_warn_pct == 70
        assert row.used_bytes == 0
        assert fake_session.flush_calls == 1

    async def test_default_limit_when_unset(
        self, svc: StorageQuotaService, fake_session, tenant_id: str
    ) -> None:
        fake_session.queue_scalar(None)

        row = await svc.upsert_quota(
            fake_session,
            tenant_id=tenant_id,
            bucket_purpose="kb_raw",
            actor="usr_admin",
        )
        assert row.limit_bytes == 10_737_418_240
        assert row.soft_warn_pct == 80

    async def test_patches_existing_row(
        self, svc: StorageQuotaService, fake_session, tenant_id: str
    ) -> None:
        existing = TenantStorageQuota(
            id="sqt_test",
            tenant_id=tenant_id,
            bucket_purpose="workspace",
            limit_bytes=1_000,
            used_bytes=500,
            soft_warn_pct=80,
        )
        fake_session.queue_scalar(existing)

        row = await svc.upsert_quota(
            fake_session,
            tenant_id=tenant_id,
            bucket_purpose="workspace",
            limit_bytes=9_999,
            actor="usr_admin",
        )

        assert row is existing
        assert row.limit_bytes == 9_999
        # used_bytes untouched — reconcile owns that field
        assert row.used_bytes == 500
        # soft_warn_pct unchanged (not in patch)
        assert row.soft_warn_pct == 80


class TestListQuotas:
    async def test_returns_all_rows_for_tenant(
        self, svc: StorageQuotaService, fake_session, tenant_id: str
    ) -> None:
        rows = [
            TenantStorageQuota(
                id="sqt_a",
                tenant_id=tenant_id,
                bucket_purpose="workspace",
                limit_bytes=1_000,
                used_bytes=10,
                soft_warn_pct=80,
            ),
            TenantStorageQuota(
                id="sqt_b",
                tenant_id=tenant_id,
                bucket_purpose="kb_raw",
                limit_bytes=2_000,
                used_bytes=20,
                soft_warn_pct=80,
            ),
        ]
        fake_session.queue_scalars(rows)

        out = await svc.list_quotas(fake_session, tenant_id=tenant_id)
        assert len(out) == 2
        assert {r.bucket_purpose for r in out} == {"workspace", "kb_raw"}


class TestSerialize:
    def test_serialize_shape(self) -> None:
        from datetime import UTC, datetime

        row = TenantStorageQuota(
            id="sqt_x",
            tenant_id="tnt_01",
            bucket_purpose="workspace",
            limit_bytes=1_000,
            used_bytes=500,
            soft_warn_pct=80,
            updated_at=datetime(2026, 6, 12, tzinfo=UTC),
        )
        out = StorageQuotaService.serialize(row)
        assert out == {
            "id": "sqt_x",
            "tenant_id": "tnt_01",
            "bucket_purpose": "workspace",
            "limit_bytes": 1_000,
            "used_bytes": 500,
            "soft_warn_pct": 80,
            "updated_at": "2026-06-12T00:00:00+00:00",
        }
