"""Unit tests for LifecycleService — soft-delete, restore, hard-delete, sweep."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from foundation_lifecycle.domain.models import (
    DestructionCertificate,
    DestructionJob,
    LegalHold,
    RecycleBin,
    ResourceType,
    RetentionPolicyOverride,
)
from foundation_lifecycle.errors import LEGAL_HOLD_ACTIVE, RESOURCE_NOT_IN_BIN, RESOURCE_TYPE_NOT_FOUND, FoundationError
from foundation_lifecycle.services.lifecycle_service import LifecycleService
from foundation_storage.errors import (
    OBJECT_LOCKED,
    STORAGE_UNAVAILABLE,
    ObjectLockedError,
    StorageError,
)

from tests._factories import make_resource_type, make_recycle_bin_entry


@pytest.fixture
def svc() -> LifecycleService:
    return LifecycleService()


class TestSoftDelete:
    async def test_soft_delete_creates_bin_entry(self, svc: LifecycleService, fake_session, tenant_id: str, actor_id: str, request_id: str) -> None:
        rt = make_resource_type()
        fake_session.put(rt)
        # no legal hold
        fake_session.queue_scalar(None)
        fake_session.queue_scalar(None)  # no override

        entry = await svc.soft_delete(session=fake_session, tenant_id=tenant_id,
            resource_type_id=rt.id, resource_id="res_123", resource_name="test doc",
            deleted_by=actor_id, request_id=request_id)
        assert entry.resource_id == "res_123"
        assert entry.expires_at > datetime.now(UTC)

    async def test_soft_delete_unknown_type_raises(self, svc: LifecycleService, fake_session, tenant_id: str, actor_id: str, request_id: str) -> None:
        with pytest.raises(FoundationError) as exc:
            await svc.soft_delete(session=fake_session, tenant_id=tenant_id,
                resource_type_id="unknown", resource_id="x", resource_name=None,
                deleted_by=actor_id, request_id=request_id)
        assert exc.value.error_code is RESOURCE_TYPE_NOT_FOUND

    async def test_soft_delete_with_legal_hold_raises(self, svc: LifecycleService, fake_session, tenant_id: str, actor_id: str, request_id: str) -> None:
        rt = make_resource_type()
        fake_session.put(rt)
        hold = LegalHold(id="lhd_test", tenant_id=tenant_id, resource_type_id=rt.id,
                         resource_id="res_123", reason="Court order", placed_by="admin")
        fake_session.queue_scalar(hold)

        with pytest.raises(FoundationError) as exc:
            await svc.soft_delete(session=fake_session, tenant_id=tenant_id,
                resource_type_id=rt.id, resource_id="res_123", resource_name=None,
                deleted_by=actor_id, request_id=request_id)
        assert exc.value.error_code is LEGAL_HOLD_ACTIVE

    async def test_soft_delete_persists_s3_location_when_provided(
        self, svc: LifecycleService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        rt = make_resource_type()
        fake_session.put(rt)
        fake_session.queue_scalar(None)
        fake_session.queue_scalar(None)

        entry = await svc.soft_delete(
            session=fake_session, tenant_id=tenant_id,
            resource_type_id=rt.id, resource_id="res_s3",
            resource_name=None, deleted_by=actor_id, request_id=request_id,
            s3_location=["foundation-workspace::tenants/tnt/x/y.pdf"],
        )
        assert entry.original_location is not None
        assert json.loads(entry.original_location) == [
            "foundation-workspace::tenants/tnt/x/y.pdf"
        ]

    async def test_soft_delete_omits_original_location_when_none(
        self, svc: LifecycleService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        rt = make_resource_type()
        fake_session.put(rt)
        fake_session.queue_scalar(None)
        fake_session.queue_scalar(None)
        entry = await svc.soft_delete(
            session=fake_session, tenant_id=tenant_id,
            resource_type_id=rt.id, resource_id="res_no_s3",
            resource_name=None, deleted_by=actor_id, request_id=request_id,
            s3_location=None,
        )
        assert entry.original_location is None

    async def test_soft_delete_uses_retention_override(
        self, svc: LifecycleService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        rt = make_resource_type(recycle_bin_days=30)
        override = RetentionPolicyOverride(
            id="rpo_test",
            tenant_id=tenant_id,
            resource_type_id=rt.id,
            retention_days=None,
            recycle_bin_days=7,
        )
        fake_session.put(rt)
        fake_session.queue_scalar(None)  # no legal hold
        fake_session.queue_scalar(override)

        entry = await svc.soft_delete(
            session=fake_session,
            tenant_id=tenant_id,
            resource_type_id=rt.id,
            resource_id="res_override",
            resource_name=None,
            deleted_by=actor_id,
            request_id=request_id,
        )

        assert timedelta(days=6) < entry.expires_at - datetime.now(UTC) < timedelta(days=8)


class TestRestore:
    async def test_restore(self, svc: LifecycleService, fake_session, tenant_id: str, actor_id: str, request_id: str) -> None:
        entry = make_recycle_bin_entry(tenant_id=tenant_id)
        fake_session.put(entry)

        result = await svc.restore(session=fake_session, tenant_id=tenant_id,
            bin_id=entry.id, restored_by=actor_id, request_id=request_id)
        assert result.restored_at is not None

    async def test_restore_not_found(self, svc: LifecycleService, fake_session, tenant_id: str, actor_id: str, request_id: str) -> None:
        with pytest.raises(FoundationError) as exc:
            await svc.restore(session=fake_session, tenant_id=tenant_id,
                bin_id="bin_nonexistent", restored_by=actor_id, request_id=request_id)
        assert exc.value.error_code is RESOURCE_NOT_IN_BIN


class TestHardDelete:
    async def test_hard_delete(self, svc: LifecycleService, fake_session, tenant_id: str, actor_id: str, request_id: str) -> None:
        entry = make_recycle_bin_entry(tenant_id=tenant_id)
        fake_session.put(entry)
        fake_session.queue_scalar(None)  # no legal hold
        rt = make_resource_type()
        fake_session.put(rt)

        await svc.hard_delete(session=fake_session, tenant_id=tenant_id,
            bin_id=entry.id, destroyed_by=actor_id, witness_user_id=None, request_id=request_id)
        assert entry.hard_deleted_at is not None

    async def test_hard_delete_with_legal_hold_raises(
        self, svc: LifecycleService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        entry = make_recycle_bin_entry(tenant_id=tenant_id)
        hold = LegalHold(id="lhd_test", tenant_id=tenant_id, resource_type_id=entry.resource_type_id,
                         resource_id=entry.resource_id, reason="Court order", placed_by="admin")
        fake_session.put(entry)
        fake_session.queue_scalar(hold)

        with pytest.raises(FoundationError) as exc:
            await svc.hard_delete(session=fake_session, tenant_id=tenant_id,
                bin_id=entry.id, destroyed_by=actor_id, witness_user_id=None, request_id=request_id)

        assert exc.value.error_code is LEGAL_HOLD_ACTIVE

    async def test_hard_delete_generates_certificate_when_required(
        self, svc: LifecycleService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        rt = make_resource_type(requires_cert=True)
        rt.destruction_method = "crypto_key_destroy"
        entry = make_recycle_bin_entry(tenant_id=tenant_id, resource_type_id=rt.id)
        fake_session.put(entry)
        fake_session.put(rt)
        fake_session.queue_scalar(None)  # no legal hold

        await svc.hard_delete(session=fake_session, tenant_id=tenant_id,
            bin_id=entry.id, destroyed_by=actor_id, witness_user_id="usr_witness",
            request_id=request_id)

        certs = [obj for obj in fake_session.added if isinstance(obj, DestructionCertificate)]
        assert len(certs) == 1
        assert certs[0].witness_user_id == "usr_witness"
        assert certs[0].destruction_method == "crypto_key_destroy"

    async def test_hard_delete_already_destroyed_noops(
        self, svc: LifecycleService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        entry = make_recycle_bin_entry(tenant_id=tenant_id)
        entry.hard_deleted_at = datetime.now(UTC)
        fake_session.put(entry)

        await svc.hard_delete(session=fake_session, tenant_id=tenant_id,
            bin_id=entry.id, destroyed_by=actor_id, witness_user_id=None, request_id=request_id)

        assert fake_session.flush_calls == 0

    async def test_hard_delete_gcs_s3_objects(
        self, svc: LifecycleService, fake_session, tenant_id: str, actor_id: str, request_id: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Stub bucket map so parse_s3_location works without real ENV.
        from foundation_lifecycle.services import storage_location
        fake_settings = MagicMock()
        fake_settings.bucket_to_purpose_map.return_value = {
            "foundation-workspace": __import__(
                "foundation_storage"
            ).BucketPurpose.WORKSPACE,
        }
        monkeypatch.setattr(
            storage_location, "get_storage_settings", lambda: fake_settings
        )

        entry = make_recycle_bin_entry(
            tenant_id=tenant_id,
            original_location=json.dumps([
                "foundation-workspace::tenants/tnt_01/workspaces/ws_1/files/f_1/x.pdf"
            ]),
        )
        fake_session.put(entry)
        fake_session.queue_scalar(None)  # no legal hold
        rt = make_resource_type()
        fake_session.put(rt)

        storage_client = MagicMock()
        storage_client.delete_object = AsyncMock()

        await svc.hard_delete(
            session=fake_session, tenant_id=tenant_id, bin_id=entry.id,
            destroyed_by=actor_id, witness_user_id=None, request_id=request_id,
            storage_client=storage_client,
        )
        storage_client.delete_object.assert_awaited_once()
        assert entry.hard_deleted_at is not None

    async def test_hard_delete_object_locked_still_marks_db(
        self, svc: LifecycleService, fake_session, tenant_id: str, actor_id: str, request_id: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from foundation_lifecycle.services import storage_location
        fake_settings = MagicMock()
        fake_settings.bucket_to_purpose_map.return_value = {
            "foundation-audit": __import__("foundation_storage").BucketPurpose.AUDIT,
        }
        monkeypatch.setattr(
            storage_location, "get_storage_settings", lambda: fake_settings
        )

        entry = make_recycle_bin_entry(
            tenant_id=tenant_id,
            original_location=json.dumps([
                "foundation-audit::tenants/tnt_01/events/2026/01/01/00/e1.json"
            ]),
        )
        fake_session.put(entry)
        fake_session.queue_scalar(None)
        rt = make_resource_type()
        fake_session.put(rt)

        storage_client = MagicMock()
        storage_client.delete_object = AsyncMock(
            side_effect=ObjectLockedError(OBJECT_LOCKED, detail="WORM")
        )

        await svc.hard_delete(
            session=fake_session, tenant_id=tenant_id, bin_id=entry.id,
            destroyed_by=actor_id, witness_user_id=None, request_id=request_id,
            storage_client=storage_client,
        )
        assert entry.hard_deleted_at is not None

    async def test_hard_delete_generic_storage_error_still_marks_db(
        self, svc: LifecycleService, fake_session, tenant_id: str, actor_id: str, request_id: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from foundation_lifecycle.services import storage_location
        fake_settings = MagicMock()
        fake_settings.bucket_to_purpose_map.return_value = {
            "foundation-workspace": __import__(
                "foundation_storage"
            ).BucketPurpose.WORKSPACE,
        }
        monkeypatch.setattr(
            storage_location, "get_storage_settings", lambda: fake_settings
        )

        entry = make_recycle_bin_entry(
            tenant_id=tenant_id,
            original_location=json.dumps([
                "foundation-workspace::tenants/tnt_01/workspaces/ws_1/files/f_1/x.pdf"
            ]),
        )
        fake_session.put(entry)
        fake_session.queue_scalar(None)
        rt = make_resource_type()
        fake_session.put(rt)

        storage_client = MagicMock()
        storage_client.delete_object = AsyncMock(
            side_effect=StorageError(STORAGE_UNAVAILABLE, detail="boom")
        )

        await svc.hard_delete(
            session=fake_session, tenant_id=tenant_id, bin_id=entry.id,
            destroyed_by=actor_id, witness_user_id=None, request_id=request_id,
            storage_client=storage_client,
        )
        assert entry.hard_deleted_at is not None

    async def test_hard_delete_no_storage_client_skips_gc(
        self, svc: LifecycleService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        # original_location set but storage_client=None → must not crash.
        entry = make_recycle_bin_entry(
            tenant_id=tenant_id,
            original_location=json.dumps([
                "foundation-workspace::tenants/tnt_01/workspaces/ws_1/files/f_1/x.pdf"
            ]),
        )
        fake_session.put(entry)
        fake_session.queue_scalar(None)
        rt = make_resource_type()
        fake_session.put(rt)

        await svc.hard_delete(
            session=fake_session, tenant_id=tenant_id, bin_id=entry.id,
            destroyed_by=actor_id, witness_user_id=None, request_id=request_id,
        )
        assert entry.hard_deleted_at is not None


class TestSweep:
    async def test_sweep_expired(self, svc: LifecycleService, fake_session, tenant_id: str) -> None:
        expired = make_recycle_bin_entry(tenant_id=tenant_id, bin_id="bin_expired",
            expires_at=datetime.now(UTC) - timedelta(days=1))
        active = make_recycle_bin_entry(tenant_id=tenant_id, bin_id="bin_active",
            expires_at=datetime.now(UTC) + timedelta(days=30))
        fake_session.queue_scalars([expired])  # only expired
        fake_session.queue_scalar(None)  # no legal hold for expired

        count = await svc.sweep_expired(fake_session, limit=100)
        assert count >= 1

    async def test_sweep_skips_entries_with_legal_hold(
        self, svc: LifecycleService, fake_session, tenant_id: str,
    ) -> None:
        expired = make_recycle_bin_entry(
            tenant_id=tenant_id,
            bin_id="bin_expired_hold",
            expires_at=datetime.now(UTC) - timedelta(days=1),
        )
        hold = LegalHold(id="lhd_test", tenant_id=tenant_id, resource_type_id=expired.resource_type_id,
                         resource_id=expired.resource_id, reason="Court order", placed_by="admin")
        fake_session.queue_scalars([expired])
        fake_session.queue_scalar(hold)

        count = await svc.sweep_expired(fake_session, limit=100)

        assert count == 0
        assert expired.hard_deleted_at is None

    async def test_sweep_records_destruction_job(
        self, svc: LifecycleService, fake_session, tenant_id: str,
    ) -> None:
        expired = make_recycle_bin_entry(
            tenant_id=tenant_id,
            bin_id="bin_expired_job",
            expires_at=datetime.now(UTC) - timedelta(days=1),
        )
        fake_session.queue_scalars([expired])
        fake_session.queue_scalar(None)

        count = await svc.sweep_expired(fake_session, limit=100)

        jobs = [obj for obj in fake_session.added if isinstance(obj, DestructionJob)]
        assert count == 1
        assert jobs[0].resources_destroyed == 1


class TestListRecycleBin:
    async def test_list_recycle_bin_paginates(
        self, svc: LifecycleService, fake_session, tenant_id: str,
    ) -> None:
        first = make_recycle_bin_entry(tenant_id=tenant_id, bin_id="bin_1")
        second = make_recycle_bin_entry(tenant_id=tenant_id, bin_id="bin_2")
        fake_session.queue_scalars([first, second])

        rows, cursor = await svc.list_recycle_bin(
            fake_session,
            tenant_id=tenant_id,
            cursor="bin_0",
            limit=1,
        )

        assert rows == [first]
        assert cursor == second.id
