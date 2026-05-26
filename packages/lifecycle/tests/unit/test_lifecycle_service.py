"""Unit tests for LifecycleService — soft-delete, restore, hard-delete, sweep."""

from __future__ import annotations
from datetime import UTC, datetime, timedelta

import pytest

from foundation_lifecycle.domain.models import LegalHold, RecycleBin, ResourceType
from foundation_lifecycle.errors import LEGAL_HOLD_ACTIVE, RESOURCE_NOT_IN_BIN, RESOURCE_TYPE_NOT_FOUND, FoundationError
from foundation_lifecycle.services.lifecycle_service import LifecycleService

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
