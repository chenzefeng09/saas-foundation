"""Unit tests for LargeAttachmentService (two-layer BOOLEAN admission)."""

from __future__ import annotations

import pytest

from foundation_lifecycle.domain.models import (
    TenantLargeAttachmentSetting,
    UserLargeAttachmentAllow,
)
from foundation_lifecycle.services.large_attachment_service import (
    LargeAttachmentService,
)


@pytest.fixture
def svc() -> LargeAttachmentService:
    return LargeAttachmentService()


class TestUpsertTenantSetting:
    async def test_creates_new_row_when_missing(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        fake_session.queue_scalar(None)  # get_tenant_setting → no row

        row = await svc.upsert_tenant_setting(
            fake_session,
            tenant_id=tenant_id,
            enabled=True,
            actor="usr_admin",
        )

        assert row.id.startswith("tla_")
        assert row.tenant_id == tenant_id
        assert row.large_attachment_enabled is True
        assert row.updated_by == "usr_admin"
        assert fake_session.flush_calls == 1

    async def test_patches_existing_row(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        existing = TenantLargeAttachmentSetting(
            id="tla_test",
            tenant_id=tenant_id,
            large_attachment_enabled=False,
            updated_by="usr_old",
        )
        fake_session.queue_scalar(existing)

        row = await svc.upsert_tenant_setting(
            fake_session,
            tenant_id=tenant_id,
            enabled=True,
            actor="usr_admin",
        )

        assert row is existing
        assert row.large_attachment_enabled is True
        assert row.updated_by == "usr_admin"


class TestUpsertUserAllow:
    async def test_creates_new_row_when_missing(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        fake_session.queue_scalar(None)  # get_user_allow → no row

        row = await svc.upsert_user_allow(
            fake_session,
            tenant_id=tenant_id,
            user_id="usr_42",
            allowed=True,
            actor="usr_admin",
        )

        assert row.id.startswith("ula_")
        assert row.tenant_id == tenant_id
        assert row.user_id == "usr_42"
        assert row.allowed is True
        assert fake_session.flush_calls == 1

    async def test_patches_existing_row(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        existing = UserLargeAttachmentAllow(
            id="ula_test",
            tenant_id=tenant_id,
            user_id="usr_42",
            allowed=True,
        )
        fake_session.queue_scalar(existing)

        row = await svc.upsert_user_allow(
            fake_session,
            tenant_id=tenant_id,
            user_id="usr_42",
            allowed=False,
            actor="usr_admin",
        )

        assert row is existing
        assert row.allowed is False
        assert row.updated_by == "usr_admin"


class TestListUserAllows:
    async def test_returns_all_rows_for_tenant(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        rows = [
            UserLargeAttachmentAllow(
                id="ula_a", tenant_id=tenant_id, user_id="usr_a", allowed=True
            ),
            UserLargeAttachmentAllow(
                id="ula_b", tenant_id=tenant_id, user_id="usr_b", allowed=False
            ),
        ]
        fake_session.queue_scalars(rows)

        out = await svc.list_user_allows(fake_session, tenant_id=tenant_id)
        assert len(out) == 2
        assert {r.user_id for r in out} == {"usr_a", "usr_b"}


class TestDeleteUserAllow:
    async def test_deletes_existing_row(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        existing = UserLargeAttachmentAllow(
            id="ula_x", tenant_id=tenant_id, user_id="usr_x", allowed=True
        )
        fake_session.queue_scalar(existing)

        deleted = await svc.delete_user_allow(
            fake_session, tenant_id=tenant_id, user_id="usr_x"
        )
        assert deleted is True
        assert existing in fake_session.deleted

    async def test_returns_false_when_missing(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        fake_session.queue_scalar(None)

        deleted = await svc.delete_user_allow(
            fake_session, tenant_id=tenant_id, user_id="usr_nope"
        )
        assert deleted is False
        assert fake_session.deleted == []


class TestResolveTruthTable:
    """allowed IFF tenant switch on AND user allow-row with allowed == true."""

    async def test_tenant_off_user_allowed_true_denied(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        # get_tenant_setting → off ; get_user_allow → allowed=True
        fake_session.queue_scalar(
            TenantLargeAttachmentSetting(
                id="tla_1", tenant_id=tenant_id, large_attachment_enabled=False
            )
        )
        fake_session.queue_scalar(
            UserLargeAttachmentAllow(
                id="ula_1", tenant_id=tenant_id, user_id="usr_1", allowed=True
            )
        )

        out = await svc.resolve(
            fake_session, tenant_id=tenant_id, user_id="usr_1"
        )
        assert out == {
            "allowed": False,
            "tenant_enabled": False,
            "user_allowed": True,
        }

    async def test_tenant_off_no_setting_row_denied(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        fake_session.queue_scalar(None)  # no tenant setting → off
        fake_session.queue_scalar(
            UserLargeAttachmentAllow(
                id="ula_1", tenant_id=tenant_id, user_id="usr_1", allowed=True
            )
        )

        out = await svc.resolve(
            fake_session, tenant_id=tenant_id, user_id="usr_1"
        )
        assert out["allowed"] is False
        assert out["tenant_enabled"] is False
        assert out["user_allowed"] is True

    async def test_tenant_on_no_user_row_denied(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        fake_session.queue_scalar(
            TenantLargeAttachmentSetting(
                id="tla_1", tenant_id=tenant_id, large_attachment_enabled=True
            )
        )
        fake_session.queue_scalar(None)  # no user allow row

        out = await svc.resolve(
            fake_session, tenant_id=tenant_id, user_id="usr_1"
        )
        assert out == {
            "allowed": False,
            "tenant_enabled": True,
            "user_allowed": False,
        }

    async def test_tenant_on_user_allowed_true_allowed(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        fake_session.queue_scalar(
            TenantLargeAttachmentSetting(
                id="tla_1", tenant_id=tenant_id, large_attachment_enabled=True
            )
        )
        fake_session.queue_scalar(
            UserLargeAttachmentAllow(
                id="ula_1", tenant_id=tenant_id, user_id="usr_1", allowed=True
            )
        )

        out = await svc.resolve(
            fake_session, tenant_id=tenant_id, user_id="usr_1"
        )
        assert out == {
            "allowed": True,
            "tenant_enabled": True,
            "user_allowed": True,
        }

    async def test_tenant_on_user_allowed_false_denied(
        self, svc: LargeAttachmentService, fake_session, tenant_id: str
    ) -> None:
        fake_session.queue_scalar(
            TenantLargeAttachmentSetting(
                id="tla_1", tenant_id=tenant_id, large_attachment_enabled=True
            )
        )
        fake_session.queue_scalar(
            UserLargeAttachmentAllow(
                id="ula_1", tenant_id=tenant_id, user_id="usr_1", allowed=False
            )
        )

        out = await svc.resolve(
            fake_session, tenant_id=tenant_id, user_id="usr_1"
        )
        assert out == {
            "allowed": False,
            "tenant_enabled": True,
            "user_allowed": False,
        }


class TestSerialize:
    def test_serialize_setting_shape(self) -> None:
        from datetime import UTC, datetime

        row = TenantLargeAttachmentSetting(
            id="tla_x",
            tenant_id="tnt_01",
            large_attachment_enabled=True,
            updated_at=datetime(2026, 6, 12, tzinfo=UTC),
            updated_by="usr_admin",
        )
        out = LargeAttachmentService.serialize_setting(row)
        assert out == {
            "id": "tla_x",
            "tenant_id": "tnt_01",
            "large_attachment_enabled": True,
            "updated_at": "2026-06-12T00:00:00+00:00",
            "updated_by": "usr_admin",
        }

    def test_serialize_allow_shape(self) -> None:
        from datetime import UTC, datetime

        row = UserLargeAttachmentAllow(
            id="ula_x",
            tenant_id="tnt_01",
            user_id="usr_1",
            allowed=False,
            updated_at=datetime(2026, 6, 12, tzinfo=UTC),
            updated_by="usr_admin",
        )
        out = LargeAttachmentService.serialize_allow(row)
        assert out == {
            "id": "ula_x",
            "tenant_id": "tnt_01",
            "user_id": "usr_1",
            "allowed": False,
            "updated_at": "2026-06-12T00:00:00+00:00",
            "updated_by": "usr_admin",
        }
