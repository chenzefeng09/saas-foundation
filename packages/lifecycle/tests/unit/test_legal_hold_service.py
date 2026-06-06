"""Unit tests for LegalHoldService."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from foundation_lifecycle.domain.models import LegalHold
from foundation_lifecycle.errors import LEGAL_HOLD_NOT_FOUND, FoundationError
from foundation_lifecycle.services.legal_hold_service import LegalHoldService


@pytest.fixture
def svc() -> LegalHoldService:
    return LegalHoldService()


class TestPlace:
    async def test_place_creates_hold_and_outbox(
        self, svc: LegalHoldService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        hold = await svc.place(
            fake_session,
            tenant_id=tenant_id,
            resource_type_id="user_data",
            resource_id="res_123",
            reason="Court order",
            placed_by=actor_id,
            case_reference="case-1",
            request_id=request_id,
        )

        assert hold.id.startswith("lhd_")
        assert hold.tenant_id == tenant_id
        assert hold.case_reference == "case-1"
        assert fake_session.flush_calls == 1


class TestRelease:
    async def test_release_marks_hold_released(
        self, svc: LegalHoldService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        hold = LegalHold(
            id="lhd_test",
            tenant_id=tenant_id,
            resource_type_id="user_data",
            resource_id="res_123",
            reason="Court order",
            placed_by="admin",
        )
        fake_session.put(hold)

        result = await svc.release(
            fake_session,
            tenant_id=tenant_id,
            hold_id=hold.id,
            released_by=actor_id,
            request_id=request_id,
        )

        assert result is hold
        assert hold.released_at is not None
        assert hold.released_by == actor_id

    async def test_release_already_released_noops(
        self, svc: LegalHoldService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        released_at = datetime.now(UTC)
        hold = LegalHold(
            id="lhd_released",
            tenant_id=tenant_id,
            resource_type_id="user_data",
            resource_id="res_123",
            reason="Court order",
            placed_by="admin",
            released_at=released_at,
            released_by="other",
        )
        fake_session.put(hold)

        result = await svc.release(
            fake_session,
            tenant_id=tenant_id,
            hold_id=hold.id,
            released_by=actor_id,
            request_id=request_id,
        )

        assert result is hold
        assert hold.released_at == released_at
        assert hold.released_by == "other"

    async def test_release_missing_raises(
        self, svc: LegalHoldService, fake_session, tenant_id: str, actor_id: str, request_id: str,
    ) -> None:
        with pytest.raises(FoundationError) as exc:
            await svc.release(
                fake_session,
                tenant_id=tenant_id,
                hold_id="lhd_missing",
                released_by=actor_id,
                request_id=request_id,
            )

        assert exc.value.error_code is LEGAL_HOLD_NOT_FOUND


class TestQueries:
    async def test_check_returns_true_for_active_hold(
        self, svc: LegalHoldService, fake_session, tenant_id: str,
    ) -> None:
        hold = LegalHold(
            id="lhd_active",
            tenant_id=tenant_id,
            resource_type_id="user_data",
            resource_id="res_123",
            reason="Court order",
            placed_by="admin",
        )
        fake_session.queue_scalar(hold)

        assert await svc.check(
            fake_session,
            tenant_id=tenant_id,
            resource_type_id="user_data",
            resource_id="res_123",
        ) is True

    async def test_list_holds_paginates(
        self, svc: LegalHoldService, fake_session, tenant_id: str,
    ) -> None:
        first = LegalHold(
            id="lhd_1",
            tenant_id=tenant_id,
            resource_type_id="user_data",
            resource_id="res_1",
            reason="Court order",
            placed_by="admin",
        )
        second = LegalHold(
            id="lhd_2",
            tenant_id=tenant_id,
            resource_type_id="user_data",
            resource_id="res_2",
            reason="Court order",
            placed_by="admin",
        )
        fake_session.queue_scalars([first, second])

        rows, cursor = await svc.list_holds(fake_session, tenant_id=tenant_id, limit=1)

        assert rows == [first]
        assert cursor == second.id
