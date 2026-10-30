"""Unit tests for LegalHoldService."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy.dialects import postgresql

from foundation_lifecycle.domain.models import LegalHold
from foundation_lifecycle.errors import LEGAL_HOLD_NOT_FOUND, VALIDATION_FAILED, FoundationError
from foundation_lifecycle.services.legal_hold_service import LegalHoldService
from foundation_lifecycle.services.pagination import decode_cursor, encode_cursor

from tests._factories import make_legal_hold


@pytest.fixture
def svc() -> LegalHoldService:
    return LegalHoldService()


_T0 = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
_TICK = timedelta(seconds=1)
_ORDER_BY = "ORDER BY lifecycle.legal_hold.placed_at DESC, lifecycle.legal_hold.id DESC"
_AFTER = "(lifecycle.legal_hold.placed_at, lifecycle.legal_hold.id) < "


def _sql(stmt: Any) -> str:
    """Render a recorded SELECT as Postgres SQL, values inlined."""
    compiled = stmt.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True})
    return " ".join(str(compiled).split())


def _db_answer(holds: list[LegalHold], cursor: str | None, limit: int) -> list[LegalHold]:
    """What list_holds' query returns from ``holds``: newest first, after ``cursor``, limit+1."""
    ordered = sorted(holds, key=lambda h: (h.placed_at, h.id), reverse=True)
    if cursor is not None:
        after = decode_cursor(cursor, id_prefix="lhd_")
        ordered = [h for h in ordered if (h.placed_at, h.id) < after]
    return ordered[: limit + 1]


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

    async def test_list_holds_pages_through_every_hold_once(
        self, svc: LegalHoldService, fake_session, tenant_id: str,
    ) -> None:
        # Holds placed in one transaction share now(), and ids (ULIDs minted by the
        # app) need not sort like placed_at: paging must neither skip nor repeat one.
        holds = [
            make_legal_hold(hold_id="lhd_5", tenant_id=tenant_id, placed_at=_T0),
            make_legal_hold(hold_id="lhd_1", tenant_id=tenant_id, placed_at=_T0 + _TICK),
            make_legal_hold(hold_id="lhd_4", tenant_id=tenant_id, placed_at=_T0 + _TICK),
            make_legal_hold(hold_id="lhd_2", tenant_id=tenant_id, placed_at=_T0 + _TICK),
            make_legal_hold(hold_id="lhd_3", tenant_id=tenant_id, placed_at=_T0 + 2 * _TICK),
        ]

        pages: list[list[LegalHold]] = []
        cursor = None
        for _ in holds:  # a cursor that never runs out fails below instead of looping
            fake_session.queue_scalars(_db_answer(holds, cursor, limit=2))
            page, cursor = await svc.list_holds(
                fake_session, tenant_id=tenant_id, cursor=cursor, limit=2,
            )
            pages.append(page)
            if cursor is None:
                break

        assert cursor is None
        assert [[h.id for h in page] for page in pages] == [
            ["lhd_3", "lhd_4"], ["lhd_2", "lhd_1"], ["lhd_5"],
        ]
        first, *later = (_sql(s) for s in fake_session.statements)
        assert _ORDER_BY in first
        assert _AFTER not in first
        for previous, sql in zip(pages[:-1], later, strict=True):
            last = previous[-1]  # each page resumes right after the last hold shown
            assert _ORDER_BY in sql
            assert f"{_AFTER}('{last.placed_at}', '{last.id}')" in sql

    @pytest.mark.parametrize("filters", [
        {},
        {"resource_type_id": "user_data"},
        {"resource_id": "res_123"},
        {"resource_type_id": "user_data", "resource_id": "res_123"},
        {"resource_id": ""},  # an empty filter matches no resource; it must not mean "all holds"
    ])
    async def test_list_holds_narrows_to_the_requested_resource(
        self, svc: LegalHoldService, fake_session, tenant_id: str, filters: dict[str, str],
    ) -> None:
        await svc.list_holds(fake_session, tenant_id=tenant_id, **filters)

        (sql,) = (_sql(s) for s in fake_session.statements)
        assert f"lifecycle.legal_hold.tenant_id = '{tenant_id}'" in sql
        assert "lifecycle.legal_hold.released_at IS NULL" in sql
        assert _ORDER_BY in sql
        for column in ("resource_type_id", "resource_id"):
            predicate = f"lifecycle.legal_hold.{column} = "
            if column in filters:
                assert f"{predicate}'{filters[column]}'" in sql
            else:
                assert predicate not in sql

    async def test_list_holds_keeps_the_resource_filter_on_later_pages(
        self, svc: LegalHoldService, fake_session, tenant_id: str,
    ) -> None:
        cursor = encode_cursor(_T0, "lhd_2")

        await svc.list_holds(
            fake_session, tenant_id=tenant_id, resource_id="res_123", cursor=cursor, limit=2,
        )

        (sql,) = (_sql(s) for s in fake_session.statements)
        assert "lifecycle.legal_hold.resource_id = 'res_123'" in sql
        assert f"{_AFTER}('{_T0}', 'lhd_2')" in sql
        assert _ORDER_BY in sql

    @pytest.mark.parametrize("cursor", [
        "lhd_01J0000000000000000000HLD1",  # a bare id, what this list used to hand out
        encode_cursor(_T0, "bin_01J0000000000000000000BIN1"),  # the recycle bin's cursor
        "%%%",
    ])
    async def test_list_holds_rejects_a_cursor_it_did_not_issue(
        self, svc: LegalHoldService, fake_session, tenant_id: str, cursor: str,
    ) -> None:
        with pytest.raises(FoundationError) as exc:
            await svc.list_holds(fake_session, tenant_id=tenant_id, cursor=cursor)

        assert exc.value.error_code is VALIDATION_FAILED
        assert fake_session.statements == []
