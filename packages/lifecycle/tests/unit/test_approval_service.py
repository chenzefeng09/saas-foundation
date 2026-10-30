"""Unit tests for ApprovalService — four-eyes hard-delete and legal-hold release.

The services that carry an approved request out are the real ones, so each test
checks what actually happened to the entry, the hold and the certificate.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy.dialects import postgresql

from foundation_lifecycle.domain.models import (
    ApprovalRequest,
    DestructionCertificate,
    LegalHold,
    Outbox,
    RecycleBin,
)
from foundation_lifecycle.errors import (
    APPROVAL_NOT_PENDING,
    APPROVAL_REQUEST_NOT_FOUND,
    LEGAL_HOLD_ACTIVE,
    LEGAL_HOLD_NOT_FOUND,
    RESOURCE_NOT_IN_BIN,
    SELF_APPROVAL_FORBIDDEN,
    VALIDATION_FAILED,
    FoundationError,
)
from foundation_lifecycle.services.approval_service import ApprovalService, effective_status
from foundation_lifecycle.services.legal_hold_service import LegalHoldService
from foundation_lifecycle.services.lifecycle_service import LifecycleService
from foundation_lifecycle.services.pagination import decode_cursor, encode_cursor

from tests._factories import (
    make_approval_request,
    make_legal_hold,
    make_recycle_bin_entry,
    make_resource_type,
)

REQUESTER = "usr_01J0000000000000000000REQ1"
APPROVER = "usr_01J0000000000000000000APR1"
OTHER_TENANT = "tnt_01J0000000000000000000TNT2"
WINDOW = timedelta(minutes=30)
_LONG_AGO = datetime.now(UTC) - timedelta(hours=2)  # a request opened then has expired
_T0 = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
_TICK = timedelta(seconds=1)


@pytest.fixture
def svc() -> ApprovalService:
    return ApprovalService(lifecycle=LifecycleService(), holds=LegalHoldService(), window=WINDOW)


def _of(session: Any, model: type) -> list[Any]:
    return [obj for obj in session.added if isinstance(obj, model)]


def _events(session: Any) -> list[str]:
    return [o.event_type for o in _of(session, Outbox)]


def _targets(tenant_id: str) -> tuple[RecycleBin, LegalHold]:
    return make_recycle_bin_entry(tenant_id=tenant_id), make_legal_hold(tenant_id=tenant_id)


def _request_on(
    operation: str, entry: RecycleBin, hold: LegalHold, **kwargs: Any,
) -> ApprovalRequest:
    target = entry.id if operation == "HARD_DELETE" else hold.id
    return make_approval_request(tenant_id=entry.tenant_id, operation=operation, target_id=target,
                                 requested_by=REQUESTER, **kwargs)


class TestRequestHardDelete:
    async def test_opens_a_pending_request_and_destroys_nothing(
        self, svc: ApprovalService, fake_session, tenant_id: str, request_id: str,
    ) -> None:
        entry = make_recycle_bin_entry(tenant_id=tenant_id)
        fake_session.put(entry)

        req = await svc.request_hard_delete(fake_session, tenant_id=tenant_id, bin_id=entry.id,
                                            requested_by=REQUESTER, request_id=request_id)

        assert req is not None
        assert (req.operation, req.target_id, req.requested_by, req.status) == (
            "HARD_DELETE", entry.id, REQUESTER, "PENDING")
        assert req.id.startswith("apr_")
        assert len(req.id) == 30
        assert req.expires_at - req.requested_at == WINDOW
        assert (req.decided_by, req.decided_at) == (None, None)
        assert entry.hard_deleted_at is None
        assert _of(fake_session, ApprovalRequest) == [req]
        assert _of(fake_session, DestructionCertificate) == []
        assert _events(fake_session) == ["foundation.lifecycle.approval.requested"]
        # Locked, so two people asking at once wait for each other and get one request.
        assert fake_session.locked == [(RecycleBin, entry.id)]

    async def test_asking_again_returns_the_open_request_whoever_asks(
        self, svc: ApprovalService, fake_session, tenant_id: str, request_id: str,
    ) -> None:
        entry = make_recycle_bin_entry(tenant_id=tenant_id)
        fake_session.put(entry)
        open_req = make_approval_request(tenant_id=tenant_id, target_id=entry.id,
                                         requested_by=REQUESTER)
        fake_session.queue_scalar(None)  # no legal hold
        fake_session.queue_scalar(open_req)  # the entry's open request

        req = await svc.request_hard_delete(fake_session, tenant_id=tenant_id, bin_id=entry.id,
                                            requested_by=APPROVER, request_id=request_id)

        assert req is open_req
        assert req.requested_by == REQUESTER  # asking again does not make it anyone else's
        assert _of(fake_session, ApprovalRequest) == []
        assert _events(fake_session) == []

    async def test_an_open_request_past_its_window_is_marked_expired_and_replaced(
        self, svc: ApprovalService, fake_session, tenant_id: str, request_id: str,
    ) -> None:
        entry = make_recycle_bin_entry(tenant_id=tenant_id)
        fake_session.put(entry)
        stale = make_approval_request(tenant_id=tenant_id, target_id=entry.id,
                                      requested_by=REQUESTER, requested_at=_LONG_AGO)
        fake_session.queue_scalar(None)  # no legal hold
        fake_session.queue_scalar(stale)

        req = await svc.request_hard_delete(fake_session, tenant_id=tenant_id, bin_id=entry.id,
                                            requested_by=APPROVER, request_id=request_id)

        assert stale.status == "EXPIRED"
        assert req is not stale
        assert (req.status, req.requested_by) == ("PENDING", APPROVER)
        assert _of(fake_session, ApprovalRequest) == [req]

    @pytest.mark.parametrize("state", ["missing", "other-tenant", "restored"])
    async def test_an_entry_not_in_the_bin_is_refused(
        self, svc: ApprovalService, fake_session, tenant_id: str, request_id: str, state: str,
    ) -> None:
        entry = make_recycle_bin_entry(
            tenant_id=OTHER_TENANT if state == "other-tenant" else tenant_id)
        if state == "restored":
            entry.restored_at = datetime.now(UTC)
        if state != "missing":
            fake_session.put(entry)

        with pytest.raises(FoundationError) as exc:
            await svc.request_hard_delete(fake_session, tenant_id=tenant_id, bin_id=entry.id,
                                          requested_by=REQUESTER, request_id=request_id)

        assert exc.value.error_code is RESOURCE_NOT_IN_BIN
        assert _of(fake_session, ApprovalRequest) == []

    async def test_an_entry_already_destroyed_needs_no_request(
        self, svc: ApprovalService, fake_session, tenant_id: str, request_id: str,
    ) -> None:
        entry = make_recycle_bin_entry(tenant_id=tenant_id)
        entry.hard_deleted_at = datetime.now(UTC)
        fake_session.put(entry)

        req = await svc.request_hard_delete(fake_session, tenant_id=tenant_id, bin_id=entry.id,
                                            requested_by=REQUESTER, request_id=request_id)

        assert req is None
        assert _of(fake_session, ApprovalRequest) == []

    async def test_an_entry_under_a_legal_hold_is_refused(
        self, svc: ApprovalService, fake_session, tenant_id: str, request_id: str,
    ) -> None:
        entry = make_recycle_bin_entry(tenant_id=tenant_id)
        fake_session.put(entry)
        fake_session.queue_scalar(make_legal_hold(tenant_id=tenant_id))

        with pytest.raises(FoundationError) as exc:
            await svc.request_hard_delete(fake_session, tenant_id=tenant_id, bin_id=entry.id,
                                          requested_by=REQUESTER, request_id=request_id)

        assert exc.value.error_code is LEGAL_HOLD_ACTIVE
        assert _of(fake_session, ApprovalRequest) == []


class TestRequestRelease:
    async def test_opens_a_pending_request_and_the_hold_stays_active(
        self, svc: ApprovalService, fake_session, tenant_id: str, request_id: str,
    ) -> None:
        hold = make_legal_hold(tenant_id=tenant_id)
        fake_session.put(hold)

        req = await svc.request_release(fake_session, tenant_id=tenant_id, hold_id=hold.id,
                                        requested_by=REQUESTER, request_id=request_id)

        assert req is not None
        assert (req.operation, req.target_id, req.requested_by, req.status) == (
            "RELEASE_LEGAL_HOLD", hold.id, REQUESTER, "PENDING")
        assert (hold.released_at, hold.released_by) == (None, None)
        assert fake_session.locked == [(LegalHold, hold.id)]

    async def test_a_hold_already_released_needs_no_request(
        self, svc: ApprovalService, fake_session, tenant_id: str, request_id: str,
    ) -> None:
        hold = make_legal_hold(tenant_id=tenant_id)
        hold.released_at = datetime.now(UTC)
        fake_session.put(hold)

        req = await svc.request_release(fake_session, tenant_id=tenant_id, hold_id=hold.id,
                                        requested_by=REQUESTER, request_id=request_id)

        assert req is None
        assert _of(fake_session, ApprovalRequest) == []

    @pytest.mark.parametrize("state", ["missing", "other-tenant"])
    async def test_a_hold_not_in_this_tenant_is_refused(
        self, svc: ApprovalService, fake_session, tenant_id: str, request_id: str, state: str,
    ) -> None:
        if state == "other-tenant":
            fake_session.put(make_legal_hold(tenant_id=OTHER_TENANT))

        with pytest.raises(FoundationError) as exc:
            await svc.request_release(fake_session, tenant_id=tenant_id, hold_id="lhd_test1",
                                      requested_by=REQUESTER, request_id=request_id)

        assert exc.value.error_code is LEGAL_HOLD_NOT_FOUND
        assert _of(fake_session, ApprovalRequest) == []


class TestApprove:
    async def test_another_user_approves_and_the_entry_is_destroyed_with_them_as_witness(
        self, svc: ApprovalService, fake_session, tenant_id: str, request_id: str,
    ) -> None:
        rt = make_resource_type(requires_cert=True)
        entry = make_recycle_bin_entry(tenant_id=tenant_id, resource_type_id=rt.id)
        req = make_approval_request(tenant_id=tenant_id, target_id=entry.id, requested_by=REQUESTER)
        for obj in (rt, entry, req):
            fake_session.put(obj)

        approved = await svc.approve(fake_session, tenant_id=tenant_id, approval_id=req.id,
                                     approved_by=APPROVER, request_id=request_id)

        assert approved is req
        assert (req.status, req.decided_by) == ("APPROVED", APPROVER)
        assert req.decided_at is not None
        assert entry.hard_deleted_at is not None
        (cert,) = _of(fake_session, DestructionCertificate)
        assert (cert.destroyed_by, cert.witness_user_id) == (REQUESTER, APPROVER)
        assert _events(fake_session) == [
            "foundation.lifecycle.hard_deleted", "foundation.lifecycle.approval.approved"]
        # Locked, so a second decision arriving at once finds it decided.
        assert fake_session.locked == [(ApprovalRequest, req.id)]

    async def test_another_user_approves_and_the_hold_is_released_as_the_requester_asked(
        self, svc: ApprovalService, fake_session, tenant_id: str, request_id: str,
    ) -> None:
        hold = make_legal_hold(tenant_id=tenant_id)
        req = make_approval_request(tenant_id=tenant_id, operation="RELEASE_LEGAL_HOLD",
                                    target_id=hold.id, requested_by=REQUESTER)
        fake_session.put(hold)
        fake_session.put(req)

        await svc.approve(fake_session, tenant_id=tenant_id, approval_id=req.id,
                          approved_by=APPROVER, request_id=request_id)

        assert hold.released_at is not None
        assert hold.released_by == REQUESTER
        assert (req.status, req.decided_by) == ("APPROVED", APPROVER)
        assert _events(fake_session) == [
            "foundation.lifecycle.legal_hold.released", "foundation.lifecycle.approval.approved"]

    @pytest.mark.parametrize("operation", ["HARD_DELETE", "RELEASE_LEGAL_HOLD"])
    async def test_the_requester_cannot_approve_their_own_request(
        self, svc: ApprovalService, fake_session, tenant_id: str, request_id: str, operation: str,
    ) -> None:
        entry, hold = _targets(tenant_id)
        req = _request_on(operation, entry, hold)
        for obj in (entry, hold, req):
            fake_session.put(obj)

        with pytest.raises(FoundationError) as exc:
            await svc.approve(fake_session, tenant_id=tenant_id, approval_id=req.id,
                              approved_by=REQUESTER, request_id=request_id)

        assert exc.value.error_code is SELF_APPROVAL_FORBIDDEN
        assert (req.status, req.decided_by) == ("PENDING", None)
        assert entry.hard_deleted_at is None
        assert hold.released_at is None
        assert _of(fake_session, DestructionCertificate) == []

    @pytest.mark.parametrize(("stored", "requested_at", "seen_as"), [
        pytest.param("PENDING", _LONG_AGO, "EXPIRED", id="window-closed"),
        pytest.param("EXPIRED", _LONG_AGO, "EXPIRED", id="expired"),
        pytest.param("APPROVED", None, "APPROVED", id="approved"),
        pytest.param("REJECTED", None, "REJECTED", id="rejected"),
    ])
    async def test_a_request_no_longer_pending_cannot_be_approved(
        self, svc: ApprovalService, fake_session, tenant_id: str, request_id: str,
        stored: str, requested_at: datetime | None, seen_as: str,
    ) -> None:
        entry = make_recycle_bin_entry(tenant_id=tenant_id)
        req = make_approval_request(tenant_id=tenant_id, target_id=entry.id, requested_by=REQUESTER,
                                    status=stored, requested_at=requested_at)
        fake_session.put(entry)
        fake_session.put(req)

        with pytest.raises(FoundationError) as exc:
            await svc.approve(fake_session, tenant_id=tenant_id, approval_id=req.id,
                              approved_by=APPROVER, request_id=request_id)

        assert exc.value.error_code is APPROVAL_NOT_PENDING
        assert exc.value.extra["status"] == seen_as
        assert entry.hard_deleted_at is None

    @pytest.mark.parametrize("state", ["missing", "other-tenant"])
    async def test_a_request_not_in_this_tenant_is_not_found(
        self, svc: ApprovalService, fake_session, tenant_id: str, request_id: str, state: str,
    ) -> None:
        if state == "other-tenant":
            fake_session.put(make_approval_request(tenant_id=OTHER_TENANT, requested_by=REQUESTER))

        with pytest.raises(FoundationError) as exc:
            await svc.approve(fake_session, tenant_id=tenant_id, approval_id="apr_test1",
                              approved_by=APPROVER, request_id=request_id)

        assert exc.value.error_code is APPROVAL_REQUEST_NOT_FOUND

    async def test_a_legal_hold_placed_since_the_request_still_blocks_the_destruction(
        self, svc: ApprovalService, fake_session, tenant_id: str, request_id: str,
    ) -> None:
        entry = make_recycle_bin_entry(tenant_id=tenant_id)
        req = make_approval_request(tenant_id=tenant_id, target_id=entry.id, requested_by=REQUESTER)
        fake_session.put(entry)
        fake_session.put(req)
        fake_session.queue_scalar(make_legal_hold(tenant_id=tenant_id))  # what hard_delete finds

        with pytest.raises(FoundationError) as exc:
            await svc.approve(fake_session, tenant_id=tenant_id, approval_id=req.id,
                              approved_by=APPROVER, request_id=request_id)

        assert exc.value.error_code is LEGAL_HOLD_ACTIVE
        assert req.status == "PENDING"
        assert entry.hard_deleted_at is None

    @pytest.mark.parametrize("since", ["restored", "destroyed"])
    async def test_an_entry_restored_or_destroyed_since_the_request_is_left_alone(
        self, svc: ApprovalService, fake_session, tenant_id: str, request_id: str, since: str,
    ) -> None:
        rt = make_resource_type(requires_cert=True)
        entry = make_recycle_bin_entry(tenant_id=tenant_id, resource_type_id=rt.id)
        if since == "restored":
            entry.restored_at = datetime.now(UTC)
        else:  # by the retention sweep, which needs nobody's approval
            entry.hard_deleted_at = datetime.now(UTC)
        req = make_approval_request(tenant_id=tenant_id, target_id=entry.id, requested_by=REQUESTER)
        for obj in (rt, entry, req):
            fake_session.put(obj)

        with pytest.raises(FoundationError) as exc:
            await svc.approve(fake_session, tenant_id=tenant_id, approval_id=req.id,
                              approved_by=APPROVER, request_id=request_id)

        assert exc.value.error_code is RESOURCE_NOT_IN_BIN
        assert req.status == "PENDING"
        # No witness to a destruction it did not do.
        assert _of(fake_session, DestructionCertificate) == []


class TestReject:
    @pytest.mark.parametrize("rejected_by", [APPROVER, REQUESTER],
                             ids=["another-user", "the-requester"])
    async def test_rejecting_closes_the_request_without_acting(
        self, svc: ApprovalService, fake_session, tenant_id: str, request_id: str, rejected_by: str,
    ) -> None:
        entry = make_recycle_bin_entry(tenant_id=tenant_id)
        req = make_approval_request(tenant_id=tenant_id, target_id=entry.id, requested_by=REQUESTER)
        fake_session.put(entry)
        fake_session.put(req)

        await svc.reject(fake_session, tenant_id=tenant_id, approval_id=req.id,
                         rejected_by=rejected_by, request_id=request_id)

        assert (req.status, req.decided_by) == ("REJECTED", rejected_by)
        assert req.decided_at is not None
        assert entry.hard_deleted_at is None
        assert _events(fake_session) == ["foundation.lifecycle.approval.rejected"]
        assert fake_session.locked == [(ApprovalRequest, req.id)]

    async def test_a_rejected_request_cannot_be_approved_after(
        self, svc: ApprovalService, fake_session, tenant_id: str, request_id: str,
    ) -> None:
        entry = make_recycle_bin_entry(tenant_id=tenant_id)
        req = make_approval_request(tenant_id=tenant_id, target_id=entry.id, requested_by=REQUESTER)
        fake_session.put(entry)
        fake_session.put(req)
        await svc.reject(fake_session, tenant_id=tenant_id, approval_id=req.id,
                         rejected_by=APPROVER, request_id=request_id)

        with pytest.raises(FoundationError) as exc:
            await svc.approve(fake_session, tenant_id=tenant_id, approval_id=req.id,
                              approved_by=APPROVER, request_id=request_id)

        assert exc.value.error_code is APPROVAL_NOT_PENDING
        assert exc.value.extra["status"] == "REJECTED"
        assert entry.hard_deleted_at is None


class TestEffectiveStatus:
    def test_a_pending_request_expires_when_its_window_closes(self) -> None:
        req = make_approval_request(requested_at=_T0)

        assert effective_status(req, _T0 + WINDOW - _TICK) == "PENDING"
        assert effective_status(req, _T0 + WINDOW) == "EXPIRED"

    @pytest.mark.parametrize("status", ["APPROVED", "REJECTED", "EXPIRED"])
    def test_a_decided_request_keeps_its_status(self, status: str) -> None:
        req = make_approval_request(requested_at=_T0, status=status)

        assert effective_status(req, _T0 + 10 * WINDOW) == status


_COL = "lifecycle.approval_request"
_ORDER_BY = f"ORDER BY {_COL}.requested_at DESC, {_COL}.id DESC"
_AFTER = f"({_COL}.requested_at, {_COL}.id) < "


def _sql(stmt: Any) -> str:
    """Render a recorded SELECT as Postgres SQL, values inlined."""
    compiled = stmt.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True})
    return " ".join(str(compiled).split())


def _db_answer(
    reqs: list[ApprovalRequest], cursor: str | None, limit: int,
) -> list[ApprovalRequest]:
    """What list_requests' query returns: newest first, after ``cursor``, limit+1 rows."""
    ordered = sorted(reqs, key=lambda r: (r.requested_at, r.id), reverse=True)
    if cursor is not None:
        after = decode_cursor(cursor, id_prefix="apr_")
        ordered = [r for r in ordered if (r.requested_at, r.id) < after]
    return ordered[: limit + 1]


class TestQuery:
    async def test_get_does_not_show_another_tenants_request(
        self, svc: ApprovalService, fake_session, tenant_id: str,
    ) -> None:
        fake_session.put(make_approval_request(tenant_id=OTHER_TENANT))

        with pytest.raises(FoundationError) as exc:
            await svc.get(fake_session, tenant_id=tenant_id, approval_id="apr_test1")

        assert exc.value.error_code is APPROVAL_REQUEST_NOT_FOUND

    async def test_listing_pending_leaves_out_requests_whose_window_closed(
        self, svc: ApprovalService, fake_session, tenant_id: str,
    ) -> None:
        await svc.list_requests(fake_session, tenant_id=tenant_id, status="PENDING")

        (sql,) = (_sql(s) for s in fake_session.statements)
        assert f"{_COL}.tenant_id = '{tenant_id}'" in sql
        assert f"{_COL}.status = 'PENDING' AND {_COL}.expires_at > '" in sql

    async def test_listing_expired_takes_in_pending_requests_past_their_window(
        self, svc: ApprovalService, fake_session, tenant_id: str,
    ) -> None:
        await svc.list_requests(fake_session, tenant_id=tenant_id, status="EXPIRED")

        (sql,) = (_sql(s) for s in fake_session.statements)
        assert (f"({_COL}.status = 'EXPIRED' OR {_COL}.status = 'PENDING' "
                f"AND {_COL}.expires_at <= '") in sql

    async def test_listing_filters_by_status_and_operation(
        self, svc: ApprovalService, fake_session, tenant_id: str,
    ) -> None:
        await svc.list_requests(fake_session, tenant_id=tenant_id, status="APPROVED",
                                operation="RELEASE_LEGAL_HOLD")

        (sql,) = (_sql(s) for s in fake_session.statements)
        where = sql.split(" WHERE ", 1)[1]
        assert f"{_COL}.status = 'APPROVED'" in where
        assert f"{_COL}.operation = 'RELEASE_LEGAL_HOLD'" in where
        assert "expires_at" not in where  # a decided request does not expire

    async def test_listing_pages_through_every_request_once(
        self, svc: ApprovalService, fake_session, tenant_id: str,
    ) -> None:
        def opened(approval_id: str, ticks: int) -> ApprovalRequest:
            return make_approval_request(tenant_id=tenant_id, approval_id=approval_id,
                                         requested_at=_T0 + ticks * _TICK)

        reqs = [opened("apr_5", 0), opened("apr_1", 1), opened("apr_4", 1), opened("apr_2", 1),
                opened("apr_3", 2)]

        pages: list[list[ApprovalRequest]] = []
        cursor = None
        for _ in reqs:  # a cursor that never runs out fails below instead of looping
            fake_session.queue_scalars(_db_answer(reqs, cursor, limit=2))
            page, cursor = await svc.list_requests(fake_session, tenant_id=tenant_id,
                                                   cursor=cursor, limit=2)
            pages.append(page)
            if cursor is None:
                break

        assert cursor is None
        assert [[r.id for r in page] for page in pages] == [
            ["apr_3", "apr_4"], ["apr_2", "apr_1"], ["apr_5"],
        ]
        first, *later = (_sql(s) for s in fake_session.statements)
        assert _ORDER_BY in first
        assert _AFTER not in first
        for previous, sql in zip(pages[:-1], later, strict=True):
            last = previous[-1]  # each page resumes right after the last request shown
            assert _ORDER_BY in sql
            assert f"{_AFTER}('{last.requested_at}', '{last.id}')" in sql

    async def test_listing_rejects_a_cursor_it_did_not_issue(
        self, svc: ApprovalService, fake_session, tenant_id: str,
    ) -> None:
        with pytest.raises(FoundationError) as exc:
            await svc.list_requests(fake_session, tenant_id=tenant_id,
                                    cursor=encode_cursor(_T0, "bin_01J0000000000000000000BIN1"))

        assert exc.value.error_code is VALIDATION_FAILED
        assert fake_session.statements == []
