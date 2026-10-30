"""Four-eyes approval of hard-delete and legal-hold release (lifecycle-v1 §4.4).

Purging an entry before its time and releasing a legal hold each take two people
(lifecycle-v1 §4.1, §4.2, §5): the second approves and witnesses through a request
of their own (pam-v1 §4), never the requester (pam-v1 §14 #4). Asking for either
operation therefore only opens an approval request. It takes effect when another
user approves it within the approval window; the requester is recorded as who
destroyed or released, and the approver as the witness on the destruction
certificate.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import ulid
from sqlalchemy import ColumnElement, and_, or_, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_lifecycle.domain.models import ApprovalRequest, LegalHold, Outbox, RecycleBin
from foundation_lifecycle.errors import (
    APPROVAL_NOT_PENDING,
    APPROVAL_REQUEST_NOT_FOUND,
    LEGAL_HOLD_ACTIVE,
    LEGAL_HOLD_NOT_FOUND,
    RESOURCE_NOT_IN_BIN,
    SELF_APPROVAL_FORBIDDEN,
    FoundationError,
)
from foundation_lifecycle.services.legal_hold_service import LegalHoldService
from foundation_lifecycle.services.lifecycle_service import LifecycleService
from foundation_lifecycle.services.pagination import decode_cursor, encode_cursor

_APPROVAL_ID_PREFIX = "apr_"

HARD_DELETE = "HARD_DELETE"
RELEASE_LEGAL_HOLD = "RELEASE_LEGAL_HOLD"

PENDING = "PENDING"
APPROVED = "APPROVED"
REJECTED = "REJECTED"
EXPIRED = "EXPIRED"


def effective_status(req: ApprovalRequest, now: datetime) -> str:
    """The stored status, except ``EXPIRED`` for a pending request whose window has closed.

    Nothing has to run for a request to expire: its row still says ``PENDING`` until
    a new request for the same target replaces it.
    """
    return EXPIRED if req.status == PENDING and req.expires_at <= now else req.status


def _has_status(status: str, now: datetime) -> ColumnElement[bool]:
    """SQL for "the effective status is ``status``" (see :func:`effective_status`)."""
    stored_pending = ApprovalRequest.status == PENDING
    if status == PENDING:
        return and_(stored_pending, ApprovalRequest.expires_at > now)
    if status == EXPIRED:
        return or_(ApprovalRequest.status == EXPIRED,
                   and_(stored_pending, ApprovalRequest.expires_at <= now))
    return ApprovalRequest.status == status


class ApprovalService:
    """Open, approve, reject and list four-eyes approval requests."""

    def __init__(self, *, lifecycle: LifecycleService, holds: LegalHoldService,
                 window: timedelta) -> None:
        self._lifecycle = lifecycle
        self._holds = holds
        self._window = window

    # ------------------------------------------------------------------ Request
    async def request_hard_delete(
        self, session: AsyncSession, *, tenant_id: str, bin_id: str,
        requested_by: str, request_id: str,
    ) -> ApprovalRequest | None:
        """Ask a second person to approve destroying a recycle-bin entry.

        Returns the entry's open request (the one already open, whoever opened it), or
        None if the entry is already destroyed. Refused as the destruction would be: an
        entry not in this tenant's bin is a 404, one under a legal hold a 409.
        """
        # FOR UPDATE: two people asking at once get one request, not a unique-index error.
        entry = await session.get(RecycleBin, bin_id, with_for_update=True)
        if entry is None or entry.tenant_id != tenant_id or entry.restored_at is not None:
            raise FoundationError(RESOURCE_NOT_IN_BIN, extra={"bin_id": bin_id})
        if entry.hard_deleted_at is not None:
            return None
        if await self._holds.check(session, tenant_id=tenant_id,
                                   resource_type_id=entry.resource_type_id,
                                   resource_id=entry.resource_id):
            raise FoundationError(LEGAL_HOLD_ACTIVE, extra={"resource_id": entry.resource_id})
        return await self._open(session, tenant_id=tenant_id, operation=HARD_DELETE,
                                target_id=bin_id, requested_by=requested_by, request_id=request_id)

    async def request_release(
        self, session: AsyncSession, *, tenant_id: str, hold_id: str,
        requested_by: str, request_id: str,
    ) -> ApprovalRequest | None:
        """Ask a second person to approve releasing a legal hold.

        Returns the hold's open request, or None if the hold is already released.
        """
        hold = await session.get(LegalHold, hold_id, with_for_update=True)
        if hold is None or hold.tenant_id != tenant_id:
            raise FoundationError(LEGAL_HOLD_NOT_FOUND, extra={"hold_id": hold_id})
        if hold.released_at is not None:
            return None
        return await self._open(session, tenant_id=tenant_id, operation=RELEASE_LEGAL_HOLD,
                                target_id=hold_id, requested_by=requested_by, request_id=request_id)

    # ------------------------------------------------------------------ Decide
    async def approve(
        self, session: AsyncSession, *, tenant_id: str, approval_id: str,
        approved_by: str, request_id: str,
    ) -> ApprovalRequest:
        """Approve as the second person, which carries the operation out now.

        The requester is recorded as who destroyed or released; the approver is the
        witness the destruction certificate names. The operation's own checks run
        again, so a legal hold placed meanwhile still blocks the destruction (409) and
        the request stays open.
        """
        req = await self._pending(session, tenant_id=tenant_id, approval_id=approval_id)
        if approved_by == req.requested_by:
            raise FoundationError(SELF_APPROVAL_FORBIDDEN, extra={"approval_request_id": req.id})
        if req.operation == HARD_DELETE:
            await self._lifecycle.hard_delete(
                session, tenant_id=tenant_id, bin_id=req.target_id,
                destroyed_by=req.requested_by, witness_user_id=approved_by,
                request_id=request_id)
        else:
            await self._holds.release(
                session, tenant_id=tenant_id, hold_id=req.target_id,
                released_by=req.requested_by, request_id=request_id)
        return await self._decide(session, req, status=APPROVED, decided_by=approved_by,
                                  request_id=request_id)

    async def reject(
        self, session: AsyncSession, *, tenant_id: str, approval_id: str,
        rejected_by: str, request_id: str,
    ) -> ApprovalRequest:
        """Turn the request down. Anyone may, the requester too (withdrawing it)."""
        req = await self._pending(session, tenant_id=tenant_id, approval_id=approval_id)
        return await self._decide(session, req, status=REJECTED, decided_by=rejected_by,
                                  request_id=request_id)

    # ------------------------------------------------------------------ Query
    async def get(
        self, session: AsyncSession, *, tenant_id: str, approval_id: str,
    ) -> ApprovalRequest:
        req = await session.get(ApprovalRequest, approval_id)
        if req is None or req.tenant_id != tenant_id:
            raise FoundationError(APPROVAL_REQUEST_NOT_FOUND,
                                  extra={"approval_request_id": approval_id})
        return req

    async def list_requests(
        self, session: AsyncSession, *, tenant_id: str,
        status: str | None = None, operation: str | None = None,
        cursor: str | None = None, limit: int = 50,
    ) -> tuple[list[ApprovalRequest], str | None]:
        """Requests, newest first, keyset-paged on (requested_at, id); see services.pagination.

        ``status`` matches the effective status, so ``PENDING`` leaves out requests
        whose window has closed and ``EXPIRED`` includes them.
        """
        stmt = select(ApprovalRequest).where(ApprovalRequest.tenant_id == tenant_id)
        if status is not None:
            stmt = stmt.where(_has_status(status, datetime.now(UTC)))
        if operation is not None:
            stmt = stmt.where(ApprovalRequest.operation == operation)
        if cursor:
            requested_at, approval_id = decode_cursor(cursor, id_prefix=_APPROVAL_ID_PREFIX)
            stmt = stmt.where(tuple_(ApprovalRequest.requested_at, ApprovalRequest.id)
                              < (requested_at, approval_id))
        stmt = stmt.order_by(ApprovalRequest.requested_at.desc(),
                             ApprovalRequest.id.desc()).limit(limit + 1)
        rows = list((await session.scalars(stmt)).all())
        page = rows[:limit]
        # The cursor is the sort key of the last row *returned*, never the lookahead row's.
        next_cursor = (encode_cursor(page[-1].requested_at, page[-1].id)
                       if len(rows) > limit else None)
        return page, next_cursor

    # ------------------------------------------------------------------ Helpers
    async def _open(
        self, session: AsyncSession, *, tenant_id: str, operation: str, target_id: str,
        requested_by: str, request_id: str,
    ) -> ApprovalRequest:
        now = datetime.now(UTC)
        open_req = await session.scalar(
            select(ApprovalRequest).where(
                ApprovalRequest.tenant_id == tenant_id,
                ApprovalRequest.operation == operation,
                ApprovalRequest.target_id == target_id,
                ApprovalRequest.status == PENDING,
            ).limit(1)
        )
        if open_req is not None:
            if effective_status(open_req, now) == PENDING:
                return open_req
            # Its window closed with nobody approving it; this request takes its place.
            open_req.status = EXPIRED
            await session.flush()  # before the insert: the unique index allows one PENDING row
        req = ApprovalRequest(
            id=f"{_APPROVAL_ID_PREFIX}{ulid.new()!s}",
            tenant_id=tenant_id,
            operation=operation,
            target_id=target_id,
            requested_by=requested_by,
            requested_at=now,
            expires_at=now + self._window,
            status=PENDING,
        )
        session.add(req)
        self._emit(session, req, "foundation.lifecycle.approval.requested", request_id)
        await session.flush()
        return req

    async def _pending(
        self, session: AsyncSession, *, tenant_id: str, approval_id: str,
    ) -> ApprovalRequest:
        # FOR UPDATE: two decisions on one request are taken one after the other, so the
        # second finds it decided instead of destroying or releasing a second time.
        req = await session.get(ApprovalRequest, approval_id, with_for_update=True)
        if req is None or req.tenant_id != tenant_id:
            raise FoundationError(APPROVAL_REQUEST_NOT_FOUND,
                                  extra={"approval_request_id": approval_id})
        status = effective_status(req, datetime.now(UTC))
        if status != PENDING:
            raise FoundationError(APPROVAL_NOT_PENDING,
                                  extra={"approval_request_id": approval_id, "status": status})
        return req

    async def _decide(
        self, session: AsyncSession, req: ApprovalRequest, *, status: str, decided_by: str,
        request_id: str,
    ) -> ApprovalRequest:
        req.status = status
        req.decided_by = decided_by
        req.decided_at = datetime.now(UTC)
        self._emit(session, req, f"foundation.lifecycle.approval.{status.lower()}", request_id)
        await session.flush()
        return req

    def _emit(self, session: AsyncSession, req: ApprovalRequest, event_type: str,
              request_id: str) -> None:
        session.add(Outbox(
            tenant_id=req.tenant_id, event_type=event_type, aggregate_id=req.id,
            payload={"approval_request_id": req.id, "operation": req.operation,
                     "target_id": req.target_id, "requested_by": req.requested_by,
                     "decided_by": req.decided_by},
            request_id=request_id,
        ))
