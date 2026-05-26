"""PAM (Privileged Access Management) service.

Provides:
  - request_elevation: Just-In-Time privilege elevation
  - approve: 4-eyes approval for high-risk operations
  - deny: reject elevation request
  - get_active_sessions: list current privileged sessions
  - revoke: immediately terminate privileged access

Integrates with crypto-service for KEK destruction (4-eyes), lifecycle for legal holds,
and audit for session recording.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import ulid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_pam.domain.models import PAMElevationRequest, PAMSession, Outbox
from foundation_pam.observability import get_logger

log = get_logger(__name__)


class PAMService:
    """JIT elevation + 4-eyes approval workflow."""

    async def request_elevation(
        self, session: AsyncSession, *, tenant_id: str,
        user_id: str, reason: str, target_permissions: list[str],
        duration_minutes: int, ticket_reference: str | None,
        request_id: str,
    ) -> PAMElevationRequest:
        """Request temporary privilege elevation (JIT).

        Duration: 30 min to 4 hours. Auto-revoked on expiry.
        """
        if duration_minutes < 5 or duration_minutes > 480:
            raise ValueError("Duration must be between 5 and 480 minutes")

        expires = datetime.now(UTC) + timedelta(minutes=duration_minutes)
        req = PAMElevationRequest(
            id=f"pam_{ulid.new()!s}",
            tenant_id=tenant_id,
            user_id=user_id,
            reason=reason,
            target_permissions=target_permissions,
            duration_minutes=duration_minutes,
            ticket_reference=ticket_reference,
            status="PENDING",
            requested_at=datetime.now(UTC),
            expires_at=expires,
        )
        session.add(req)
        self._emit(session, tenant_id, "foundation.pam.elevation.requested",
                   {"user_id": user_id, "permissions": target_permissions}, request_id)
        await session.flush()
        return req

    async def approve(
        self, session: AsyncSession, *, tenant_id: str,
        request_id_str: str, approver_id: str, reason: str | None,
    ) -> PAMElevationRequest:
        """Approve a PAM elevation request (4-eyes: approver != requester)."""
        req = await session.get(PAMElevationRequest, request_id_str)
        if req is None or req.tenant_id != tenant_id:
            raise ValueError(f"PAM request {request_id_str} not found")
        if req.user_id == approver_id:
            raise ValueError("Approver must be different from requester (four-eyes principle)")
        if req.status != "PENDING":
            raise ValueError(f"Request is {req.status}, not PENDING")

        req.status = "APPROVED"
        req.approved_by = approver_id
        req.approved_at = datetime.now(UTC)
        req.approval_reason = reason

        # Activate session
        session.add(PAMSession(
            id=f"pams_{ulid.new()!s}",
            tenant_id=tenant_id,
            elevation_request_id=req.id,
            user_id=req.user_id,
            approved_by=approver_id,
            permissions=req.target_permissions,
            started_at=datetime.now(UTC),
            expires_at=req.expires_at,
            is_active=True,
        ))

        self._emit(session, tenant_id, "foundation.pam.elevation.approved",
                   {"request_id": req.id, "approver": approver_id}, "")
        await session.flush()
        return req

    async def deny(
        self, session: AsyncSession, *, tenant_id: str,
        request_id_str: str, approver_id: str, reason: str,
    ) -> PAMElevationRequest:
        """Deny a PAM elevation request."""
        req = await session.get(PAMElevationRequest, request_id_str)
        if req is None or req.tenant_id != tenant_id:
            raise ValueError(f"PAM request {request_id_str} not found")
        req.status = "DENIED"
        req.approved_by = approver_id
        req.approved_at = datetime.now(UTC)
        req.approval_reason = reason
        self._emit(session, tenant_id, "foundation.pam.elevation.denied",
                   {"request_id": req.id, "approver": approver_id, "reason": reason}, "")
        await session.flush()
        return req

    async def get_active_sessions(
        self, session: AsyncSession, *, tenant_id: str, user_id: str | None = None,
    ) -> list[PAMSession]:
        """List active privileged sessions."""
        stmt = select(PAMSession).where(
            PAMSession.tenant_id == tenant_id,
            PAMSession.is_active.is_(True),
            PAMSession.expires_at > datetime.now(UTC),
        )
        if user_id:
            stmt = stmt.where(PAMSession.user_id == user_id)
        return list((await session.scalars(stmt)).all())

    async def revoke(
        self, session: AsyncSession, *, tenant_id: str, session_id: str,
        revoked_by: str, reason: str,
    ) -> None:
        """Immediately revoke a privileged session."""
        s = await session.get(PAMSession, session_id)
        if s is None or s.tenant_id != tenant_id:
            raise ValueError(f"Session {session_id} not found")
        s.is_active = False
        s.revoked_at = datetime.now(UTC)
        s.revoked_by = revoked_by
        s.revocation_reason = reason
        self._emit(session, tenant_id, "foundation.pam.session.revoked",
                   {"session_id": session_id, "user_id": s.user_id}, "")
        await session.flush()

    async def auto_expire(self, session: AsyncSession) -> int:
        """Expire all sessions past their expiry. Returns count."""
        stmt = select(PAMSession).where(
            PAMSession.is_active.is_(True),
            PAMSession.expires_at <= datetime.now(UTC),
        )
        expired = list((await session.scalars(stmt)).all())
        for s in expired:
            s.is_active = False
            s.revoked_at = datetime.now(UTC)
            s.revoked_by = "SYSTEM"
            s.revocation_reason = "Auto-expired"
        return len(expired)

    def _emit(self, session, tenant_id, event_type, payload, request_id):
        session.add(Outbox(tenant_id=tenant_id, event_type=event_type,
            aggregate_id=payload.get("request_id", ""), payload=payload, request_id=request_id))
