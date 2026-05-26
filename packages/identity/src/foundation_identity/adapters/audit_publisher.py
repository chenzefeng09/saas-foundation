"""Audit event publisher (outbox pattern).

Strategy is configurable:
  * outbox_db (default)  — INSERT into identity.outbox; background worker drains to
                            audit-service. Transactional guarantee.
  * http_direct           — fire-and-forget POST to audit-service /events. Only safe
                            for non-critical paths; not used by default.
  * log_only              — print to structlog. Test / dev only.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol

import ulid
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_identity.config import get_settings
from foundation_identity.domain.models import Outbox
from foundation_identity.observability import get_logger

log = get_logger(__name__)


class AuditPublisher(Protocol):
    """Surface used by service layer; concrete impl chosen at startup."""

    async def publish(
        self,
        session: AsyncSession,
        *,
        event_type: str,
        tenant_id: str | None,
        aggregate_id: str | None,
        payload: dict[str, Any],
        request_id: str | None = None,
    ) -> None: ...


def _new_outbox_id() -> str:
    return f"evt_{ulid.new()!s}"


class _OutboxPublisher:
    """Default. INSERT to outbox table inside the caller's transaction."""

    async def publish(
        self,
        session: AsyncSession,
        *,
        event_type: str,
        tenant_id: str | None,
        aggregate_id: str | None,
        payload: dict[str, Any],
        request_id: str | None = None,
    ) -> None:
        # Validation — keep event-name contract: foundation.<svc>.<entity>.<action>
        if event_type.count(".") != 3:
            raise ValueError(
                f"event_type must be 4-segment dotted; got {event_type!r}"
            )

        row = Outbox(
            id=_new_outbox_id(),
            tenant_id=tenant_id,
            event_type=event_type,
            aggregate_id=aggregate_id,
            payload=payload,
            request_id=request_id,
        )
        session.add(row)
        # NOTE: the caller controls commit; we never commit here. This preserves
        # the transactional invariant — either both the business row and the
        # outbox row land, or neither.


class _LogOnlyPublisher:
    """For tests / local dev where audit-service isn't running."""

    async def publish(
        self,
        session: AsyncSession,  # noqa: ARG002
        *,
        event_type: str,
        tenant_id: str | None,
        aggregate_id: str | None,
        payload: dict[str, Any],
        request_id: str | None = None,
    ) -> None:
        log.info(
            "audit.event",
            event_type=event_type,
            tenant_id=tenant_id,
            aggregate_id=aggregate_id,
            payload=payload,
            request_id=request_id,
            recorded_at=datetime.now(UTC).isoformat(),
        )


_singleton: AuditPublisher | None = None


def get_audit_publisher() -> AuditPublisher:
    global _singleton
    if _singleton is None:
        kind = get_settings().audit_publisher_kind
        if kind == "outbox_db":
            _singleton = _OutboxPublisher()
        elif kind == "log_only":
            _singleton = _LogOnlyPublisher()
        else:
            # http_direct not implemented in skeleton; falls back with warning
            log.warning("audit.publisher.unimplemented", kind=kind)
            _singleton = _LogOnlyPublisher()
    return _singleton
