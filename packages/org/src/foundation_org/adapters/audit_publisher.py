"""Audit publisher — outbox pattern.

Same shape as the authz publisher: services call `publish(...)` inside the
same DB transaction; a separate worker (out of scope for M1) drains the
outbox into Redis Streams / NATS.

The publisher accepts 4-segment dotted event types
(`foundation.org.<aggregate>.<verb>`) so audit consumers can route by
prefix.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from foundation_org.config import get_settings
from foundation_org.domain.models import Outbox
from foundation_org.observability import get_logger

log = get_logger(__name__)


class AuditPublisher(Protocol):
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


class _OutboxPublisher:
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
        if event_type.count(".") != 3:
            raise ValueError(f"event_type must be 4-segment dotted; got {event_type!r}")
        session.add(
            Outbox(
                tenant_id=tenant_id,
                event_type=event_type,
                aggregate_id=aggregate_id,
                payload=payload,
                request_id=request_id,
            )
        )


class _LogOnlyPublisher:
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
            log.warning("audit.publisher.unimplemented", kind=kind)
            _singleton = _LogOnlyPublisher()
    return _singleton
