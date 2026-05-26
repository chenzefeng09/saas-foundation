"""Audit publisher — same outbox pattern as identity."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol

import ulid
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_authz.config import get_settings
from foundation_authz.domain.models import Outbox
from foundation_authz.observability import get_logger

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


def _new_outbox_id() -> str:
    return f"evt_{ulid.new()!s}"


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
                id=_new_outbox_id(),
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
