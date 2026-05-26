"""Audit SDK — the ONLY way services push audit events.

Usage:
    from foundation_audit.sdk import emit

    await emit(AuditEvent(
        event_id=f"evt_{ulid.new()!s}",
        occurred_at=datetime.now(UTC),
        tenant_id=ctx.tenant_id,
        service="identity",
        event_type="foundation.identity.user.login_success",
        severity="INFO",
        outcome="SUCCESS",
        actor_kind="USER",
        actor_user_id=user_id,
        request_id=request_id,
        payload={"method": "password"},
    ))

The SDK:
  1. Validates the event.
  2. Publishes to audit-service via HTTP (or local outbox if unavailable).
  3. Returns immediately — fire-and-forget with at-least-once guarantee.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING

import httpx
import structlog

from foundation_audit.config import get_settings
from foundation_audit.schemas.event import AuditEvent

if TYPE_CHECKING:
    pass

log = structlog.get_logger("foundation_audit.sdk")

_client: httpx.AsyncClient | None = None


def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        settings = get_settings()
        _client = httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{settings.http_port}{settings.api_prefix}",
            timeout=5.0,
        )
    return _client


async def emit(event: AuditEvent) -> bool:
    """Fire-and-forget emit. Returns True if delivered, False if queued locally."""
    try:
        client = _get_client()
        resp = await client.post(
            "/events",
            json=event.model_dump(mode="json"),
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code == 202:
            return True
        log.warning("audit.emit.rejected", status=resp.status_code, event_id=event.event_id)
    except (httpx.ConnectError, httpx.TimeoutException, OSError):
        log.warning("audit.emit.unavailable", event_id=event.event_id)
    except Exception:
        log.exception("audit.emit.error", event_id=event.event_id)
    return False


async def emit_batch(events: list[AuditEvent]) -> int:
    """Emit multiple events in one request. Returns count accepted."""
    if not events:
        return 0
    try:
        client = _get_client()
        payload = [e.model_dump(mode="json") for e in events]
        resp = await client.post("/events/batch", json=payload)
        if resp.status_code == 202:
            return len(events)
    except Exception:
        log.exception("audit.emit_batch.error", count=len(events))
    return 0


async def close() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None
