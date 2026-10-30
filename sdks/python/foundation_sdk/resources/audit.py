"""Audit resource — immutable audit trail querying."""

from __future__ import annotations

from typing import Any, Literal

from foundation_sdk._context import current_context
from foundation_sdk._transport import Transport


def _query_body(*, event_type: str | None, user_id: str | None, resource_id: str | None,
                since: str | None, until: str | None) -> dict[str, Any]:
    """An ``AuditQuery`` for the context tenant (the routes reject any other tenant)."""
    body: dict[str, Any] = {"tenant_id": current_context().tenant_id}
    for key, value in (("event_type", event_type), ("actor_user_id", user_id),
                       ("resource_id", resource_id), ("occurred_from", since),
                       ("occurred_to", until)):
        if value:
            body[key] = value
    return body


class AuditResource:
    """Query the immutable audit trail (hash-chained + Merkle-tree verified)."""

    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def query(self, *, event_type: str | None = None, user_id: str | None = None,
              resource_id: str | None = None, since: str | None = None,
              until: str | None = None, limit: int = 100, cursor: str | None = None,
              ) -> dict[str, Any]:
        """Events of the context tenant. ``user_id`` filters by actor;
        ``since`` / ``until`` are ISO-8601 bounds on ``occurred_at``.

        Returns ``{items, next_cursor, total_estimate}``.
        """
        body = _query_body(event_type=event_type, user_id=user_id, resource_id=resource_id,
                           since=since, until=until)
        body["limit"] = limit
        if cursor:
            body["cursor"] = cursor
        return self._t.request("POST", "/api/audit/v1/events:query", json=body)

    def verify_chain(self, *, service: str | None = None, from_event_id: str | None = None,
                     limit: int = 1000) -> dict[str, Any]:
        """Re-verify the hash chain and Merkle roots of the context tenant's events,
        oldest first from ``from_event_id`` (or the start), at most ``limit`` (≤ 10000).
        """
        body: dict[str, Any] = {"tenant_id": current_context().tenant_id, "limit": limit}
        if service:
            body["service"] = service
        if from_event_id:
            body["from_event_id"] = from_event_id
        return self._t.request("POST", "/api/audit/v1/events:verify-integrity", json=body)

    def export(self, *, format: Literal["csv", "json"] = "csv", event_type: str | None = None,
               user_id: str | None = None, resource_id: str | None = None,
               since: str | None = None, until: str | None = None) -> str:
        """The matching events (at most 10000) as the content of a CSV or JSON file."""
        body = _query_body(event_type=event_type, user_id=user_id, resource_id=resource_id,
                           since=since, until=until)
        return self._t.request_text("POST", "/api/audit/v1/events:export",
                                     params={"format": format}, json=body)
