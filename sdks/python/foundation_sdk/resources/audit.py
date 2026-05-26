"""Audit resource — immutable audit trail querying."""

from __future__ import annotations

from typing import Any

from foundation_sdk._transport import Transport


class AuditResource:
    """Query the immutable audit trail (hash-chained + Merkle-tree verified)."""

    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def query(self, *, event_type: str | None = None, user_id: str | None = None,
              resource_id: str | None = None, since: str | None = None,
              until: str | None = None, limit: int = 100, cursor: str | None = None,
              ) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit}
        if event_type:
            params["event_type"] = event_type
        if user_id:
            params["user_id"] = user_id
        if resource_id:
            params["resource_id"] = resource_id
        if since:
            params["since"] = since
        if until:
            params["until"] = until
        if cursor:
            params["cursor"] = cursor
        return self._t.request("GET", "/api/audit/v1/events", params=params)

    def get_event(self, event_id: str) -> dict[str, Any]:
        return self._t.request("GET", f"/api/audit/v1/events/{event_id}")

    def verify_chain(self, *, event_ids: list[str]) -> dict[str, Any]:
        """Verify the hash chain and Merkle root for a set of events."""
        return self._t.request("POST", "/api/audit/v1/verify",
                                json={"event_ids": event_ids})

    def export(self, *, format: str = "csv", event_type: str | None = None,
               since: str | None = None, until: str | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"format": format}
        if event_type:
            body["event_type"] = event_type
        if since:
            body["since"] = since
        if until:
            body["until"] = until
        return self._t.request("POST", "/api/audit/v1/export", json=body)
