"""Lifecycle resource — recycle bin and legal holds."""

from __future__ import annotations

from typing import Any

from foundation_sdk._context import current_context
from foundation_sdk._transport import Transport


def _actor(explicit: str | None, field: str) -> str:
    """``explicit``, else the context user: the routes record who acted from the body."""
    actor = explicit or current_context().user_id
    if not actor:
        raise ValueError(f"{field} is required when the FoundationContext has no user_id")
    return actor


class LifecycleResource:
    """Manage resource lifecycle: recycle bin restore / hard delete, legal holds."""

    def __init__(self, transport: Transport) -> None:
        self._t = transport

    # --- Legal Hold ---

    def mark_legal_hold(self, *, resource_type: str, resource_id: str, reason: str,
                         case_reference: str | None = None) -> dict[str, Any]:
        """Place a hold on one resource. ``reason`` must be at least 10 characters.

        Returns ``{hold_id, status}``.
        """
        body: dict[str, Any] = {"resource_type_id": resource_type,
                                "resource_id": resource_id, "reason": reason}
        if case_reference is not None:
            body["case_reference"] = case_reference
        return self._t.request("POST", "/api/lifecycle/v1/legal-holds", json=body)

    def release_legal_hold(self, hold_id: str, *,
                           released_by: str | None = None) -> dict[str, Any]:
        """Release a hold; ``released_by`` defaults to the context user."""
        return self._t.request("POST", f"/api/lifecycle/v1/legal-holds/{hold_id}:release",
                                json={"released_by": _actor(released_by, "released_by")})

    def list_legal_holds(self, *, resource_id: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if resource_id is not None:
            params["filter.resource_id"] = resource_id
        return self._t.request("GET", "/api/lifecycle/v1/legal-holds", params=params)

    # --- Recycle Bin ---

    def list_recycle_bin(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/lifecycle/v1/recycle-bin")

    def restore_from_bin(self, bin_id: str, *, restored_by: str | None = None) -> dict[str, Any]:
        """Restore a recycle-bin entry (``bin_id`` from ``list_recycle_bin``, not the resource id).

        Without ``restored_by`` the service records the caller.
        """
        body = {"restored_by": restored_by} if restored_by is not None else None
        return self._t.request("POST", f"/api/lifecycle/v1/recycle-bin/{bin_id}:restore",
                                json=body)

    def purge_from_bin(self, bin_id: str, *, destroyed_by: str | None = None,
                       witness_user_id: str | None = None) -> dict[str, Any]:
        """Hard-delete a recycle-bin entry; ``destroyed_by`` defaults to the context user."""
        body: dict[str, Any] = {"destroyed_by": _actor(destroyed_by, "destroyed_by")}
        if witness_user_id is not None:
            body["witness_user_id"] = witness_user_id
        return self._t.request("POST", f"/api/lifecycle/v1/recycle-bin/{bin_id}:hard-delete",
                                json=body)
