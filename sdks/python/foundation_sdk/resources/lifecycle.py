"""Lifecycle resource — recycle bin and legal holds."""

from __future__ import annotations

from typing import Any

from foundation_sdk._transport import Transport


class LifecycleResource:
    """Manage resource lifecycle: recycle bin restore / hard delete, legal holds.

    Restore, hard delete and release are recorded against the caller: the service
    takes who acted from the authenticated context (``X-User-Id``), never from the
    request, so these methods take no actor.
    """

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

    def release_legal_hold(self, hold_id: str) -> dict[str, Any]:
        """Release a hold; the service records the context user as the releaser."""
        return self._t.request("POST", f"/api/lifecycle/v1/legal-holds/{hold_id}:release")

    def list_legal_holds(self, *, resource_id: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if resource_id is not None:
            params["filter.resource_id"] = resource_id
        return self._t.request("GET", "/api/lifecycle/v1/legal-holds", params=params)

    # --- Recycle Bin ---

    def list_recycle_bin(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/lifecycle/v1/recycle-bin")

    def restore_from_bin(self, bin_id: str) -> dict[str, Any]:
        """Restore a recycle-bin entry (``bin_id`` from ``list_recycle_bin``, not the resource id).

        The service records the context user as the restorer.
        """
        return self._t.request("POST", f"/api/lifecycle/v1/recycle-bin/{bin_id}:restore")

    def purge_from_bin(self, bin_id: str) -> dict[str, Any]:
        """Hard-delete a recycle-bin entry; the service records the context user as the one
        who destroyed it. A destruction certificate names no witness.
        """
        return self._t.request("POST", f"/api/lifecycle/v1/recycle-bin/{bin_id}:hard-delete")
