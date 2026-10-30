"""Lifecycle resource — recycle bin, legal holds and their four-eyes approvals."""

from __future__ import annotations

from typing import Any, Literal

from foundation_sdk._transport import Transport


class LifecycleResource:
    """Manage resource lifecycle: recycle bin restore / hard delete, legal holds.

    Restore, hard delete and release are recorded against the caller: the service
    takes who acted from the authenticated context (``X-User-Id``), never from the
    request, so these methods take no actor. Hard delete and release take a second
    person: they only open an approval request, which another user carries out with
    ``approve_request``.
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
        """Ask for a hold to be released; it is released once another user approves.

        Returns ``{released: false, approval_request}``, the request to approve, or
        ``{released: true}`` if the hold is already released. The service records the
        context user as the requester and, once approved, as the releaser.
        """
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
        """Ask for a recycle-bin entry to be hard-deleted now; it is destroyed once another
        user approves.

        Returns ``{destroyed: false, approval_request}``, the request to approve, or
        ``{destroyed: true}`` if the entry is already destroyed. The service records the
        context user as the requester and, once approved, as the one who destroyed it;
        the approver is the witness the destruction certificate names.
        """
        return self._t.request("POST", f"/api/lifecycle/v1/recycle-bin/{bin_id}:hard-delete")

    # --- Four-eyes approvals ---

    def list_approval_requests(
        self, *,
        status: Literal["PENDING", "APPROVED", "REJECTED", "EXPIRED"] | None = None,
        operation: Literal["HARD_DELETE", "RELEASE_LEGAL_HOLD"] | None = None,
        limit: int = 50, cursor: str | None = None,
    ) -> dict[str, Any]:
        """Approval requests, newest first: ``{items, next_cursor}``.

        A pending request whose window has closed is ``EXPIRED``.
        """
        params: dict[str, Any] = {"limit": limit}
        if status is not None:
            params["filter.status"] = status
        if operation is not None:
            params["filter.operation"] = operation
        if cursor:
            params["cursor"] = cursor
        return self._t.request("GET", "/api/lifecycle/v1/approval-requests", params=params)

    def get_approval_request(self, approval_id: str) -> dict[str, Any]:
        return self._t.request("GET", f"/api/lifecycle/v1/approval-requests/{approval_id}")

    def approve_request(self, approval_id: str) -> dict[str, Any]:
        """Approve as the second person, which carries the request out now: the entry is
        destroyed, with the context user as the certificate's witness, or the hold released.

        The service refuses the requester's own approval (403) and a request that was
        already decided or has expired (409).
        """
        return self._t.request(
            "POST", f"/api/lifecycle/v1/approval-requests/{approval_id}/approve")

    def reject_request(self, approval_id: str) -> dict[str, Any]:
        """Turn a request down; nothing is destroyed or released. The requester may
        withdraw their own request this way."""
        return self._t.request(
            "POST", f"/api/lifecycle/v1/approval-requests/{approval_id}/reject")
