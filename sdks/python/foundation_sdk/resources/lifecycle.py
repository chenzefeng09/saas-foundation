"""Lifecycle resource — retention, recycle bin, legal hold, data destruction."""

from __future__ import annotations

from typing import Any

from foundation_sdk._transport import Transport


class LifecycleResource:
    """Manage resource lifecycle: retention, soft-delete, legal hold, data destruction."""

    def __init__(self, transport: Transport) -> None:
        self._t = transport

    # --- Legal Hold ---

    def mark_legal_hold(self, *, resource_type: str, resource_id: str,
                         reason: str) -> dict[str, Any]:
        return self._t.request("POST", "/api/lifecycle/v1/legal-holds",
                                json={"resource_type": resource_type,
                                      "resource_id": resource_id, "reason": reason})

    def release_legal_hold(self, hold_id: str) -> dict[str, Any]:
        return self._t.request("DELETE", f"/api/lifecycle/v1/legal-holds/{hold_id}")

    def list_legal_holds(self, *, resource_id: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if resource_id:
            params["resource_id"] = resource_id
        return self._t.request("GET", "/api/lifecycle/v1/legal-holds", params=params)

    # --- Retention ---

    def set_retention_policy(self, *, resource_type: str, retention_days: int) -> dict[str, Any]:
        return self._t.request("PUT", "/api/lifecycle/v1/retention-policies",
                                json={"resource_type": resource_type,
                                      "retention_days": retention_days})

    def get_retention_policy(self, resource_type: str) -> dict[str, Any]:
        return self._t.request("GET", f"/api/lifecycle/v1/retention-policies/{resource_type}")

    # --- Recycle Bin ---

    def list_recycle_bin(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/lifecycle/v1/recycle-bin")

    def restore_from_bin(self, resource_id: str) -> dict[str, Any]:
        return self._t.request("POST", f"/api/lifecycle/v1/recycle-bin/{resource_id}/restore")

    def purge_from_bin(self, resource_id: str) -> dict[str, Any]:
        return self._t.request("DELETE", f"/api/lifecycle/v1/recycle-bin/{resource_id}")

    # --- Destruction Certificate ---

    def generate_destruction_certificate(self, *, resource_ids: list[str]) -> dict[str, Any]:
        return self._t.request("POST", "/api/lifecycle/v1/destruction-certificates",
                                json={"resource_ids": resource_ids})
