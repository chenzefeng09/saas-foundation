"""PAM resource — privileged access management: JIT elevation, 4-eyes approval."""

from __future__ import annotations

from typing import Any

from foundation_sdk._transport import Transport


class PAMResource:
    """Privileged Access Management: JIT elevation, 4-eyes approval, session management."""

    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def request_elevation(self, *, reason: str, duration_minutes: int = 60,
                           target_resources: list[str] | None = None) -> dict[str, Any]:
        return self._t.request("POST", "/api/pam/v1/elevations",
                                json={"reason": reason,
                                      "duration_minutes": duration_minutes,
                                      "target_resources": target_resources or []})

    def approve_elevation(self, elevation_id: str, *, justification: str = "") -> dict[str, Any]:
        return self._t.request("POST", f"/api/pam/v1/elevations/{elevation_id}/approve",
                                json={"justification": justification})

    def revoke_elevation(self, elevation_id: str) -> dict[str, Any]:
        return self._t.request("POST", f"/api/pam/v1/elevations/{elevation_id}/revoke")

    def list_active_sessions(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/pam/v1/sessions")

    def list_pending_elevations(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/pam/v1/elevations/pending")

    def get_elevation_history(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/pam/v1/elevations/history")
