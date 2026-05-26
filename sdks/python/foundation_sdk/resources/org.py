"""Org resource — four-level organization tree management."""

from __future__ import annotations

from typing import Any

from foundation_sdk._transport import Transport


class OrgResource:
    """Manage org units, teams, and memberships."""

    def __init__(self, transport: Transport) -> None:
        self._t = transport

    # --- Org Units ---

    def list_org_units(self, *, parent_id: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if parent_id:
            params["parent_id"] = parent_id
        return self._t.request("GET", "/api/org/v1/org-units", params=params)

    def create_org_unit(self, *, name: str, parent_id: str | None = None,
                         description: str = "") -> dict[str, Any]:
        return self._t.request("POST", "/api/org/v1/org-units",
                                json={"name": name, "parent_id": parent_id,
                                      "description": description})

    def get_org_unit(self, org_unit_id: str) -> dict[str, Any]:
        return self._t.request("GET", f"/api/org/v1/org-units/{org_unit_id}")

    # --- Teams ---

    def list_teams(self, *, org_unit_id: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if org_unit_id:
            params["org_unit_id"] = org_unit_id
        return self._t.request("GET", "/api/org/v1/teams", params=params)

    def create_team(self, *, name: str, org_unit_id: str, description: str = "") -> dict[str, Any]:
        return self._t.request("POST", "/api/org/v1/teams",
                                json={"name": name, "org_unit_id": org_unit_id,
                                      "description": description})

    # --- Memberships ---

    def add_member(self, *, user_id: str, team_id: str, role: str = "member") -> dict[str, Any]:
        return self._t.request("POST", "/api/org/v1/memberships",
                                json={"user_id": user_id, "team_id": team_id, "role": role})

    def remove_member(self, user_id: str, team_id: str) -> dict[str, Any]:
        return self._t.request("DELETE",
            f"/api/org/v1/memberships/{user_id}/{team_id}")

    def list_members(self, team_id: str) -> dict[str, Any]:
        return self._t.request("GET", f"/api/org/v1/teams/{team_id}/members")
