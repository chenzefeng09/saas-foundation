"""Authz resource — RBAC + OPA authorization checks."""

from __future__ import annotations

from typing import Any

from foundation_sdk._transport import Transport


class AuthzResource:
    """Authorization checks and role management."""

    def __init__(self, transport: Transport) -> None:
        self._t = transport

    # --- Permission Check ---

    def check(self, *, action: str, resource_type: str, resource_id: str | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"action": action, "resource_type": resource_type}
        if resource_id:
            body["resource_id"] = resource_id
        return self._t.request("POST", "/api/authz/v1/check", json=body)

    async def check_async(self, *, action: str, resource_type: str,
                           resource_id: str | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"action": action, "resource_type": resource_type}
        if resource_id:
            body["resource_id"] = resource_id
        return await self._t.request_async("POST", "/api/authz/v1/check", json=body)

    # --- Roles ---

    def list_roles(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/authz/v1/roles")

    def create_role(self, *, name: str, permissions: list[str]) -> dict[str, Any]:
        return self._t.request("POST", "/api/authz/v1/roles",
                                json={"name": name, "permissions": permissions})

    def bind_role(self, *, user_id: str, role_name: str, scope: str = "tenant") -> dict[str, Any]:
        return self._t.request("POST", "/api/authz/v1/bindings",
                                json={"user_id": user_id, "role": role_name, "scope": scope})

    def list_permissions(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/authz/v1/permissions")
