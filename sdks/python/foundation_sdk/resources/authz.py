"""Authz resource — RBAC + OPA authorization checks."""

from __future__ import annotations

from typing import Any

from foundation_sdk._context import current_context
from foundation_sdk._transport import Transport


def _check_body(*, action: str, resource_type: str, resource_id: str | None,
                user_id: str | None) -> dict[str, Any]:
    subject = user_id or current_context().user_id
    if not subject:
        raise ValueError("user_id is required when the FoundationContext has no user_id")
    body: dict[str, Any] = {"user_id": subject, "action": action,
                            "resource_type": resource_type}
    if resource_id:
        body["resource_id"] = resource_id
    return body


class AuthzResource:
    """Authorization checks and role management."""

    def __init__(self, transport: Transport) -> None:
        self._t = transport

    # --- Permission Check ---

    def check(self, *, action: str, resource_type: str, resource_id: str | None = None,
              user_id: str | None = None) -> dict[str, Any]:
        """May ``user_id`` (default: the context user) perform ``action``?"""
        body = _check_body(action=action, resource_type=resource_type,
                           resource_id=resource_id, user_id=user_id)
        return self._t.request("POST", "/api/authz/v1/check", json=body)

    async def check_async(self, *, action: str, resource_type: str,
                           resource_id: str | None = None,
                           user_id: str | None = None) -> dict[str, Any]:
        body = _check_body(action=action, resource_type=resource_type,
                           resource_id=resource_id, user_id=user_id)
        return await self._t.request_async("POST", "/api/authz/v1/check", json=body)

    # --- Roles ---

    def list_roles(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/authz/v1/roles")

    def create_role(self, *, name: str, permissions: list[str],
                    display_name: str | None = None,
                    description: str | None = None) -> dict[str, Any]:
        """``display_name`` defaults to ``name``."""
        body: dict[str, Any] = {"name": name, "display_name": display_name or name,
                                "permissions": permissions}
        if description is not None:
            body["description"] = description
        return self._t.request("POST", "/api/authz/v1/roles", json=body)

    def bind_role(self, *, user_id: str, role_id: str, scope_kind: str = "TENANT",
                  scope_id: str | None = None, expires_at: str | None = None,
                  grant_reason: str | None = None) -> dict[str, Any]:
        """Bind role ``role_id`` (``rol_…``, from ``list_roles``) to a user.

        ``scope_kind`` is TENANT, ORG_UNIT, TEAM, RESOURCE or GLOBAL_SYSTEM; every
        kind but TENANT needs ``scope_id``. ``expires_at`` is ISO-8601.
        """
        body: dict[str, Any] = {"principal_kind": "USER", "principal_id": user_id,
                                "role_id": role_id, "scope_kind": scope_kind}
        for key, value in (("scope_id", scope_id), ("expires_at", expires_at),
                           ("grant_reason", grant_reason)):
            if value is not None:
                body[key] = value
        return self._t.request("POST", "/api/authz/v1/bindings", json=body)

    def list_permissions(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/authz/v1/permissions")
