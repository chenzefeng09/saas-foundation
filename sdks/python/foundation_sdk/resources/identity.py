"""Identity resource — user management, sessions, password policy."""

from __future__ import annotations

from typing import Any

from foundation_sdk._transport import Transport


class IdentityResource:
    """Manage users, sessions, and password policies via the Identity service."""

    def __init__(self, transport: Transport) -> None:
        self._t = transport

    # --- Users ---

    def get_user(self, user_id: str) -> dict[str, Any]:
        return self._t.request("GET", f"/api/identity/v1/users/{user_id}")

    async def get_user_async(self, user_id: str) -> dict[str, Any]:
        return await self._t.request_async("GET", f"/api/identity/v1/users/{user_id}")

    def list_users(self, *, limit: int = 50, cursor: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        return self._t.request("GET", "/api/identity/v1/users", params=params)

    def create_user(self, *, email: str, display_name: str, password: str | None = None,
                    roles: list[str] | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"email": email, "display_name": display_name}
        if password:
            body["password"] = password
        if roles:
            body["roles"] = roles
        return self._t.request("POST", "/api/identity/v1/users", json=body)

    def disable_user(self, user_id: str) -> dict[str, Any]:
        return self._t.request("POST", f"/api/identity/v1/users/{user_id}/disable")

    def freeze_user(self, user_id: str) -> dict[str, Any]:
        """Emergency freeze — invalidates all tokens immediately."""
        return self._t.request("POST", f"/api/identity/v1/users/{user_id}/freeze")

    # --- Password Policy ---

    def get_password_policy(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/identity/v1/password-policy")

    def validate_password(self, password: str) -> dict[str, Any]:
        return self._t.request("POST", "/api/identity/v1/password-policy/validate",
                                json={"password": password})

    # --- Sessions ---

    def list_sessions(self, user_id: str) -> dict[str, Any]:
        return self._t.request("GET", f"/api/identity/v1/users/{user_id}/sessions")

    def revoke_session(self, user_id: str, session_id: str) -> dict[str, Any]:
        return self._t.request("DELETE",
            f"/api/identity/v1/users/{user_id}/sessions/{session_id}")

    # --- Health ---

    def healthz(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/identity/v1/healthz")
