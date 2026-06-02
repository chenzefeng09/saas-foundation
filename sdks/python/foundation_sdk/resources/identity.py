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

    def me(self) -> dict[str, Any]:
        """Resolve caller identity from the current bearer token.

        BFFs call this on every page-load to rehydrate the user profile from
        the foundation-issued JWT without trusting any client-side state.
        Returns ``{user_id, tenant_id, email, display_name, roles, mfa_enabled, locale}``.
        """
        return self._t.request("GET", "/api/identity/v1/sessions/me")

    async def me_async(self) -> dict[str, Any]:
        return await self._t.request_async("GET", "/api/identity/v1/sessions/me")

    # --- Service-account tokens ---

    _SAT_PATH = "/api/identity/v1/sessions/service-account-token"

    @staticmethod
    def _sat_body(
        *,
        tenant_id: str,
        subject: str,
        scopes: list[str],
        audience: str,
        ttl_seconds: int,
    ) -> dict[str, Any]:
        return {
            "tenant_id": tenant_id,
            "subject": subject,
            "scopes": scopes,
            "audience": audience,
            "ttl_seconds": ttl_seconds,
        }

    def issue_service_account_token(
        self,
        *,
        tenant_id: str,
        subject: str,
        scopes: list[str],
        audience: str = "foundation",
        ttl_seconds: int = 3_600,
    ) -> dict[str, Any]:
        """Mint a short-lived, scope-limited, tenant-bound JWT.

        Use this whenever a service spawns a workload (container, batch job,
        scheduled task) that needs to call foundation services on behalf of a
        tenant.  Do **not** forward your own service-account token to the
        workload — leakage of that token grants the workload's attacker your
        full service identity.

        Args:
            tenant_id: Tenant the workload will operate on. MUST equal the
                tenant carried in the SDK's current bearer token; cross-tenant
                minting is rejected by identity-service.
            subject: Stable identifier of the workload — e.g.
                ``"agent-scheduler:run_01J5XYZ..."``.  Used in audit logs and
                JWT ``sub`` claim.
            scopes: Subset of the foundation scope catalogue
                (see ``docs/CONVENTIONS.md §4``).  Identity rejects unknown
                scopes with FOUNDATION.IDENTITY.AUTH.SCOPE_NOT_ALLOWED.
            audience: Target service name; downstream services verify ``aud``.
                Default ``"foundation"`` works for cross-foundation calls.
            ttl_seconds: 60 ≤ ttl ≤ 86_400.  Pick the smallest value that
                covers the workload's expected lifetime; typical agent
                sandbox: 600–3_600s.

        Returns:
            ``{access_token, expires_at, jti, ...}`` — pass ``access_token``
            into the workload's environment (preferably as a single-use
            secret mount, not env var).
        """
        return self._t.request(
            "POST",
            self._SAT_PATH,
            json=self._sat_body(
                tenant_id=tenant_id, subject=subject, scopes=scopes,
                audience=audience, ttl_seconds=ttl_seconds,
            ),
        )

    async def issue_service_account_token_async(
        self,
        *,
        tenant_id: str,
        subject: str,
        scopes: list[str],
        audience: str = "foundation",
        ttl_seconds: int = 3_600,
    ) -> dict[str, Any]:
        """Async variant of :meth:`issue_service_account_token`."""
        return await self._t.request_async(
            "POST",
            self._SAT_PATH,
            json=self._sat_body(
                tenant_id=tenant_id, subject=subject, scopes=scopes,
                audience=audience, ttl_seconds=ttl_seconds,
            ),
        )

    # --- Health ---

    def healthz(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/identity/v1/healthz")
