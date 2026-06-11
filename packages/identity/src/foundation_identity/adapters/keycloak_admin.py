"""Keycloak Admin API adapter — thin async httpx client.

Only this file may import keycloak / OIDC concepts. Service layer must NOT
depend on Keycloak data shapes; we convert at the adapter boundary.

Token caching: admin token cached in-process with 30s safety margin before expiry.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from foundation_identity.config import get_settings
from foundation_identity.errors import KEYCLOAK_ERROR, KEYCLOAK_UNAVAILABLE, FoundationError
from foundation_identity.observability import get_logger

log = get_logger(__name__)


@dataclass(slots=True)
class _AdminToken:
    access_token: str
    expires_at: datetime


class KeycloakAdminAdapter:
    """Minimal CRUD wrapper over Keycloak Admin REST API.

    Methods used by identity-service:
      * create_user / get_user / update_user / delete_user
      * disable_user / enable_user
      * logout_all_sessions
      * trigger_required_action (password reset)
      * upsert_identity_provider (SSO config)
    """

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        settings = get_settings()
        self._base = str(settings.keycloak_base_url).rstrip("/")
        self._realm = settings.keycloak_realm
        self._admin_realm = settings.keycloak_admin_realm
        self._admin_client_id = settings.keycloak_admin_client_id
        self._admin_user = settings.keycloak_admin_user
        self._admin_password = settings.keycloak_admin_password.get_secret_value()
        self._timeout = settings.keycloak_timeout_seconds
        # NOTE: we intentionally do NOT reuse a single AsyncClient.
        #
        # On macOS + Docker Desktop, reusing httpx's keep-alive connection pool
        # against Keycloak/Quarkus produces empty 502 responses on the second+
        # request (the first one always succeeds). Fresh per-call clients —
        # while ~5ms slower — are correct everywhere we've tested (Mac dev,
        # Linux CI, in-cluster K8s).
        #
        # `client` is kept as a constructor parameter so unit tests can inject
        # a respx-mocked client.
        self._injected_client = client
        self._token: _AdminToken | None = None
        self._token_lock = asyncio.Lock()

    def _new_client(self) -> httpx.AsyncClient:
        if self._injected_client is not None:
            return self._injected_client
        return httpx.AsyncClient(
            timeout=self._timeout,
            transport=httpx.AsyncHTTPTransport(retries=0),
        )

    # ------------------------------------------------------------------ token
    async def _get_admin_token(self) -> str:
        async with self._token_lock:
            now = datetime.now(UTC)
            if self._token and self._token.expires_at - timedelta(seconds=30) > now:
                return self._token.access_token

            url = f"{self._base}/realms/{self._admin_realm}/protocol/openid-connect/token"
            client = self._new_client()
            try:
                try:
                    resp = await client.post(
                        url,
                        data={
                            "client_id": self._admin_client_id,
                            "username": self._admin_user,
                            "password": self._admin_password,
                            "grant_type": "password",
                        },
                    )
                except httpx.HTTPError as e:
                    raise FoundationError(KEYCLOAK_UNAVAILABLE, detail=str(e)) from e
            finally:
                if self._injected_client is None:
                    await client.aclose()

            if resp.status_code != 200:
                raise FoundationError(
                    KEYCLOAK_ERROR,
                    detail=f"Token endpoint returned {resp.status_code}: {resp.text[:200]}",
                )
            data = resp.json()
            self._token = _AdminToken(
                access_token=data["access_token"],
                expires_at=now + timedelta(seconds=int(data["expires_in"])),
            )
            return self._token.access_token

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
        expected: tuple[int, ...] = (200, 201, 204),
    ) -> httpx.Response:
        token = await self._get_admin_token()
        url = f"{self._base}/admin/realms/{self._realm}{path}"
        client = self._new_client()
        try:
            try:
                resp = await client.request(
                    method,
                    url,
                    json=json,
                    params=params,
                    headers={"Authorization": f"Bearer {token}"},
                )
            except httpx.HTTPError as e:
                raise FoundationError(KEYCLOAK_UNAVAILABLE, detail=str(e)) from e
        finally:
            if self._injected_client is None:
                await client.aclose()

        if resp.status_code not in expected:
            log.warning(
                "keycloak.unexpected_status",
                method=method,
                path=path,
                status=resp.status_code,
                body=resp.text[:500],
            )
            raise FoundationError(
                KEYCLOAK_ERROR,
                detail=f"{method} {path} -> {resp.status_code}: {resp.text[:200]}",
            )
        return resp

    # ------------------------------------------------------------------ users
    async def create_user(
        self,
        *,
        email: str,
        username: str | None = None,
        attributes: dict[str, list[str]] | None = None,
        enabled: bool = True,
    ) -> str:
        """Return Keycloak user id (UUID)."""
        payload: dict[str, Any] = {
            "username": username or email,
            "email": email,
            "enabled": enabled,
            "emailVerified": False,
        }
        if attributes:
            payload["attributes"] = attributes

        resp = await self._request("POST", "/users", json=payload, expected=(201,))
        location = resp.headers.get("Location", "")
        # Keycloak returns the new user id in the Location header tail
        return location.rsplit("/", 1)[-1]

    async def get_user(self, kc_user_id: str) -> dict[str, Any]:
        resp = await self._request("GET", f"/users/{kc_user_id}", expected=(200,))
        return resp.json()  # type: ignore[no-any-return]

    async def update_user(self, kc_user_id: str, patch: dict[str, Any]) -> None:
        await self._request("PUT", f"/users/{kc_user_id}", json=patch, expected=(204,))

    async def disable_user(self, kc_user_id: str) -> None:
        await self.update_user(kc_user_id, {"enabled": False})

    async def enable_user(self, kc_user_id: str) -> None:
        await self.update_user(kc_user_id, {"enabled": True})

    async def delete_user(self, kc_user_id: str) -> None:
        await self._request("DELETE", f"/users/{kc_user_id}", expected=(204,))

    async def logout_all_sessions(self, kc_user_id: str) -> None:
        await self._request(
            "POST", f"/users/{kc_user_id}/logout", expected=(204,),
        )

    async def trigger_required_action(
        self, kc_user_id: str, *, action: str = "UPDATE_PASSWORD"
    ) -> None:
        await self._request(
            "PUT",
            f"/users/{kc_user_id}/execute-actions-email",
            json=[action],
            expected=(204,),
        )

    # ------------------------------------------------------------------ credentials
    async def list_credentials(self, kc_user_id: str) -> list[dict[str, Any]]:
        """List a user's Keycloak credentials (password / OTP / WebAuthn / …).

        Returns the realm credentials endpoint payload — each item carries
        ``id``, ``type`` (``password``/``otp``/``webauthn``/``webauthn-passwordless``),
        ``userLabel``, ``createdDate`` etc.  Used for WebAuthn key listing UI.
        """
        resp = await self._request(
            "GET", f"/users/{kc_user_id}/credentials", expected=(200,)
        )
        return resp.json()  # type: ignore[no-any-return]

    async def delete_credential(self, kc_user_id: str, credential_id: str) -> None:
        """Remove a single Keycloak credential by id (one WebAuthn key, etc.)."""
        await self._request(
            "DELETE",
            f"/users/{kc_user_id}/credentials/{credential_id}",
            expected=(204,),
        )

    # ------------------------------------------------------------------ idp
    async def upsert_identity_provider(self, alias: str, config: dict[str, Any]) -> None:
        """Create or update an Identity Provider (SSO)."""
        try:
            await self._request("GET", f"/identity-provider/instances/{alias}", expected=(200,))
            exists = True
        except FoundationError:
            exists = False

        body = {"alias": alias, **config}
        if exists:
            await self._request(
                "PUT", f"/identity-provider/instances/{alias}", json=body, expected=(204,),
            )
        else:
            await self._request(
                "POST", "/identity-provider/instances", json=body, expected=(201,),
            )

    # ------------------------------------------------------------------ lifecycle
    async def aclose(self) -> None:
        if self._injected_client is not None:
            await self._injected_client.aclose()


_singleton: KeycloakAdminAdapter | None = None


def get_keycloak_admin() -> KeycloakAdminAdapter:
    """Module-level singleton; tests can override via FastAPI dependency_overrides."""
    global _singleton
    if _singleton is None:
        _singleton = KeycloakAdminAdapter()
    return _singleton
