"""Keycloak OIDC adapter — token endpoint + JWKS verification.

Distinct from :mod:`keycloak_admin` (which uses the *Admin REST API* for user
CRUD). This module talks to the *OIDC* endpoints — token, certs, userinfo —
and is used by the session endpoints to:

* exchange end-user credentials for an access/refresh token (password grant),
* mint a service-account token (client_credentials grant), and
* validate bearer tokens presented by callers (JWKS signature + claims).

Why a *fresh* httpx client per call?  Same reason documented in
:mod:`keycloak_admin`: on macOS + Docker Desktop, reusing httpx's keep-alive
pool against Keycloak/Quarkus yields empty 502s on the second request.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTError

from foundation_identity.config import get_settings
from foundation_identity.errors import (
    INVALID_CREDENTIALS,
    KEYCLOAK_ERROR,
    KEYCLOAK_UNAVAILABLE,
    TOKEN_EXPIRED,
    TOKEN_INVALID,
    FoundationError,
)
from foundation_identity.observability import get_logger

log = get_logger(__name__)


class KeycloakOIDCAdapter:
    """OIDC client for Keycloak realm endpoints."""

    def __init__(self) -> None:
        settings = get_settings()
        self._base = str(settings.keycloak_base_url).rstrip("/")
        self._realm = settings.keycloak_realm
        self._client_id = "foundation-identity-service"
        # Reuse the existing keycloak_admin client secret if you later move
        # it into settings.  For M2 we read directly from settings to avoid
        # adding yet another env var.
        self._client_secret = (
            settings.foundation_identity_client_secret.get_secret_value()
        )
        self._timeout = settings.keycloak_timeout_seconds
        self._jwks_cache_ttl = settings.jwks_cache_ttl_seconds

        self._jwks: dict[str, Any] | None = None
        self._jwks_fetched_at: float = 0.0
        self._jwks_lock = asyncio.Lock()

    # --------------------------------------------------------------- urls
    def _token_url(self) -> str:
        return f"{self._base}/realms/{self._realm}/protocol/openid-connect/token"

    def _jwks_url(self) -> str:
        return f"{self._base}/realms/{self._realm}/protocol/openid-connect/certs"

    def _new_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=self._timeout,
            transport=httpx.AsyncHTTPTransport(retries=0),
        )

    # --------------------------------------------------------- grants
    async def password_grant(self, *, username: str, password: str) -> dict[str, Any]:
        """Exchange end-user credentials for a token bundle.

        Raises:
            FoundationError(INVALID_CREDENTIALS): KC returned 400/401 (bad creds).
            FoundationError(KEYCLOAK_UNAVAILABLE): network failure.
            FoundationError(KEYCLOAK_ERROR): unexpected 5xx / shape mismatch.
        """
        return await self._token_request(
            {
                "grant_type": "password",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "username": username,
                "password": password,
                "scope": "openid",
            }
        )

    async def client_credentials_grant(self) -> dict[str, Any]:
        """Mint a service-account token for foundation-identity-service."""
        return await self._token_request(
            {
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "scope": "openid",
            }
        )

    async def _token_request(self, data: dict[str, str]) -> dict[str, Any]:
        client = self._new_client()
        try:
            try:
                resp = await client.post(self._token_url(), data=data)
            except httpx.HTTPError as exc:
                raise FoundationError(KEYCLOAK_UNAVAILABLE, detail=str(exc)) from exc
        finally:
            await client.aclose()

        if resp.status_code == 200:
            payload = resp.json()
            if "access_token" not in payload:
                raise FoundationError(
                    KEYCLOAK_ERROR,
                    detail="Token response missing access_token",
                )
            return payload  # type: ignore[no-any-return]

        # 400 invalid_grant / 401 unauthorized → credential failure
        if resp.status_code in (400, 401):
            try:
                err = resp.json()
            except ValueError:
                err = {}
            kc_err = err.get("error", "")
            if kc_err in ("invalid_grant", "unauthorized_client", "invalid_client"):
                log.info(
                    "keycloak.token.invalid_credentials",
                    grant=data.get("grant_type"),
                    kc_error=kc_err,
                )
                raise FoundationError(INVALID_CREDENTIALS, detail=kc_err)
            # Other 4xx → bubble as keycloak error for ops visibility.
            raise FoundationError(
                KEYCLOAK_ERROR,
                detail=f"Token endpoint {resp.status_code}: {resp.text[:200]}",
            )

        # 5xx → upstream broken
        log.warning(
            "keycloak.token.unexpected_status",
            status=resp.status_code,
            body=resp.text[:500],
        )
        raise FoundationError(
            KEYCLOAK_ERROR,
            detail=f"Token endpoint {resp.status_code}",
        )

    # --------------------------------------------------------- JWKS
    async def _get_jwks(self) -> dict[str, Any]:
        """Fetch + cache the realm JWKS for ``jwks_cache_ttl_seconds``."""
        now = time.monotonic()
        if self._jwks and (now - self._jwks_fetched_at) < self._jwks_cache_ttl:
            return self._jwks

        async with self._jwks_lock:
            now = time.monotonic()
            if self._jwks and (now - self._jwks_fetched_at) < self._jwks_cache_ttl:
                return self._jwks

            client = self._new_client()
            try:
                try:
                    resp = await client.get(self._jwks_url())
                except httpx.HTTPError as exc:
                    raise FoundationError(
                        KEYCLOAK_UNAVAILABLE, detail=str(exc)
                    ) from exc
            finally:
                await client.aclose()

            if resp.status_code != 200:
                raise FoundationError(
                    KEYCLOAK_ERROR,
                    detail=f"JWKS fetch {resp.status_code}",
                )
            self._jwks = resp.json()
            self._jwks_fetched_at = time.monotonic()
            return self._jwks

    async def verify_token(self, token: str) -> dict[str, Any]:
        """Verify a JWT against realm JWKS; return decoded claims.

        Audience is NOT enforced here — the identity service issues tokens
        under client_id ``foundation-identity-service`` whose default
        ``aud`` is the client itself; downstream services check ``aud`` per
        their own contract.  Issuer IS enforced.
        """
        try:
            unverified_header = jwt.get_unverified_header(token)
        except JWTError as exc:
            raise FoundationError(TOKEN_INVALID, detail=str(exc)) from exc

        kid = unverified_header.get("kid")
        if not kid:
            raise FoundationError(TOKEN_INVALID, detail="missing kid in header")

        jwks = await self._get_jwks()
        keys = [k for k in jwks.get("keys", []) if k.get("kid") == kid]
        if not keys:
            # Possibly a rotated key — clear cache + retry once.
            self._jwks = None
            jwks = await self._get_jwks()
            keys = [k for k in jwks.get("keys", []) if k.get("kid") == kid]
        if not keys:
            raise FoundationError(TOKEN_INVALID, detail=f"kid {kid} not in JWKS")

        settings = get_settings()
        try:
            claims = jwt.decode(
                token,
                keys[0],
                algorithms=[unverified_header.get("alg", "RS256")],
                issuer=str(settings.jwt_issuer).rstrip("/"),
                options={
                    # We don't enforce audience here; see docstring.
                    "verify_aud": False,
                },
            )
        except ExpiredSignatureError as exc:
            raise FoundationError(TOKEN_EXPIRED, detail=str(exc)) from exc
        except JWTError as exc:
            raise FoundationError(TOKEN_INVALID, detail=str(exc)) from exc
        return claims  # type: ignore[no-any-return]


_singleton: KeycloakOIDCAdapter | None = None


def get_keycloak_oidc() -> KeycloakOIDCAdapter:
    """Module-level singleton; tests override via FastAPI dependency_overrides."""
    global _singleton
    if _singleton is None:
        _singleton = KeycloakOIDCAdapter()
    return _singleton
