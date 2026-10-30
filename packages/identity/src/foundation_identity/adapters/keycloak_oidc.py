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
    ACCOUNT_SETUP_REQUIRED,
    INVALID_CREDENTIALS,
    KEYCLOAK_ERROR,
    KEYCLOAK_UNAVAILABLE,
    TOKEN_EXPIRED,
    TOKEN_INVALID,
    FoundationError,
)
from foundation_identity.observability import get_logger

log = get_logger(__name__)

# Keycloak's token endpoint answers ``invalid_grant`` with this (fixed, English)
# ``error_description`` when the direct grant AUTHENTICATED the user but the
# account still has required actions pending — UPDATE_PASSWORD after a password
# expiry / admin-requested reset, VERIFY_EMAIL, CONFIGURE_TOTP, ...  The password
# grant cannot run those interactive steps, so it fails; the credentials
# themselves were correct.
_ACCOUNT_NOT_SET_UP = "account is not fully set up"


def _is_account_setup_required(err: dict[str, Any]) -> bool:
    desc = err.get("error_description")
    return isinstance(desc, str) and _ACCOUNT_NOT_SET_UP in desc.lower()


class KeycloakOIDCAdapter:
    """OIDC client for Keycloak realm endpoints."""

    def __init__(self) -> None:
        settings = get_settings()
        self._base = str(settings.keycloak_base_url).rstrip("/")
        self._realm = settings.keycloak_realm
        self._client_id = settings.oidc_client_id
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

    def _logout_url(self) -> str:
        return f"{self._base}/realms/{self._realm}/protocol/openid-connect/logout"

    def _revoke_url(self) -> str:
        return f"{self._base}/realms/{self._realm}/protocol/openid-connect/revoke"

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
            FoundationError(ACCOUNT_SETUP_REQUIRED): the credentials are valid
                but the account has pending required actions (expired password,
                admin-requested reset, ...) — KC "Account is not fully set up".
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

    async def refresh_token_grant(self, *, refresh_token: str) -> dict[str, Any]:
        """Exchange a refresh token for a fresh access/refresh token bundle.

        Drives refresh-token *rotation*: Keycloak (with rotation enabled on the
        realm/client) returns a brand-new ``refresh_token`` alongside the new
        ``access_token`` and invalidates the one presented here.  The caller is
        responsible for blacklisting the old token's ``jti`` so a replayed
        rotation is detected.

        Never log ``refresh_token`` or the resulting tokens.

        Raises:
            FoundationError(INVALID_CREDENTIALS): KC returned invalid_grant
                (the refresh token is expired, already rotated, or revoked).
            FoundationError(KEYCLOAK_UNAVAILABLE): network failure.
            FoundationError(KEYCLOAK_ERROR): unexpected 5xx / shape mismatch.
        """
        return await self._token_request(
            {
                "grant_type": "refresh_token",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "refresh_token": refresh_token,
            }
        )

    async def authorization_code_grant(
        self, *, code: str, redirect_uri: str
    ) -> dict[str, Any]:
        """Exchange an OIDC authorization ``code`` for a token bundle.

        Completes the browser SSO login flow: after Keycloak redirects the
        browser back with ``?code=…``, the BFF posts the code here and we
        redeem it at the realm token endpoint (``grant_type=authorization_code``).

        The ``redirect_uri`` MUST be byte-identical to the one used when the
        authorize URL was built — Keycloak validates it.

        Never log ``code`` or the resulting tokens.

        Raises:
            FoundationError(INVALID_CREDENTIALS): KC returned invalid_grant
                (expired / already-redeemed / mismatched code).
            FoundationError(KEYCLOAK_UNAVAILABLE): network failure.
            FoundationError(KEYCLOAK_ERROR): unexpected 5xx / shape mismatch.
        """
        return await self._token_request(
            {
                "grant_type": "authorization_code",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "code": code,
                "redirect_uri": redirect_uri,
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
            if not isinstance(err, dict):
                err = {}
            kc_err = err.get("error", "")
            if kc_err == "invalid_grant" and _is_account_setup_required(err):
                log.info(
                    "keycloak.token.account_setup_required",
                    grant=data.get("grant_type"),
                )
                raise FoundationError(
                    ACCOUNT_SETUP_REQUIRED,
                    detail="Account is not fully set up (required actions pending)",
                )
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

    # --------------------------------------------------- logout / revoke
    async def logout_session(self, *, refresh_token: str) -> None:
        """Terminate the Keycloak SSO session behind ``refresh_token``.

        Calls the realm back-channel logout endpoint (Keycloak 18+ accepts a
        ``refresh_token`` form param and ends the associated user session).
        This is the server-side half of single-logout: after this, the refresh
        token can no longer be rotated at Keycloak.

        *Best-effort*: logging out an already-expired/already-logged-out token
        is a no-op success, not an error — Keycloak returns 204 (or 400
        ``invalid_grant`` for a stale token), both of which we treat as "session
        is gone", which is the desired end state.  Only network failures and
        unexpected 5xx surface as errors so the caller can decide whether to
        still mark the local session revoked.

        Raises:
            FoundationError(KEYCLOAK_UNAVAILABLE): network failure.
            FoundationError(KEYCLOAK_ERROR): unexpected 5xx.
        """
        await self._post_terminate(
            self._logout_url(),
            {
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "refresh_token": refresh_token,
            },
            op="logout",
        )

    async def revoke_token(
        self, *, token: str, token_type_hint: str = "refresh_token"  # noqa: S107 — RFC 7009 param name, not a secret
    ) -> None:
        """Revoke a single token at the realm revocation endpoint (RFC 7009).

        Used to invalidate an access or refresh token immediately rather than
        waiting for expiry.  Pass ``token_type_hint="access_token"`` when
        revoking an access token.

        *Best-effort*, same contract as :meth:`logout_session`: revoking an
        already-invalid token returns 200 per RFC 7009 §2.2, so only transport
        failures and 5xx are raised.

        Raises:
            FoundationError(KEYCLOAK_UNAVAILABLE): network failure.
            FoundationError(KEYCLOAK_ERROR): unexpected 5xx.
        """
        await self._post_terminate(
            self._revoke_url(),
            {
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "token": token,
                "token_type_hint": token_type_hint,
            },
            op="revoke",
        )

    async def _post_terminate(
        self, url: str, data: dict[str, str], *, op: str
    ) -> None:
        """Shared POST for logout/revoke — tolerant of already-invalid tokens.

        2xx and 400 are both "the token/session is gone" (success); 5xx and
        transport errors raise so the caller can react.
        """
        client = self._new_client()
        try:
            try:
                resp = await client.post(url, data=data)
            except httpx.HTTPError as exc:
                raise FoundationError(KEYCLOAK_UNAVAILABLE, detail=str(exc)) from exc
        finally:
            await client.aclose()

        # 2xx → terminated; 400 → token already stale/invalid → same end state.
        if resp.status_code < 400 or resp.status_code == 400:
            return
        log.warning(
            f"keycloak.{op}.unexpected_status",
            status=resp.status_code,
            body=resp.text[:500],
        )
        raise FoundationError(
            KEYCLOAK_ERROR,
            detail=f"{op} endpoint {resp.status_code}",
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
        # Keycloak derives the token issuer from the request host, so the same
        # realm is a *different* issuer depending on whether it was reached via
        # the in-cluster URL (keycloak:8080, password/service grants) or the
        # browser-facing URL (127.0.0.1:8080, authorization-code flows).  Both
        # are this deployment's realm — accept either.
        allowed_issuers = {str(settings.jwt_issuer).rstrip("/")}
        public_base = getattr(settings, "keycloak_public_base_url", None)
        if public_base:
            allowed_issuers.add(
                f"{str(public_base).rstrip('/')}/realms/{settings.keycloak_realm}"
            )
        try:
            claims = jwt.decode(
                token,
                keys[0],
                algorithms=[unverified_header.get("alg", "RS256")],
                options={
                    # We don't enforce audience here; see docstring.
                    "verify_aud": False,
                    # Issuer is checked manually below against the allowed set.
                    "verify_iss": False,
                },
            )
        except ExpiredSignatureError as exc:
            raise FoundationError(TOKEN_EXPIRED, detail=str(exc)) from exc
        except JWTError as exc:
            raise FoundationError(TOKEN_INVALID, detail=str(exc)) from exc
        if claims.get("iss", "").rstrip("/") not in allowed_issuers:
            raise FoundationError(TOKEN_INVALID, detail="Invalid issuer")
        return claims  # type: ignore[no-any-return]


_singleton: KeycloakOIDCAdapter | None = None


def get_keycloak_oidc() -> KeycloakOIDCAdapter:
    """Module-level singleton; tests override via FastAPI dependency_overrides."""
    global _singleton
    if _singleton is None:
        _singleton = KeycloakOIDCAdapter()
    return _singleton
