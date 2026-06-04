"""Cookie / opaque-token signing helpers shared by business-layer BFFs.

Why this lives in the SDK
-------------------------
Business apps (e.g. agent-platform's BFF) need to persist short-lived state
across HTTP requests — typically session metadata such as ``tenant_id`` and
``user_id`` after a successful Keycloak login.  Storing that data unsigned
(plain base64 JSON) lets any client tamper with the tenant ID and trivially
escalate to another tenant.

Rather than every business team reinventing this with subtle bugs, the
foundation SDK ships a single signed-cookie helper backed by
``itsdangerous.URLSafeTimedSerializer`` (HMAC-SHA256 + URL-safe base64 +
embedded timestamp).  Business BFFs construct it once at startup and reuse
the same instance for sign/verify of every cookie.

Security properties
-------------------
* HMAC-SHA256 signature — tampering with payload invalidates the cookie
* Timestamp-bound — verifier rejects cookies older than ``max_age`` seconds
* Per-deployment ``secret_key`` — leaking a secret only impacts that tenant
* ``salt`` lets one secret be reused for multiple cookie families (e.g. a
  short BFF session cookie and a separate CSRF cookie) without cross-use

Intentionally **not** included
------------------------------
* Confidentiality.  Payloads must be considered readable — do **not** put
  secrets in them.  Tenant ID / user ID / display name are fine; password
  hashes / API keys are not.
* JWT.  These cookies are opaque to the browser and never sent to other
  services.  When a service-to-service call needs a JWT, use the
  foundation-issued OIDC access_token instead — see
  ``foundation_sdk.resources.identity.IdentityResource.issue_service_account_token``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

__all__ = [
    "CookieSigner",
    "CookieSignerSettings",
    "SignatureInvalid",
    "SignatureExpiredError",
]


class SignatureInvalid(ValueError):
    """Cookie signature does not match — payload was tampered with or wrong key."""


class SignatureExpiredError(ValueError):
    """Cookie signature is valid but timestamp is older than max_age."""


@dataclass(frozen=True, slots=True)
class CookieSignerSettings:
    """Configuration for :class:`CookieSigner`.

    Attributes:
        secret_key: HMAC secret. **Must be ≥ 32 chars** and never the literal
            string ``"change-me"``-style default; ``CookieSigner.__post_init__``
            enforces this so a forgotten env var crashes loudly at startup
            instead of producing forgeable cookies in production.
        salt: Distinguishes cookies signed with the same secret but for
            different purposes (e.g. ``"bff-session"`` vs ``"bff-csrf"``).
            Defaults to ``"foundation-cookie"``.
        max_age_seconds: Default expiry for :meth:`CookieSigner.unsign`.
            Individual call sites may override per-cookie.
    """

    secret_key: str
    salt: str = "foundation-cookie"
    max_age_seconds: int = 86_400  # 24h


class CookieSigner:
    """Sign and verify opaque cookie payloads.

    Typical usage in a BFF:

        signer = CookieSigner(CookieSignerSettings(secret_key=settings.cookie_secret))
        token = signer.sign({"user_id": "usr_…", "tenant_id": "tnt_…"})
        response.set_cookie("bff_session", token, httponly=True, samesite="strict")

        # On a later request:
        payload = signer.unsign(request.cookies["bff_session"])
        tenant_id = payload["tenant_id"]
    """

    _FORBIDDEN_SECRET_MARKERS = ("change-me", "changeme", "default", "secret-key-here")
    _MIN_SECRET_LEN = 32

    def __init__(self, settings: CookieSignerSettings) -> None:
        self._validate_secret(settings.secret_key)
        self._settings = settings
        self._serializer = URLSafeTimedSerializer(
            secret_key=settings.secret_key,
            salt=settings.salt,
        )

    @classmethod
    def _validate_secret(cls, secret: str) -> None:
        if len(secret) < cls._MIN_SECRET_LEN:
            raise ValueError(
                f"cookie secret must be ≥ {cls._MIN_SECRET_LEN} chars, got {len(secret)}"
            )
        lowered = secret.lower()
        for marker in cls._FORBIDDEN_SECRET_MARKERS:
            if marker in lowered:
                raise ValueError(
                    f"cookie secret contains forbidden placeholder {marker!r}; "
                    "generate a random value (e.g. `python -c \"import secrets; "
                    "print(secrets.token_urlsafe(48))\"`) and load it from the "
                    "deployment secret manager"
                )

    def sign(self, payload: dict[str, Any]) -> str:
        """Produce a tamper-evident cookie value.

        ``payload`` must be JSON-serialisable; complex types should be coerced
        to primitives by the caller.
        """
        return self._serializer.dumps(payload)

    def unsign(
        self,
        token: str,
        *,
        max_age_seconds: int | None = None,
    ) -> dict[str, Any]:
        """Verify and decode a cookie value.

        Raises:
            SignatureInvalid: token was tampered or signed with a different key.
            SignatureExpiredError: token is valid but past its ``max_age_seconds``.
        """
        ttl = max_age_seconds if max_age_seconds is not None else self._settings.max_age_seconds
        try:
            payload = self._serializer.loads(token, max_age=ttl)
        except SignatureExpired as exc:
            raise SignatureExpiredError("cookie expired") from exc
        except BadSignature as exc:
            raise SignatureInvalid("cookie signature invalid") from exc
        if not isinstance(payload, dict):
            raise SignatureInvalid(f"cookie payload must be dict, got {type(payload).__name__}")
        return payload
