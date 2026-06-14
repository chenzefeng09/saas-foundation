"""ASGI middleware: parse tenant + request context."""

from __future__ import annotations

import hmac
import re

import structlog
import ulid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from foundation_authz.domain.base import FoundationContext, foundation_context

REQUEST_ID_HEADER = "X-Request-Id"
TENANT_ID_HEADER = "X-Tenant-Id"
USER_ID_HEADER = "X-User-Id"
ACTOR_HEADER = "X-Actor"  # USER / SERVICE / SYSTEM / MIGRATOR — gateway sets

# Header used by platform-internal callers (the BFF admin path) to assert ADMIN
# authority.  The value is a pre-shared secret stored in AUTHZ_INTERNAL_ADMIN_TOKEN;
# callers that present the correct token are allowed to have actor=ADMIN (which the
# admin_all RLS policies honour to bypass tenant isolation).  External/client
# requests MUST NOT know this secret.
INTERNAL_ADMIN_TOKEN_HEADER = "X-Internal-Admin-Token"

REQUEST_ID_PATTERN = re.compile(r"^req_[0-9A-Z]{26}$")
TENANT_ID_PATTERN = re.compile(r"^tnt_[0-9A-Z]{26}$")
USER_ID_PATTERN = re.compile(r"^usr_[0-9A-Z]{26}$")
# ADMIN is intentionally absent: clients may NOT request actor=ADMIN via header.
# actor=ADMIN is only granted internally after a valid X-Internal-Admin-Token.
ACTOR_VALUES = frozenset({"USER", "SERVICE", "SYSTEM", "MIGRATOR"})

PUBLIC_PATHS = frozenset({"/healthz", "/readyz", "/metrics", "/docs", "/openapi.json", "/redoc"})


class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        rid = request.headers.get(REQUEST_ID_HEADER)
        if rid is None or not REQUEST_ID_PATTERN.match(rid):
            rid = f"req_{ulid.new()!s}"
        request.state.request_id = rid
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=rid, path=request.url.path)
        response = await call_next(request)
        response.headers[REQUEST_ID_HEADER] = rid
        return response


class TenantContextMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        if any(request.url.path.endswith(p) for p in PUBLIC_PATHS):
            return await call_next(request)

        tenant_id = request.headers.get(TENANT_ID_HEADER)
        user_id = request.headers.get(USER_ID_HEADER)
        actor = request.headers.get(ACTOR_HEADER, "USER")
        request_id = getattr(request.state, "request_id", "")

        if tenant_id and not TENANT_ID_PATTERN.match(tenant_id):
            return _problem(400, "FOUNDATION.AUTHZ.INPUT.INVALID_FORMAT",
                            f"Invalid {TENANT_ID_HEADER} format", request.url.path, request_id)
        if user_id and not USER_ID_PATTERN.match(user_id):
            return _problem(400, "FOUNDATION.AUTHZ.INPUT.INVALID_FORMAT",
                            f"Invalid {USER_ID_HEADER} format", request.url.path, request_id)
        if actor not in ACTOR_VALUES:
            # ADMIN (or any other unrecognised value) → silently downgrade to USER
            # rather than returning 400.  This prevents the caller from probing which
            # values are "valid but forbidden" (ADMIN) vs "syntactically wrong", and
            # ensures a raw external X-Actor=ADMIN never grants ADMIN authority.
            actor = "USER"

        # Internal-admin re-elevation: only AFTER the downgrade above, a caller that
        # presents the correct pre-shared X-Internal-Admin-Token may assert ADMIN.
        # The configured token must be non-empty (empty disables the feature).
        admin_token = request.headers.get(INTERNAL_ADMIN_TOKEN_HEADER)
        if admin_token:
            configured = _internal_admin_token(request)
            # Constant-time comparison defeats timing side-channels that could let
            # an attacker recover the pre-shared token byte-by-byte.  ``configured``
            # being empty short-circuits before compare_digest so the empty-disables
            # semantics are preserved; both operands are ``str`` here.
            if configured and hmac.compare_digest(admin_token, configured):
                actor = "ADMIN"

        token = None
        if tenant_id:
            ctx = FoundationContext(
                tenant_id=tenant_id,
                user_id=user_id,
                actor=actor,  # type: ignore[arg-type]
                request_id=request_id,
            )
            token = foundation_context.set(ctx)
            structlog.contextvars.bind_contextvars(
                tenant_id=tenant_id, user_id=user_id, actor=actor
            )
        try:
            return await call_next(request)
        finally:
            if token is not None:
                foundation_context.reset(token)


def _internal_admin_token(request: Request) -> str:
    """Resolve the configured internal-admin token (plaintext).

    Prefers ``request.app.state.settings`` (set in ``create_app``) so tests can
    override it per-app; falls back to the process-wide cached ``get_settings()``.
    Returns ``""`` when unset/disabled.
    """
    settings = getattr(request.app.state, "settings", None)
    if settings is None:
        from foundation_authz.config import get_settings

        settings = get_settings()
    token = settings.internal_admin_token
    # SecretStr → str; tolerate plain-str overrides in tests.
    return token.get_secret_value() if hasattr(token, "get_secret_value") else str(token)


def _problem(status: int, code: str, detail: str, instance: str, request_id: str) -> Response:
    from datetime import UTC, datetime
    import json

    body = json.dumps({
        "type": f"https://errors.foundation.example.com/{code.lower().replace('.', '/')}",
        "title": "Bad Request",
        "status": status,
        "code": code,
        "detail": detail,
        "instance": instance,
        "request_id": request_id,
        "timestamp": datetime.now(UTC).isoformat(),
    })
    return Response(
        content=body, status_code=status, media_type="application/problem+json",
        headers={REQUEST_ID_HEADER: request_id},
    )
