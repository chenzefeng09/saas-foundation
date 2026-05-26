"""ASGI middleware: parse tenant + request context, populate FoundationContext.

Order (outer → inner):
    1. RequestIdMiddleware    — ensures X-Request-Id is generated if absent
    2. TenantContextMiddleware — extracts tenant_id / user_id / actor from headers,
                                  validates pattern, stashes in contextvars
"""

from __future__ import annotations

import re

import structlog
import ulid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from foundation_identity.domain.base import FoundationContext, foundation_context

REQUEST_ID_HEADER = "X-Request-Id"
TENANT_ID_HEADER = "X-Tenant-Id"
USER_ID_HEADER = "X-User-Id"
ACTOR_HEADER = "X-Actor"  # USER / SERVICE / SYSTEM / ADMIN — gateway sets

REQUEST_ID_PATTERN = re.compile(r"^req_[0-9A-Z]{26}$")
TENANT_ID_PATTERN = re.compile(r"^tnt_[0-9A-Z]{26}$")
USER_ID_PATTERN = re.compile(r"^usr_[0-9A-Z]{26}$")
ACTOR_VALUES = frozenset({"USER", "SERVICE", "SYSTEM", "MIGRATOR", "ADMIN"})

# Paths that DO NOT require tenant context (must match settings.api_prefix-relative routes)
PUBLIC_PATHS = frozenset({"/healthz", "/readyz", "/metrics", "/docs", "/openapi.json", "/redoc"})


class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        rid = request.headers.get(REQUEST_ID_HEADER)
        if rid is None or not REQUEST_ID_PATTERN.match(rid):
            rid = f"req_{ulid.new()!s}"

        # Stash on request.state for handlers / exception handler to read
        request.state.request_id = rid

        # Bind to structlog contextvars so all logs in this request carry rid
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=rid, path=request.url.path)

        response = await call_next(request)
        response.headers[REQUEST_ID_HEADER] = rid
        return response


class TenantContextMiddleware(BaseHTTPMiddleware):
    """Build FoundationContext from gateway-injected headers and stash in contextvars.

    Public paths are skipped. JWT signature verification is the gateway's job
    (Envoy + Keycloak JWKS); this service trusts the X-* headers because gateway
    *replaces* any client-provided values.
    """

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
            return _problem_response(
                status=400,
                code="FOUNDATION.IDENTITY.INPUT.INVALID_FORMAT",
                detail=f"Invalid {TENANT_ID_HEADER} format",
                instance=request.url.path,
                request_id=request_id,
            )
        if user_id and not USER_ID_PATTERN.match(user_id):
            return _problem_response(
                status=400,
                code="FOUNDATION.IDENTITY.INPUT.INVALID_FORMAT",
                detail=f"Invalid {USER_ID_HEADER} format",
                instance=request.url.path,
                request_id=request_id,
            )
        if actor not in ACTOR_VALUES:
            return _problem_response(
                status=400,
                code="FOUNDATION.IDENTITY.INPUT.INVALID_FORMAT",
                detail=f"Invalid {ACTOR_HEADER} value",
                instance=request.url.path,
                request_id=request_id,
            )

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


def _problem_response(
    *,
    status: int,
    code: str,
    detail: str,
    instance: str,
    request_id: str,
) -> Response:
    """Inline RFC 9457 problem response (avoid importing FastAPI exception handler here)."""
    from datetime import UTC, datetime
    import json

    body = json.dumps(
        {
            "type": f"https://errors.foundation.example.com/{code.lower().replace('.', '/')}",
            "title": "Bad Request",
            "status": status,
            "code": code,
            "detail": detail,
            "instance": instance,
            "request_id": request_id,
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )
    return Response(
        content=body,
        status_code=status,
        media_type="application/problem+json",
        headers={REQUEST_ID_HEADER: request_id},
    )
