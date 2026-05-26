"""ASGI middleware: parse tenant + request context."""

from __future__ import annotations

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
ACTOR_HEADER = "X-Actor"

REQUEST_ID_PATTERN = re.compile(r"^req_[0-9A-Z]{26}$")
TENANT_ID_PATTERN = re.compile(r"^tnt_[0-9A-Z]{26}$")
USER_ID_PATTERN = re.compile(r"^usr_[0-9A-Z]{26}$")
ACTOR_VALUES = frozenset({"USER", "SERVICE", "SYSTEM", "MIGRATOR", "ADMIN"})

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
            return _problem(400, "FOUNDATION.AUTHZ.INPUT.INVALID_FORMAT",
                            f"Invalid {ACTOR_HEADER} value", request.url.path, request_id)

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
