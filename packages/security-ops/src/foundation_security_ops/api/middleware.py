import json
import re
from datetime import UTC, datetime
from typing import TypeGuard, get_args

import structlog
import ulid
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from foundation_security_ops.domain.base import ActorKind, FoundationContext, foundation_context

RID = re.compile(r"^req_[0-9A-Z]{26}$")
TID = re.compile(r"^tnt_[0-9A-Z]{26}$")
ACTORS: frozenset[str] = frozenset(get_args(ActorKind))

PUB = frozenset({"/healthz", "/readyz", "/metrics", "/docs", "/openapi.json", "/redoc"})


def _is_actor(value: str) -> TypeGuard[ActorKind]:
    return value in ACTORS


class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, r: Request, call_next: RequestResponseEndpoint) -> Response:
        rid = r.headers.get("X-Request-Id")
        if not rid or not RID.match(rid):
            rid = f"req_{ulid.new()!s}"
        r.state.request_id = rid
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=rid, path=r.url.path)
        resp = await call_next(r)
        resp.headers["X-Request-Id"] = rid
        return resp


class TenantContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, r: Request, call_next: RequestResponseEndpoint) -> Response:
        if any(r.url.path.endswith(p) for p in PUB):
            return await call_next(r)
        tid = r.headers.get("X-Tenant-Id")
        uid = r.headers.get("X-User-Id")
        actor = r.headers.get("X-Actor", "SERVICE")
        rid = getattr(r.state, "request_id", "")
        if tid and not TID.match(tid):
            return _problem(
                400,
                "FOUNDATION.SECURITY_OPS.INPUT.INVALID_FORMAT",
                "Invalid X-Tenant-Id",
                r.url.path,
                rid,
            )
        # app.actor drives the RLS policies, so an unknown value is rejected here
        # rather than reaching the database as an arbitrary string.
        if not _is_actor(actor):
            return _problem(
                400,
                "FOUNDATION.SECURITY_OPS.INPUT.INVALID_FORMAT",
                "Invalid X-Actor",
                r.url.path,
                rid,
            )
        ctx = FoundationContext(tenant_id=tid or "", user_id=uid, actor=actor, request_id=rid)
        token = foundation_context.set(ctx)
        try:
            return await call_next(r)
        finally:
            foundation_context.reset(token)


def _problem(status: int, code: str, detail: str, instance: str, rid: str) -> Response:
    body = json.dumps(
        {
            "type": f"https://errors.foundation.example.com/{code.lower().replace('.', '/')}",
            "title": "Bad Request",
            "status": status,
            "code": code,
            "detail": detail,
            "instance": instance,
            "request_id": rid,
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )
    return Response(
        content=body,
        status_code=status,
        media_type="application/problem+json",
        headers={"X-Request-Id": rid},
    )
