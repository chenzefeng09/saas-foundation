"""Shared FastAPI helpers for business-layer services.

Why this lives in the SDK
-------------------------
Every business service that fronts foundation APIs has historically copied
the same three middlewares and exception handler set-up:

* ``X-Request-Id`` propagation (read header, generate ULID if absent, echo back
  on the response, expose to log/audit via a contextvar).
* ``X-Tenant-Id`` / ``X-User-Id`` extraction into a contextvar so downstream
  ``Depends(current_tenant)`` can read it without re-parsing headers.
* RFC 9457 Problem-Details exception handler that returns a generic detail
  (never ``str(exc)``) plus the request id so ops can correlate.

By the time agent-platform's B-M1 review landed, three services had a copy
of each of those (~150 LoC duplicated, three places to update for any
behaviour change).  This module exposes the same behaviour once so each
service can wire it in with two lines::

    from foundation_sdk.fastapi import install_request_context, register_problem_details
    install_request_context(app, service_name="agent-bff", service_version="0.1.0a1")
    register_problem_details(app, internal_code="AGENT.BFF.INTERNAL")

It is intentionally framework-coupled (FastAPI/Starlette) and therefore
behind the ``[fastapi]`` extra in ``pyproject.toml``; SDK consumers that
don't run a FastAPI server (workers, CLIs) never pay the import cost.
"""

from __future__ import annotations

import logging
import uuid
from contextvars import ContextVar
from typing import TYPE_CHECKING

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

if TYPE_CHECKING:
    pass

__all__ = [
    "install_request_context",
    "register_problem_details",
    "get_request_id",
    "get_tenant_id",
    "get_user_id",
    "get_clearance",
    "push_identity",
    "RequestContextMiddleware",
]

logger = logging.getLogger(__name__)

# Public contextvars — services import these directly so a single set of
# vars carries identity through the request, regardless of which service
# is running.  Defaults are empty strings so callers don't have to
# distinguish "unset" from "explicitly blank".
_request_id_var: ContextVar[str] = ContextVar("foundation.request_id", default="")
_tenant_id_var: ContextVar[str] = ContextVar("foundation.tenant_id", default="")
_user_id_var: ContextVar[str] = ContextVar("foundation.user_id", default="")
_clearance_var: ContextVar[str] = ContextVar("foundation.clearance", default="")


def get_request_id() -> str:
    return _request_id_var.get()


def get_tenant_id() -> str:
    return _tenant_id_var.get()


def get_user_id() -> str:
    return _user_id_var.get()


def get_clearance() -> str:
    return _clearance_var.get()


def push_identity(*, tenant_id: str, user_id: str) -> None:
    """Overwrite the contextvars from a non-header source.

    Use case: a BFF that derives identity from a signed cookie rather than
    request headers needs to populate the same vars so downstream
    ``Depends(current_tenant)`` works without special-casing the BFF.
    Should be called early in the request (e.g. from a middleware that
    runs *after* :class:`RequestContextMiddleware`).
    """
    _tenant_id_var.set(tenant_id)
    _user_id_var.set(user_id)


def _new_request_id() -> str:
    return f"req_{uuid.uuid4().hex[:26].upper()}"


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Combine request-id propagation and tenant/user header extraction.

    Two middlewares used to be split (RequestIdMiddleware +
    TenantContextMiddleware); combining them avoids two passes through
    Starlette's middleware stack for what is essentially the same job —
    reading a few headers into contextvars.
    """

    def __init__(
        self,
        app: object,
        *,
        service_name: str,
        service_version: str,
    ) -> None:
        super().__init__(app)
        self._service_name = service_name
        self._service_version = service_version

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint,
    ) -> Response:
        request_id = request.headers.get("X-Request-Id") or _new_request_id()
        _request_id_var.set(request_id)

        # Tenant / user headers are populated unconditionally; downstream
        # ``current_tenant`` dependency decides whether an empty value is
        # an error (e.g. a write endpoint) or fine (e.g. /healthz).
        _tenant_id_var.set(request.headers.get("X-Tenant-Id", ""))
        _user_id_var.set(request.headers.get("X-User-Id", ""))
        _clearance_var.set(request.headers.get("X-User-Clearance", ""))

        response = await call_next(request)
        response.headers["X-Request-Id"] = request_id
        response.headers["X-Service-Name"] = self._service_name
        response.headers["X-Service-Version"] = self._service_version
        return response


def install_request_context(
    app: FastAPI, *, service_name: str, service_version: str,
) -> None:
    """Register :class:`RequestContextMiddleware` on the given app."""
    app.add_middleware(
        RequestContextMiddleware,
        service_name=service_name,
        service_version=service_version,
    )


def register_problem_details(
    app: FastAPI,
    *,
    internal_code: str,
    error_namespace: str = "https://agent-platform.dev/errors",
) -> None:
    """Register a catch-all RFC 9457 fallback handler.

    The handler:

    * **Never** echoes ``str(exc)`` to the client — exceptions can include SQL
      text, JWT internals, or filesystem paths that a remote caller must not
      see.  The full traceback goes to ``logger.exception`` with the
      request_id; the response just carries the request_id so ops can
      correlate by it.
    * Returns RFC 9457 Problem Details (``type``, ``title``, ``status``,
      ``detail``, ``instance``, ``code``, ``request_id``).
    * Leaves service-specific error handlers (registered via
      ``@app.exception_handler(YourErrorClass)``) untouched — Starlette
      dispatches them first.
    """

    @app.exception_handler(Exception)
    async def fallback_handler(request: Request, exc: Exception) -> JSONResponse:
        request_id = get_request_id()
        logger.exception(
            "unhandled exception",
            extra={
                "request_id": request_id,
                "path": str(request.url.path),
                "method": request.method,
            },
        )
        return JSONResponse(
            status_code=500,
            content={
                "type": f"{error_namespace}/internal",
                "title": "Internal Server Error",
                "status": 500,
                "detail": (
                    "An internal error occurred. "
                    "Provide request_id when asking ops."
                ),
                "instance": str(request.url.path),
                "code": internal_code,
                "request_id": request_id,
            },
        )
