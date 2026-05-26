"""RFC 9457 problem details exception handlers."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from foundation_authz.errors import UNEXPECTED, VALIDATION_FAILED, FoundationError
from foundation_authz.observability import get_logger

log = get_logger(__name__)

_ERROR_TYPE_BASE = "https://errors.foundation.example.com"


def _body(
    *, code: str, title: str, status: int, detail: str, instance: str,
    request_id: str, user_message: str | None = None, extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "type": f"{_ERROR_TYPE_BASE}/{code.lower().replace('.', '/')}",
        "title": title,
        "status": status,
        "code": code,
        "detail": detail,
        "instance": instance,
        "request_id": request_id,
        "timestamp": datetime.now(UTC).isoformat(),
    }
    if user_message is not None:
        out["user_message"] = user_message
    if extra:
        out.update(extra)
    return out


def install_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(FoundationError)
    async def _on_foundation(request: Request, exc: FoundationError) -> JSONResponse:
        ec = exc.error_code
        return JSONResponse(
            status_code=ec.http_status,
            media_type="application/problem+json",
            content=_body(
                code=ec.code, title=ec.title, status=ec.http_status,
                detail=exc.detail, instance=request.url.path,
                request_id=getattr(request.state, "request_id", ""),
                user_message=exc.user_message,
            ),
        )

    @app.exception_handler(RequestValidationError)
    async def _on_validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        ec = VALIDATION_FAILED
        errors = [
            {
                "field": "/" + "/".join(str(p) for p in e["loc"][1:]),
                "code": e["type"].upper().replace(".", "_"),
                "detail": e["msg"],
            }
            for e in exc.errors()
        ]
        return JSONResponse(
            status_code=ec.http_status,
            media_type="application/problem+json",
            content=_body(
                code=ec.code, title=ec.title, status=ec.http_status,
                detail=f"Validation failed for {len(errors)} field(s)",
                instance=request.url.path,
                request_id=getattr(request.state, "request_id", ""),
                extra={"errors": errors},
            ),
        )

    @app.exception_handler(Exception)
    async def _on_unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled.error", path=request.url.path, error=str(exc))
        ec = UNEXPECTED
        return JSONResponse(
            status_code=ec.http_status,
            media_type="application/problem+json",
            content=_body(
                code=ec.code, title=ec.title, status=ec.http_status,
                detail=ec.default_detail, instance=request.url.path,
                request_id=getattr(request.state, "request_id", ""),
                user_message=ec.default_user_message,
            ),
        )
