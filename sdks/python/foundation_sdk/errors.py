"""Error hierarchy for Foundation SDK."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class FieldError:
    field: str
    code: str
    detail: str
    user_message: str | None = None


class FoundationError(Exception):
    default_code: str = "FOUNDATION._.INTERNAL.UNEXPECTED"
    default_http_status: int = 500

    def __init__(
        self,
        *,
        code: str | None = None,
        http_status: int | None = None,
        title: str = "",
        detail: str = "",
        user_message: str | None = None,
        request_id: str | None = None,
        trace_id: str | None = None,
        retry_after: int | None = None,
        field_errors: list[FieldError] | None = None,
        raw: dict[str, Any] | None = None,
    ) -> None:
        self.code = code or self.default_code
        self.http_status = http_status or self.default_http_status
        self.title = title
        self.detail = detail
        self.user_message = user_message
        self.request_id = request_id
        self.trace_id = trace_id
        self.retry_after = retry_after
        self.field_errors = field_errors or []
        self.raw = raw or {}
        super().__init__(f"[{self.code}] {self.detail or self.title}")


class AuthError(FoundationError):
    default_http_status = 401


class PolicyError(FoundationError):
    default_http_status = 403


class InputError(FoundationError):
    default_http_status = 400


class ValidationError(FoundationError):
    default_http_status = 422


class ResourceNotFoundError(FoundationError):
    default_http_status = 404


class ConflictError(FoundationError):
    default_http_status = 409


class QuotaExceededError(FoundationError):
    default_http_status = 429


class RateLimitedError(FoundationError):
    default_http_status = 429


class DependencyError(FoundationError):
    default_http_status = 502


class ComplianceError(FoundationError):
    default_http_status = 403


class InternalError(FoundationError):
    default_http_status = 500


STATUS_TO_CLASS: dict[int, type[FoundationError]] = {
    400: InputError, 401: AuthError, 403: PolicyError,
    404: ResourceNotFoundError, 409: ConflictError,
    422: ValidationError, 429: RateLimitedError,
    500: InternalError, 502: DependencyError,
    503: DependencyError, 504: DependencyError,
}


_CODE_TO_CLASS: dict[str, type[FoundationError]] = {}


def register_error_class(cls: type[FoundationError]) -> None:
    _CODE_TO_CLASS[cls.default_code] = cls


def from_problem(status: int, body: dict[str, Any]) -> FoundationError:
    cls = _CODE_TO_CLASS.get(body.get("code", ""), STATUS_TO_CLASS.get(status, FoundationError))
    field_errors = [
        FieldError(field=fe["field"], code=fe["code"], detail=fe["detail"],
                   user_message=fe.get("user_message"))
        for fe in body.get("errors") or []
    ]
    return cls(
        code=body.get("code"), http_status=status,
        title=body.get("title", ""), detail=body.get("detail", ""),
        user_message=body.get("user_message"),
        request_id=body.get("request_id"), trace_id=body.get("trace_id"),
        retry_after=body.get("retry_after"), field_errors=field_errors, raw=body,
    )
