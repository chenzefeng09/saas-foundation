"""Error hierarchy mapping HTTP error responses (RFC 9457) to typed exceptions.

See docs/errors.md §11 for the full taxonomy. SDK transport layer is
responsible for parsing application/problem+json and raising the appropriate
subclass.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class FieldError:
    """One field-level error from a 422 ValidationError response."""

    field: str  # JSON Pointer
    code: str
    detail: str
    user_message: str | None = None


class FoundationError(Exception):
    """Base class for all errors returned by Foundation services.

    Attributes (populated from RFC 9457 Problem Details response):
        code: machine-readable error code (e.g. FOUNDATION.IDENTITY.AUTH.INVALID_CREDENTIALS)
        http_status: HTTP status code
        title: short English title
        detail: developer-facing description
        user_message: localized end-user message
        request_id: request correlation ID
        trace_id: OTel trace ID
        retry_after: optional seconds to wait before retry
        caused_by: optional upstream error (for cross-service propagation)
        field_errors: per-field errors (only for ValidationError)
        raw: original response body for debugging
    """

    # Subclasses should override these as class attributes when known
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
        caused_by: "FoundationError | None" = None,
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
        self.caused_by = caused_by
        self.field_errors = field_errors or []
        self.raw = raw or {}
        super().__init__(f"[{self.code}] {self.detail or self.title}")


# ---------------------------------------------------------------------------
# Category base classes — subclass these per-service for concrete errors
# ---------------------------------------------------------------------------


class AuthError(FoundationError):
    """401 — authentication failed / token invalid / token missing."""

    default_http_status = 401


class PolicyError(FoundationError):
    """403 — authenticated but not authorized."""

    default_http_status = 403


class InputError(FoundationError):
    """400 — malformed request input."""

    default_http_status = 400


class ValidationError(FoundationError):
    """422 — semantic validation failed; see `field_errors`."""

    default_http_status = 422


class ResourceNotFoundError(FoundationError):
    """404 — resource does not exist (or caller has no permission to know)."""

    default_http_status = 404


class ConflictError(FoundationError):
    """409 — resource state conflict (already exists / state transition forbidden)."""

    default_http_status = 409


class StaleVersionError(FoundationError):
    """412 — optimistic lock failed (If-Match)."""

    default_http_status = 412


class QuotaExceededError(FoundationError):
    """429 — quota exceeded; check `retry_after`."""

    default_http_status = 429


class RateLimitedError(FoundationError):
    """429 — rate limit exceeded; check `retry_after`."""

    default_http_status = 429


class DependencyError(FoundationError):
    """502/503/504 — downstream dependency failed; check `caused_by`."""

    default_http_status = 502


class ComplianceError(FoundationError):
    """403 — blocked by compliance policy (DLP / cross-border / classification)."""

    default_http_status = 403


class InternalError(FoundationError):
    """500 — unexpected internal error; not safe to retry."""

    default_http_status = 500


# ---------------------------------------------------------------------------
# Status → class mapping for the transport layer
# ---------------------------------------------------------------------------


# Service-specific subclasses may register more specific mappings by code.
# Transport falls back to this status→class map when the code is unknown.
STATUS_TO_CLASS: dict[int, type[FoundationError]] = {
    400: InputError,
    401: AuthError,
    403: PolicyError,
    404: ResourceNotFoundError,
    409: ConflictError,
    412: StaleVersionError,
    422: ValidationError,
    429: RateLimitedError,
    500: InternalError,
    502: DependencyError,
    503: DependencyError,
    504: DependencyError,
}


def from_problem(status: int, body: dict[str, Any]) -> FoundationError:
    """Construct a FoundationError from an RFC 9457 Problem Details response."""
    cls = _CODE_TO_CLASS.get(body.get("code", ""), STATUS_TO_CLASS.get(status, FoundationError))

    field_errors = [
        FieldError(
            field=fe["field"],
            code=fe["code"],
            detail=fe["detail"],
            user_message=fe.get("user_message"),
        )
        for fe in body.get("errors") or []
    ]

    return cls(
        code=body.get("code"),
        http_status=status,
        title=body.get("title", ""),
        detail=body.get("detail", ""),
        user_message=body.get("user_message"),
        request_id=body.get("request_id"),
        trace_id=body.get("trace_id"),
        retry_after=body.get("retry_after"),
        field_errors=field_errors,
        raw=body,
    )


# Concrete service SDKs register their specific error classes here at import time.
# Example (in foundation_identity.errors):
#   class InvalidCredentialsError(AuthError):
#       default_code = "FOUNDATION.IDENTITY.AUTH.INVALID_CREDENTIALS"
#   register_error_class(InvalidCredentialsError)
_CODE_TO_CLASS: dict[str, type[FoundationError]] = {}


def register_error_class(cls: type[FoundationError]) -> None:
    """Register a service-specific error subclass so from_problem returns it."""
    _CODE_TO_CLASS[cls.default_code] = cls
