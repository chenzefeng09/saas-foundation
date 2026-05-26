"""Verify RFC 9457 → typed-exception mapping."""

from __future__ import annotations

from foundation_template.errors import (
    AuthError,
    ConflictError,
    DependencyError,
    FoundationError,
    QuotaExceededError,
    ResourceNotFoundError,
    ValidationError,
    from_problem,
    register_error_class,
)


def test_status_to_class_mapping():
    err = from_problem(401, {"code": "FOUNDATION.X.AUTH.FOO", "detail": "bad"})
    assert isinstance(err, AuthError)
    assert err.code == "FOUNDATION.X.AUTH.FOO"
    assert err.http_status == 401

    err = from_problem(404, {"code": "FOUNDATION.X.RESOURCE.NOT_FOUND", "detail": "x"})
    assert isinstance(err, ResourceNotFoundError)

    err = from_problem(409, {"code": "FOUNDATION.X.RESOURCE.ALREADY_EXISTS", "detail": "x"})
    assert isinstance(err, ConflictError)

    err = from_problem(422, {"code": "FOUNDATION.X.INPUT.VALIDATION_FAILED", "detail": "x"})
    assert isinstance(err, ValidationError)

    err = from_problem(429, {"code": "FOUNDATION.X.QUOTA.EXCEEDED", "detail": "x"})
    # 429 default maps to RateLimitedError; QuotaExceededError must be registered
    # for code-based override (see test_code_specific_override).

    err = from_problem(503, {"code": "FOUNDATION.X.DEPENDENCY.UNAVAILABLE", "detail": "x"})
    assert isinstance(err, DependencyError)


def test_code_specific_override():
    class MyQuotaErr(QuotaExceededError):
        default_code = "FOUNDATION.BILLING.QUOTA.EXCEEDED"

    register_error_class(MyQuotaErr)
    err = from_problem(429, {"code": "FOUNDATION.BILLING.QUOTA.EXCEEDED", "detail": "x"})
    assert isinstance(err, MyQuotaErr)


def test_validation_error_carries_field_errors():
    err = from_problem(
        422,
        {
            "code": "FOUNDATION._.INPUT.VALIDATION_FAILED",
            "detail": "Validation failed",
            "errors": [
                {"field": "/email", "code": "INVALID_EMAIL_FORMAT", "detail": "bad email"},
                {"field": "/password", "code": "PASSWORD_TOO_WEAK", "detail": "weak",
                 "user_message": "密码太弱"},
            ],
        },
    )
    assert isinstance(err, ValidationError)
    assert len(err.field_errors) == 2
    assert err.field_errors[0].field == "/email"
    assert err.field_errors[1].user_message == "密码太弱"


def test_unknown_code_falls_back_to_status_class():
    err = from_problem(403, {"code": "FOUNDATION.UNKNOWN.X.Y", "detail": "x"})
    assert isinstance(err, FoundationError)
    assert err.http_status == 403
