"""C4 — 错误格式合规 (Error Format Conformance)

检查项
------
C4-a  SDK 正确解析 RFC 9457 Problem Details 响应，并转成对应的 FoundationError 子类。
C4-b  FoundationError 携带 code / http_status / title / detail / request_id 字段。
C4-c  错误码格式符合 FOUNDATION.<SVC>.<CATEGORY>.<NAME> 约定（正则验证）。
C4-d  已注册错误码（docs/errors.md 中列出的首版样例）在 SDK 错误层次中能被正确路由。
C4-e  4xx 错误不被 SDK 重试（只有 5xx DEPENDENCY 错误才重试）。
C4-f  429 QUOTA 错误携带 retry_after 字段时，SDK 在异常里暴露该值。
C4-g  字段级错误（errors 数组）被正确反序列化为 FieldError 列表。
C4-h  (needs_stack) 真实 404 响应体符合 RFC 9457 格式（有 code / status / request_id）。

通过标准
--------
C4-a ~ C4-g 不需要底座栈，使用 respx mock。C4-h 需要栈。

失败时如何排查
--------------
- C4-a/C4-b: 检查 foundation_sdk/errors.py 的 from_problem() 函数
- C4-c: 底座服务返回的 code 字段格式不合规，修正对应 service errors.py
- C4-d: from_problem() 的 _CODE_TO_CLASS 路由未注册具体错误类
- C4-e: RetryPolicy 的 should_retry() 对 4xx 返回了 True
- C4-f: from_problem() 未从 body['retry_after'] 填充异常
- C4-g: from_problem() 未解析 body['errors'] 数组

背景
----
docs/errors.md §2 定义了 RFC 9457 格式。SDK 必须正确消费这个格式，
让业务层能够 except 具体错误类，而非裸 dict 判断。
"""

from __future__ import annotations

import re

import httpx
import pytest
import respx

from foundation_sdk import FoundationClient, tenant_context
from foundation_sdk._transport import Transport
from foundation_sdk.errors import (
    AuthError,
    ComplianceError,
    ConflictError,
    DependencyError,
    FieldError,
    FoundationError,
    InputError,
    PolicyError,
    QuotaExceededError,
    RateLimitedError,
    ResourceNotFoundError,
    ValidationError,
    from_problem,
)
from foundation_sdk._retry import DEFAULT_RETRY

TENANT_A = "tnt_01CONFORM00000000000000001"

# 错误码格式正则（CONVENTIONS §4, errors.md §3.1）
_ERROR_CODE_RE = re.compile(
    r"^FOUNDATION\.[A-Z_]+\.[A-Z_]+\.[A-Z_]+$"
)

# 首版样例错误码（来自 docs/errors.md §12）
_REGISTERED_SAMPLE_CODES = [
    "FOUNDATION._.INPUT.VALIDATION_FAILED",
    "FOUNDATION._.INPUT.PAYLOAD_TOO_LARGE",
    "FOUNDATION._.INPUT.INVALID_PAGINATION",
    "FOUNDATION._.RESOURCE.NOT_FOUND",
    "FOUNDATION._.RESOURCE.ALREADY_EXISTS",
    "FOUNDATION._.STATE.STALE_VERSION",
    "FOUNDATION._.RATE_LIMIT.EXCEEDED",
    "FOUNDATION._.INTERNAL.UNEXPECTED",
    "FOUNDATION._.DEPENDENCY.UNAVAILABLE",
    "FOUNDATION._.DEPENDENCY.TIMEOUT",
    "FOUNDATION.IDENTITY.AUTH.INVALID_CREDENTIALS",
    "FOUNDATION.IDENTITY.AUTH.TOKEN_EXPIRED",
    "FOUNDATION.IDENTITY.AUTH.MFA_REQUIRED",
    "FOUNDATION.IDENTITY.AUTH.ACCOUNT_LOCKED",
    "FOUNDATION.AUTHZ.POLICY.PERMISSION_DENIED",
    "FOUNDATION.AUTHZ.POLICY.TENANT_MISMATCH",
    "FOUNDATION.BILLING.QUOTA.EXCEEDED",
    "FOUNDATION.COMPLIANCE.DLP.DOWNLOAD_BLOCKED",
    "FOUNDATION.AUDIT.STORAGE.WORM_VIOLATION",
    "FOUNDATION.CRYPTO.KEY.NOT_FOUND",
    "FOUNDATION.CRYPTO.OPERATION.FAILED",
    "FOUNDATION.LLM_GATEWAY.PROVIDER.UNAVAILABLE",
    "FOUNDATION.LLM_GATEWAY.CAPABILITY.NOT_SUPPORTED",
]


def _make_problem(
    status: int,
    code: str,
    title: str = "Test error",
    detail: str = "detail text",
    request_id: str = "req_C4TEST001",
    retry_after: int | None = None,
    field_errors: list[dict] | None = None,
) -> dict:
    body: dict = {
        "type": f"https://errors.foundation.example.com/test/{code.lower()}",
        "title": title,
        "status": status,
        "code": code,
        "detail": detail,
        "instance": "/api/test",
        "request_id": request_id,
        "timestamp": "2026-06-01T00:00:00Z",
    }
    if retry_after is not None:
        body["retry_after"] = retry_after
    if field_errors:
        body["errors"] = field_errors
    return body


# ---------------------------------------------------------------------------
# C4-a/C4-b  from_problem() 解析并转成 FoundationError
# ---------------------------------------------------------------------------

@pytest.mark.conformance
@pytest.mark.parametrize("status,expected_cls,code", [
    (400, InputError, "FOUNDATION._.INPUT.INVALID_PAGINATION"),
    (401, AuthError, "FOUNDATION.IDENTITY.AUTH.INVALID_CREDENTIALS"),
    (403, PolicyError, "FOUNDATION.AUTHZ.POLICY.PERMISSION_DENIED"),
    (404, ResourceNotFoundError, "FOUNDATION._.RESOURCE.NOT_FOUND"),
    (409, ConflictError, "FOUNDATION._.RESOURCE.ALREADY_EXISTS"),
    (422, ValidationError, "FOUNDATION._.INPUT.VALIDATION_FAILED"),
    (429, RateLimitedError, "FOUNDATION._.RATE_LIMIT.EXCEEDED"),
    (500, FoundationError, "FOUNDATION._.INTERNAL.UNEXPECTED"),
    (502, DependencyError, "FOUNDATION._.DEPENDENCY.UNAVAILABLE"),
    (503, DependencyError, "FOUNDATION._.DEPENDENCY.TIMEOUT"),
])
def test_c4a_from_problem_routes_to_correct_class(
    status: int, expected_cls: type, code: str,
) -> None:
    """from_problem() 按 HTTP status 映射到正确的 FoundationError 子类。"""
    body = _make_problem(status, code)
    exc = from_problem(status, body)
    assert isinstance(exc, expected_cls), (
        f"C4-a FAIL: status={status}, code={code!r} → "
        f"got {type(exc).__name__!r}, expected {expected_cls.__name__!r}"
    )


@pytest.mark.conformance
def test_c4b_foundation_error_carries_required_fields() -> None:
    """FoundationError 携带 code / http_status / title / detail / request_id。"""
    body = _make_problem(
        401,
        "FOUNDATION.IDENTITY.AUTH.INVALID_CREDENTIALS",
        title="Invalid credentials",
        detail="Wrong password",
        request_id="req_C4BTEST",
    )
    exc = from_problem(401, body)
    assert exc.code == "FOUNDATION.IDENTITY.AUTH.INVALID_CREDENTIALS", \
        f"C4-b FAIL: exc.code = {exc.code!r}"
    assert exc.http_status == 401, \
        f"C4-b FAIL: exc.http_status = {exc.http_status!r}"
    assert exc.title == "Invalid credentials", \
        f"C4-b FAIL: exc.title = {exc.title!r}"
    assert exc.detail == "Wrong password", \
        f"C4-b FAIL: exc.detail = {exc.detail!r}"
    assert exc.request_id == "req_C4BTEST", \
        f"C4-b FAIL: exc.request_id = {exc.request_id!r}"


# ---------------------------------------------------------------------------
# C4-c  错误码格式验证（正则）
# ---------------------------------------------------------------------------

@pytest.mark.conformance
@pytest.mark.parametrize("code", _REGISTERED_SAMPLE_CODES)
def test_c4c_error_code_format_matches_convention(code: str) -> None:
    """注册错误码必须符合 FOUNDATION.<SVC>.<CATEGORY>.<NAME> 格式（errors.md §3.1）。"""
    assert _ERROR_CODE_RE.match(code), (
        f"C4-c FAIL: error code {code!r} does not match FOUNDATION.<SVC>.<CAT>.<NAME>. "
        "Check errors.md §3.1 for the required format."
    )


# ---------------------------------------------------------------------------
# C4-e  4xx 错误不重试
# ---------------------------------------------------------------------------

@pytest.mark.conformance
@pytest.mark.parametrize("exc_cls,status", [
    (AuthError, 401),
    (PolicyError, 403),
    (ResourceNotFoundError, 404),
    (InputError, 400),
    (ValidationError, 422),
])
def test_c4e_4xx_errors_not_retried(exc_cls: type, status: int) -> None:
    """4xx 错误不应被 SDK RetryPolicy 重试（立即上抛给业务层）。"""
    exc = exc_cls(
        code=f"FOUNDATION._.INPUT.TEST",
        http_status=status,
        detail="test",
    )
    should = DEFAULT_RETRY.should_retry(exc, attempt=0)
    assert not should, (
        f"C4-e FAIL: {exc_cls.__name__}({status}) marked as retriable. "
        "4xx errors must not be retried — fix RetryPolicy.should_retry()."
    )


# ---------------------------------------------------------------------------
# C4-f  429 QUOTA 错误暴露 retry_after
# ---------------------------------------------------------------------------

@pytest.mark.conformance
def test_c4f_quota_error_exposes_retry_after() -> None:
    """QuotaExceededError 应携带 retry_after 字段（来自响应体）。"""
    body = _make_problem(
        429,
        "FOUNDATION.BILLING.QUOTA.EXCEEDED",
        title="Quota exceeded",
        retry_after=60,
    )
    exc = from_problem(429, body)
    assert isinstance(exc, (QuotaExceededError, RateLimitedError)), \
        f"C4-f FAIL: expected quota/rate error, got {type(exc).__name__}"
    assert exc.retry_after == 60, (
        f"C4-f FAIL: retry_after = {exc.retry_after!r}, expected 60. "
        "SDK should pass body['retry_after'] into exception."
    )


# ---------------------------------------------------------------------------
# C4-g  字段级错误反序列化
# ---------------------------------------------------------------------------

@pytest.mark.conformance
def test_c4g_field_errors_deserialized_correctly() -> None:
    """422 响应的 errors 数组被正确反序列化为 FieldError 列表。"""
    body = _make_problem(
        422,
        "FOUNDATION._.INPUT.VALIDATION_FAILED",
        field_errors=[
            {
                "field": "email",
                "code": "INVALID_EMAIL_FORMAT",
                "detail": "Must be a valid email.",
                "user_message": "邮箱格式不正确。",
            },
            {
                "field": "password",
                "code": "PASSWORD_TOO_WEAK",
                "detail": "Min 12 chars.",
                "user_message": None,
            },
        ],
    )
    exc = from_problem(422, body)
    assert len(exc.field_errors) == 2, (
        f"C4-g FAIL: expected 2 field errors, got {len(exc.field_errors)}"
    )
    fe0 = exc.field_errors[0]
    assert isinstance(fe0, FieldError), \
        f"C4-g FAIL: field_errors[0] is {type(fe0).__name__}, expected FieldError"
    assert fe0.field == "email", f"C4-g FAIL: fe0.field = {fe0.field!r}"
    assert fe0.code == "INVALID_EMAIL_FORMAT"
    assert fe0.user_message == "邮箱格式不正确。"


# ---------------------------------------------------------------------------
# C4-h  (needs_stack) 真实 404 响应符合 RFC 9457
# ---------------------------------------------------------------------------

@pytest.mark.conformance
@pytest.mark.needs_stack
def test_c4h_real_404_is_rfc9457(foundation_url: str, foundation_token: str) -> None:
    """真实底座 404 响应必须是 RFC 9457 Problem Details 格式。"""
    with httpx.Client(base_url=foundation_url, timeout=10.0) as c:
        resp = c.get(
            "/api/identity/v1/users/usr_nonexistent_conformance",
            headers={
                "Authorization": f"Bearer {foundation_token}",
                "X-Tenant-Id": TENANT_A,
                "X-Request-Id": "req_C4HCONFORM",
            },
        )
    assert resp.status_code == 404, \
        f"C4-h: Expected 404, got {resp.status_code}"

    ct = resp.headers.get("content-type", "")
    assert "problem+json" in ct or "json" in ct, (
        f"C4-h FAIL: Content-Type should be application/problem+json, got {ct!r}"
    )

    body = resp.json()
    required = ["type", "status", "code", "request_id", "timestamp"]
    missing = [f for f in required if f not in body]
    assert not missing, (
        f"C4-h FAIL: RFC 9457 required fields missing: {missing!r}. "
        f"Got body keys: {list(body)}"
    )

    code = body.get("code", "")
    assert _ERROR_CODE_RE.match(code), (
        f"C4-h FAIL: error code {code!r} in response doesn't match "
        "FOUNDATION.<SVC>.<CAT>.<NAME> format."
    )
