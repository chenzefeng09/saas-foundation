"""Identity service error codes (FOUNDATION.IDENTITY.<CAT>.<NAME>).

Mapped to RFC 9457 Problem Details responses by the API layer.
Registry is the single source of truth — `make openapi-lint` cross-checks against
contracts/openapi/identity.yaml.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final


@dataclass(frozen=True, slots=True)
class ErrorCode:
    """A registered error code (immutable contract)."""

    code: str
    http_status: int
    title: str  # English, fixed
    default_detail: str
    default_user_message: str  # zh-CN baseline; per-locale overrides via i18n table


class FoundationError(Exception):
    """Base for all errors raised in service / adapters; caught by API exception handler."""

    def __init__(
        self,
        error_code: ErrorCode,
        detail: str | None = None,
        user_message: str | None = None,
        extra: dict[str, str] | None = None,
    ) -> None:
        self.error_code = error_code
        self.detail = detail or error_code.default_detail
        self.user_message = user_message or error_code.default_user_message
        self.extra: dict[str, str] = extra or {}
        super().__init__(f"{error_code.code}: {self.detail}")


# -----------------------------------------------------------------------------
# Registry — declare ALL identity error codes here.
# Categories per docs/errors.md §3.2:
#   AUTH / POLICY / INPUT / RESOURCE / STATE / QUOTA / RATE_LIMIT /
#   DEPENDENCY / STORAGE / CONFIG / CRYPTO / COMPLIANCE / INTEGRATION / INTERNAL
# -----------------------------------------------------------------------------


def _ec(category: str, name: str, http: int, title: str, detail: str, user_msg: str) -> ErrorCode:
    return ErrorCode(
        code=f"FOUNDATION.IDENTITY.{category}.{name}",
        http_status=http,
        title=title,
        default_detail=detail,
        default_user_message=user_msg,
    )


# --- AUTH (401) ---
INVALID_CREDENTIALS: Final = _ec(
    "AUTH", "INVALID_CREDENTIALS", 401,
    "Invalid credentials",
    "The provided email or password is incorrect.",
    "邮箱或密码不正确，请重试。",
)
TOKEN_EXPIRED: Final = _ec(
    "AUTH", "TOKEN_EXPIRED", 401,
    "Token expired",
    "Access token has expired; please refresh or log in again.",
    "登录已过期，请重新登录。",
)
TOKEN_INVALID: Final = _ec(
    "AUTH", "TOKEN_INVALID", 401,
    "Token invalid",
    "Token signature or claims are invalid.",
    "登录信息无效，请重新登录。",
)
MFA_REQUIRED: Final = _ec(
    "AUTH", "MFA_REQUIRED", 401,
    "MFA required",
    "Multi-factor authentication required for this operation.",
    "请完成二步验证。",
)
MFA_CODE_INVALID: Final = _ec(
    "AUTH", "MFA_CODE_INVALID", 401,
    "MFA code invalid",
    "Provided MFA code is incorrect or expired.",
    "验证码错误或已过期。",
)
ACCOUNT_LOCKED: Final = _ec(
    "AUTH", "ACCOUNT_LOCKED", 401,
    "Account locked",
    "Account has been temporarily locked due to too many failed attempts.",
    "账号已被临时锁定，请稍后再试。",
)
ACCOUNT_FROZEN: Final = _ec(
    "AUTH", "ACCOUNT_FROZEN", 401,
    "Account frozen",
    "Account is frozen by administrator.",
    "账号已被管理员冻结。",
)
LOGIN_DENIED_RISK: Final = _ec(
    "AUTH", "LOGIN_DENIED_RISK", 401,
    "Login denied — anomalous activity",
    "Login refused due to a high anomalous-activity score; please verify your identity through another channel.",
    "检测到异常登录行为，已拒绝本次登录，请通过其他途径验证身份。",
)
REFRESH_TOKEN_REUSED: Final = _ec(
    "AUTH", "REFRESH_TOKEN_REUSED", 401,
    "Refresh token reuse detected",
    "A rotated refresh token was presented again — all sessions for this user "
    "have been revoked as a precaution.",
    "检测到登录凭证异常复用，出于安全考虑已注销全部会话，请重新登录。",
)

# --- POLICY (403) ---
PERMISSION_DENIED: Final = _ec(
    "POLICY", "PERMISSION_DENIED", 403,
    "Permission denied",
    "You do not have permission to perform this action.",
    "您没有执行此操作的权限。",
)
TENANT_MISMATCH: Final = _ec(
    "POLICY", "TENANT_MISMATCH", 403,
    "Tenant mismatch",
    "Requested tenant does not match the authenticated tenant.",
    "租户上下文不匹配。",
)

# --- INPUT (400 / 422) ---
INVALID_FORMAT: Final = _ec(
    "INPUT", "INVALID_FORMAT", 400,
    "Invalid input format",
    "Request payload is malformed.",
    "请求参数格式错误。",
)
VALIDATION_FAILED: Final = _ec(
    "INPUT", "VALIDATION_FAILED", 422,
    "Validation failed",
    "Input failed semantic validation.",
    "输入校验未通过。",
)
PASSWORD_TOO_WEAK: Final = _ec(
    "INPUT", "PASSWORD_TOO_WEAK", 422,
    "Password too weak",
    "Password does not meet the configured complexity policy.",
    "密码强度不满足策略要求。",
)
PASSWORD_REUSED: Final = _ec(
    "INPUT", "PASSWORD_REUSED", 422,
    "Password reused",
    "Password has been used recently; please choose a different one.",
    "新密码与最近使用过的密码相同，请重新选择。",
)
PASSWORD_BREACHED: Final = _ec(
    "INPUT", "PASSWORD_BREACHED", 422,
    "Password found in breach corpus",
    "This password appears in known data-breach corpora; please choose a different one.",
    "该密码已在公开泄漏库中出现，请更换一个未泄漏的密码。",
)

# --- RESOURCE (404 / 409) ---
USER_NOT_FOUND: Final = _ec(
    "RESOURCE", "USER_NOT_FOUND", 404,
    "User not found",
    "No user with the given identifier exists in this tenant.",
    "用户不存在。",
)
SESSION_NOT_FOUND: Final = _ec(
    "RESOURCE", "SESSION_NOT_FOUND", 404,
    "Session not found",
    "Session does not exist or already terminated.",
    "会话不存在或已结束。",
)
USER_ALREADY_EXISTS: Final = _ec(
    "RESOURCE", "USER_ALREADY_EXISTS", 409,
    "User already exists",
    "A user with this email already exists in this tenant.",
    "该邮箱已存在用户。",
)

# --- STATE (409) ---
ACCOUNT_NOT_ACTIVE: Final = _ec(
    "STATE", "ACCOUNT_NOT_ACTIVE", 409,
    "Account not active",
    "Account is not in an active state and cannot perform this action.",
    "账号当前状态不可执行此操作。",
)
POLICY_NOT_ALLOWED_TO_RELAX: Final = _ec(
    "STATE", "POLICY_NOT_ALLOWED_TO_RELAX", 409,
    "Policy cannot be relaxed below baseline",
    "Tenant admins can only tighten policies, not relax below the compliance-mode floor.",
    "安全策略只能加严，不能放宽到合规基线之下。",
)

# --- RATE_LIMIT (429) ---
TOO_MANY_LOGIN_ATTEMPTS: Final = _ec(
    "RATE_LIMIT", "TOO_MANY_LOGIN_ATTEMPTS", 429,
    "Too many login attempts",
    "Login rate limit exceeded; please wait before retrying.",
    "登录失败次数过多，请稍后再试。",
)

# --- DEPENDENCY (502/503/504) ---
KEYCLOAK_UNAVAILABLE: Final = _ec(
    "DEPENDENCY", "KEYCLOAK_UNAVAILABLE", 503,
    "Keycloak unavailable",
    "Identity provider is currently unreachable; please retry.",
    "身份服务暂时不可用，请稍后重试。",
)
KEYCLOAK_ERROR: Final = _ec(
    "DEPENDENCY", "KEYCLOAK_ERROR", 502,
    "Keycloak error",
    "Identity provider returned an unexpected error.",
    "身份服务返回异常。",
)
REDIS_UNAVAILABLE: Final = _ec(
    "DEPENDENCY", "REDIS_UNAVAILABLE", 503,
    "Cache unavailable",
    "Session cache is currently unreachable; the operation was refused to "
    "preserve security guarantees.",
    "会话缓存暂时不可用，请稍后重试。",
)

# --- SERVICE-ACCOUNT TOKEN (400 / 403) ---
SCOPE_NOT_ALLOWED: Final = _ec(
    "AUTH", "SCOPE_NOT_ALLOWED", 403,
    "Scope not allowed",
    "One or more requested scopes are not in the foundation scope catalogue, "
    "or the caller is not allowed to request them.",
    "请求的权限范围不被允许。",
)
TTL_OUT_OF_RANGE: Final = _ec(
    "INPUT", "TTL_OUT_OF_RANGE", 422,
    "TTL out of range",
    "Requested ttl_seconds must be between 60 and 86400.",
    "Token 有效期参数超出允许范围。",
)


# --- INTEGRATION (502) ---
SSO_PROVIDER_ERROR: Final = _ec(
    "INTEGRATION", "SSO_PROVIDER_ERROR", 502,
    "SSO provider error",
    "Third-party SSO provider returned an error.",
    "第三方登录服务返回异常。",
)

# --- INTERNAL (500) ---
UNEXPECTED: Final = _ec(
    "INTERNAL", "UNEXPECTED", 500,
    "Unexpected error",
    "An unexpected internal error occurred.",
    "服务异常，请联系管理员。",
)


@dataclass(frozen=True, slots=True)
class _Registry:
    """All error codes in this service; built once at import time."""

    codes: tuple[ErrorCode, ...] = field(default=())

    @classmethod
    def build(cls) -> _Registry:
        import inspect

        codes = tuple(
            obj
            for _, obj in inspect.getmembers(__import__(__name__, fromlist=["*"]))
            if isinstance(obj, ErrorCode)
        )
        # Uniqueness invariant
        seen: set[str] = set()
        for c in codes:
            if c.code in seen:
                raise RuntimeError(f"Duplicate error code: {c.code}")
            seen.add(c.code)
        return cls(codes=codes)


REGISTRY: Final = _Registry.build()
