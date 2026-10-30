"""Authz service error codes (FOUNDATION.AUTHZ.<CAT>.<NAME>)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final


@dataclass(frozen=True, slots=True)
class ErrorCode:
    code: str
    http_status: int
    title: str
    default_detail: str
    default_user_message: str


class FoundationError(Exception):
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


def _ec(category: str, name: str, http: int, title: str, detail: str, user_msg: str) -> ErrorCode:
    return ErrorCode(
        code=f"FOUNDATION.AUTHZ.{category}.{name}",
        http_status=http,
        title=title,
        default_detail=detail,
        default_user_message=user_msg,
    )


# --- AUTH (401) ---
TENANT_CONTEXT_MISSING: Final = _ec(
    "AUTH", "TENANT_CONTEXT_MISSING", 401,
    "Tenant context missing",
    "The request carries no tenant context (X-Tenant-Id).",
    "缺少租户上下文。",
)


# --- POLICY (403) — primary category for authz ---
PERMISSION_DENIED: Final = _ec(
    "POLICY", "PERMISSION_DENIED", 403,
    "Permission denied",
    "Subject does not have the requested permission on the resource.",
    "您没有执行此操作的权限。",
)
TENANT_MISMATCH: Final = _ec(
    "POLICY", "TENANT_MISMATCH", 403,
    "Tenant mismatch",
    "Resource belongs to a different tenant than the authenticated context.",
    "租户上下文不匹配。",
)
SCOPE_OUT_OF_BOUNDS: Final = _ec(
    "POLICY", "SCOPE_OUT_OF_BOUNDS", 403,
    "Scope out of bounds",
    "Binding scope does not cover the requested resource.",
    "权限范围不包含该资源。",
)
KILL_SWITCH_ACTIVE: Final = _ec(
    "POLICY", "KILL_SWITCH_ACTIVE", 403,
    "Kill switch active",
    "Permission is hard-denied by an emergency kill switch.",
    "该操作已被紧急熔断。",
)
MFA_REQUIRED: Final = _ec(
    "POLICY", "MFA_REQUIRED", 403,
    "MFA required",
    "Permission requires MFA; current session did not satisfy MFA.",
    "此操作需要二步验证。",
)
FOUR_EYES_REQUIRED: Final = _ec(
    "POLICY", "FOUR_EYES_REQUIRED", 403,
    "Four-eyes approval required",
    "Permission requires a second approver; no approval found.",
    "此操作需要双人审批。",
)
PAM_ELEVATION_REQUIRED: Final = _ec(
    "POLICY", "PAM_ELEVATION_REQUIRED", 403,
    "PAM JIT elevation required",
    "Permission requires a JIT elevation grant; no active elevation found.",
    "此操作需要临时提权。",
)
PERMISSION_ESCALATION: Final = _ec(
    "POLICY", "PERMISSION_ESCALATION", 403,
    "Permission escalation denied",
    "Caller may not grant permissions exceeding their own effective permission set.",
    "不能授予超出自身权限范围的权限。",
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
PERMISSION_UNKNOWN: Final = _ec(
    "INPUT", "PERMISSION_UNKNOWN", 422,
    "Permission unknown",
    "Permission name is not registered with this service.",
    "未知的权限名。",
)


# --- RESOURCE (404 / 409) ---
ROLE_NOT_FOUND: Final = _ec(
    "RESOURCE", "ROLE_NOT_FOUND", 404,
    "Role not found",
    "Role does not exist in this tenant.",
    "角色不存在。",
)
BINDING_NOT_FOUND: Final = _ec(
    "RESOURCE", "BINDING_NOT_FOUND", 404,
    "Binding not found",
    "Role binding does not exist.",
    "角色绑定不存在。",
)
ROLE_ALREADY_EXISTS: Final = _ec(
    "RESOURCE", "ROLE_ALREADY_EXISTS", 409,
    "Role already exists",
    "A role with this name already exists in this tenant.",
    "同名角色已存在。",
)


# --- STATE (409) ---
ROLE_IMMUTABLE: Final = _ec(
    "STATE", "ROLE_IMMUTABLE", 409,
    "Role immutable",
    "System or immutable role cannot be modified.",
    "系统角色不可修改。",
)
ROLE_HAS_BINDINGS: Final = _ec(
    "STATE", "ROLE_HAS_BINDINGS", 409,
    "Role still has bindings",
    "Cannot delete role with active bindings; unbind first.",
    "该角色仍有绑定，无法删除。",
)
ROLE_INHERIT_CYCLE: Final = _ec(
    "STATE", "ROLE_INHERIT_CYCLE", 409,
    "Role inheritance cycle",
    "Adding this inheritance would create a cycle in the role DAG.",
    "角色继承存在循环。",
)


# --- DEPENDENCY (502 / 503 / 504) ---
OPA_UNAVAILABLE: Final = _ec(
    "DEPENDENCY", "OPA_UNAVAILABLE", 503,
    "OPA unavailable",
    "Policy engine is currently unreachable.",
    "策略引擎暂不可用。",
)
OPA_TIMEOUT: Final = _ec(
    "DEPENDENCY", "OPA_TIMEOUT", 504,
    "OPA timeout",
    "Policy engine evaluation exceeded the timeout budget.",
    "策略引擎超时。",
)
OPA_DECISION_ERROR: Final = _ec(
    "DEPENDENCY", "OPA_DECISION_ERROR", 502,
    "OPA decision error",
    "Policy engine returned an unexpected response.",
    "策略引擎返回异常。",
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
    codes: tuple[ErrorCode, ...] = field(default=())

    @classmethod
    def build(cls) -> _Registry:
        import inspect

        codes = tuple(
            obj
            for _, obj in inspect.getmembers(__import__(__name__, fromlist=["*"]))
            if isinstance(obj, ErrorCode)
        )
        seen: set[str] = set()
        for c in codes:
            if c.code in seen:
                raise RuntimeError(f"Duplicate error code: {c.code}")
            seen.add(c.code)
        return cls(codes=codes)


REGISTRY: Final = _Registry.build()
