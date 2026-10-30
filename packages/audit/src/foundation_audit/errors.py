"""Audit service error codes (FOUNDATION.AUDIT.<CAT>.<NAME>)."""

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
    def __init__(self, error_code: ErrorCode, detail: str | None = None,
                 user_message: str | None = None, extra: dict[str, str] | None = None) -> None:
        self.error_code = error_code
        self.detail = detail or error_code.default_detail
        self.user_message = user_message or error_code.default_user_message
        self.extra: dict[str, str] = extra or {}
        super().__init__(f"{error_code.code}: {self.detail}")


def _ec(category: str, name: str, http: int, title: str, detail: str, user_msg: str) -> ErrorCode:
    return ErrorCode(code=f"FOUNDATION.AUDIT.{category}.{name}", http_status=http,
                     title=title, default_detail=detail, default_user_message=user_msg)


TENANT_CONTEXT_MISSING: Final = _ec(
    "AUTH", "TENANT_CONTEXT_MISSING", 401, "Tenant context missing",
    "The request carries no tenant context (X-Tenant-Id).", "缺少租户上下文。")
PERMISSION_DENIED: Final = _ec("POLICY", "PERMISSION_DENIED", 403, "Permission denied", "Subject does not have audit permission.", "您没有审计查询权限。")
TENANT_MISMATCH: Final = _ec("POLICY", "TENANT_MISMATCH", 403, "Tenant mismatch", "Event belongs to a different tenant.", "租户不匹配。")
INVALID_FORMAT: Final = _ec("INPUT", "INVALID_FORMAT", 400, "Invalid input", "Payload malformed.", "请求格式错误。")
VALIDATION_FAILED: Final = _ec("INPUT", "VALIDATION_FAILED", 422, "Validation failed", "Input failed validation.", "输入校验未通过。")
EVENT_NOT_FOUND: Final = _ec("RESOURCE", "EVENT_NOT_FOUND", 404, "Event not found", "Audit event does not exist.", "审计事件不存在。")
CLICKHOUSE_UNAVAILABLE: Final = _ec("DEPENDENCY", "CLICKHOUSE_UNAVAILABLE", 503, "ClickHouse unavailable", "ClickHouse is unreachable.", "审计存储暂不可用。")
UNEXPECTED: Final = _ec("INTERNAL", "UNEXPECTED", 500, "Unexpected error", "Internal error.", "服务异常。")


@dataclass(frozen=True, slots=True)
class _Registry:
    codes: tuple[ErrorCode, ...] = field(default=())
    @classmethod
    def build(cls) -> _Registry:
        import inspect
        codes = tuple(obj for _, obj in inspect.getmembers(__import__(__name__, fromlist=["*"])) if isinstance(obj, ErrorCode))
        seen: set[str] = set()
        for c in codes:
            if c.code in seen: raise RuntimeError(f"Duplicate error code: {c.code}")
            seen.add(c.code)
        return cls(codes=codes)

REGISTRY: Final = _Registry.build()
