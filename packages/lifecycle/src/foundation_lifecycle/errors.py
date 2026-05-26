"""Lifecycle service error codes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final


@dataclass(frozen=True, slots=True)
class ErrorCode:
    code: str; http_status: int; title: str; default_detail: str; default_user_message: str


class FoundationError(Exception):
    def __init__(self, error_code: ErrorCode, detail: str | None = None,
                 user_message: str | None = None, extra: dict[str, str] | None = None) -> None:
        self.error_code = error_code; self.detail = detail or error_code.default_detail
        self.user_message = user_message or error_code.default_user_message
        self.extra: dict[str, str] = extra or {}
        super().__init__(f"{error_code.code}: {self.detail}")


def _ec(cat: str, name: str, http: int, title: str, detail: str, user: str) -> ErrorCode:
    return ErrorCode(code=f"FOUNDATION.LIFECYCLE.{cat}.{name}", http_status=http, title=title, default_detail=detail, default_user_message=user)

PERMISSION_DENIED: Final = _ec("POLICY", "PERMISSION_DENIED", 403, "Permission denied", "No lifecycle permission.", "您没有生命周期管理权限。")
TENANT_MISMATCH: Final = _ec("POLICY", "TENANT_MISMATCH", 403, "Tenant mismatch", "Resource belongs to different tenant.", "租户不匹配。")
VALIDATION_FAILED: Final = _ec("INPUT", "VALIDATION_FAILED", 422, "Validation failed", "Input failed validation.", "输入校验未通过。")
RESOURCE_TYPE_NOT_FOUND: Final = _ec("RESOURCE", "RESOURCE_TYPE_NOT_FOUND", 404, "Resource type not found", "Resource type is not registered.", "资源类型未注册。")
RESOURCE_NOT_IN_BIN: Final = _ec("RESOURCE", "RESOURCE_NOT_IN_BIN", 404, "Resource not in recycle bin", "Resource not found in recycle bin.", "回收站中无此资源。")
LEGAL_HOLD_ACTIVE: Final = _ec("STATE", "LEGAL_HOLD_ACTIVE", 409, "Legal hold active", "Cannot delete resource with active legal hold.", "该资源有法律保留，无法删除。")
LEGAL_HOLD_NOT_FOUND: Final = _ec("RESOURCE", "LEGAL_HOLD_NOT_FOUND", 404, "Legal hold not found", "Legal hold does not exist.", "法律保留不存在。")
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
            if c.code in seen: raise RuntimeError(f"Duplicate: {c.code}")
            seen.add(c.code)
        return cls(codes=codes)

REGISTRY: Final = _Registry.build()
