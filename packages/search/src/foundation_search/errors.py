from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final


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
        extra: dict[str, Any] | None = None,
    ) -> None:
        self.error_code = error_code
        self.detail = detail or error_code.default_detail
        self.user_message = user_message or error_code.default_user_message
        self.extra = extra or {}
        super().__init__(f"{error_code.code}: {self.detail}")


TENANT_CONTEXT_MISSING: Final = ErrorCode(
    "FOUNDATION.SEARCH.AUTH.TENANT_CONTEXT_MISSING",
    401,
    "Tenant context missing",
    "The request carries no tenant context (X-Tenant-Id).",
    "缺少租户上下文。",
)
VALIDATION_FAILED: Final = ErrorCode(
    "FOUNDATION.SEARCH.INPUT.VALIDATION_FAILED",
    422,
    "Validation failed",
    "Input failed semantic validation.",
    "输入校验未通过。",
)
UNEXPECTED: Final = ErrorCode(
    "FOUNDATION.SEARCH.INTERNAL.UNEXPECTED",
    500,
    "Unexpected error",
    "An unexpected internal error occurred.",
    "服务异常。",
)
SEARCH_BACKEND_UNAVAILABLE: Final = ErrorCode(
    "FOUNDATION.SEARCH.BACKEND.UNAVAILABLE",
    503,
    "Search backend unavailable",
    "OpenSearch is not reachable; query aborted (fail-close).",
    "搜索后端不可用; 请稍后重试。",
)
SECURITY_ATTRIBUTES_UNAVAILABLE: Final = ErrorCode(
    "FOUNDATION.SEARCH.SECURITY.ATTRIBUTES_UNAVAILABLE",
    503,
    "Security attributes unavailable",
    "Authoritative clearance or sensitivity could not be resolved; request aborted.",
    "安全等级信息暂不可用; 请稍后重试。",
)
ACCESS_DENIED: Final = ErrorCode(
    "FOUNDATION.SEARCH.AUTH.ACCESS_DENIED",
    403,
    "Access denied",
    "The caller is not allowed to perform this search operation.",
    "无权执行此搜索操作。",
)
