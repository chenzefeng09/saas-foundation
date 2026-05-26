"""Data Protection service error codes."""

from __future__ import annotations
from dataclasses import dataclass, field; from typing import Final

@dataclass(frozen=True, slots=True)
class ErrorCode:
    code: str; http_status: int; title: str; default_detail: str; default_user_message: str

class FoundationError(Exception):
    def __init__(self, error_code, detail=None, user_message=None, extra=None):
        self.error_code = error_code; self.detail = detail or error_code.default_detail
        self.user_message = user_message or error_code.default_user_message
        self.extra: dict = extra or {}
        super().__init__(f"{error_code.code}: {self.detail}")

    @staticmethod
    def _ec(c, n, h, t, d, u): return ErrorCode(code=f"FOUNDATION.DATA_PROTECTION.{c}.{n}", http_status=h, title=t, default_detail=d, default_user_message=u)

CROSS_BORDER_BLOCKED: Final = ErrorCode(code="FOUNDATION.DATA_PROTECTION.POLICY.CROSS_BORDER_BLOCKED", http_status=403, title="Cross-border transfer blocked", default_detail="Transfer blocked by data residency policy.", default_user_message="跨境传输被数据驻留策略阻止。")
DESTRUCTION_APPROVAL_INVALID: Final = ErrorCode(code="FOUNDATION.DATA_PROTECTION.STATE.DESTRUCTION_APPROVAL_INVALID", http_status=409, title="Invalid approval", default_detail="Approver must be different from requester.", default_user_message="审批人不能与请求人相同。")
VALIDATION_FAILED: Final = ErrorCode(code="FOUNDATION.DATA_PROTECTION.INPUT.VALIDATION_FAILED", http_status=422, title="Validation failed", default_detail="Input failed validation.", default_user_message="输入校验未通过。")
UNEXPECTED: Final = ErrorCode(code="FOUNDATION.DATA_PROTECTION.INTERNAL.UNEXPECTED", http_status=500, title="Unexpected error", default_detail="Internal error.", default_user_message="服务异常。")

@dataclass(frozen=True, slots=True)
class _Registry:
    codes: tuple[ErrorCode, ...] = field(default=())
    @classmethod
    def build(cls):
        import inspect; codes = tuple(o for _, o in inspect.getmembers(__import__(__name__, fromlist=["*"])) if isinstance(o, ErrorCode))
        seen = set()
        for c in codes:
            if c.code in seen: raise RuntimeError(f"Duplicate: {c.code}")
            seen.add(c.code)
        return cls(codes=codes)

REGISTRY: Final = _Registry.build()
