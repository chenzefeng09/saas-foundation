"""DLP service error codes."""

from __future__ import annotations
from dataclasses import dataclass, field; from typing import Final

@dataclass(frozen=True, slots=True)
class ErrorCode:
    code: str; http_status: int; title: str; default_detail: str; default_user_message: str

class FoundationError(Exception):
    def __init__(self, error_code: ErrorCode, detail=None, user_message=None, extra=None):
        self.error_code = error_code; self.detail = detail or error_code.default_detail
        self.user_message = user_message or error_code.default_user_message
        self.extra: dict = extra or {}
        super().__init__(f"{error_code.code}: {self.detail}")

def _ec(c, n, h, t, d, u): return ErrorCode(code=f"FOUNDATION.DLP.{c}.{n}", http_status=h, title=t, default_detail=d, default_user_message=u)

CLASSIFICATION_NOT_FOUND: Final = _ec("RESOURCE", "CLASSIFICATION_NOT_FOUND", 404, "Classification not found", "No classification for this resource.", "未找到数据分级标签。")
CLEARANCE_UNAVAILABLE: Final = _ec("DEPENDENCY", "CLEARANCE_UNAVAILABLE", 503, "Clearance unavailable", "The authoritative user clearance could not be resolved; access is denied.", "暂时无法核验用户密级，已拒绝访问。")
CLEARANCE_INSUFFICIENT: Final = _ec("POLICY", "CLEARANCE_INSUFFICIENT", 403, "Clearance insufficient", "User clearance < resource sensitivity.", "您的密级不足以访问该资源。")
DLP_DENIED: Final = _ec("POLICY", "DLP_DENIED", 403, "DLP denied", "Action blocked by DLP policy.", "DLP 策略阻止了该操作。")
IDENTITY_CONTEXT_MISSING: Final = _ec("AUTH", "IDENTITY_CONTEXT_MISSING", 401, "Identity context missing", "A trusted user identity is required for this operation.", "缺少可信用户身份。")
TENANT_CONTEXT_MISSING: Final = _ec(
    "AUTH", "TENANT_CONTEXT_MISSING", 401, "Tenant context missing",
    "The request carries no tenant context (X-Tenant-Id).", "缺少租户上下文。")
SENSITIVITY_IMMUTABLE_DOWNGRADE: Final = _ec("STATE", "SENSITIVITY_IMMUTABLE_DOWNGRADE", 409, "Cannot downgrade", "Sensitivity level cannot be downgraded.", "密级不能降级。")
VALIDATION_FAILED: Final = _ec("INPUT", "VALIDATION_FAILED", 422, "Validation failed", "Input failed validation.", "输入校验未通过。")
UNEXPECTED: Final = _ec("INTERNAL", "UNEXPECTED", 500, "Unexpected error", "Internal error.", "服务异常。")

@dataclass(frozen=True, slots=True)
class _Registry:
    codes: tuple[ErrorCode, ...] = field(default=())
    @classmethod
    def build(cls) -> _Registry:
        import inspect; codes = tuple(o for _, o in inspect.getmembers(__import__(__name__, fromlist=["*"])) if isinstance(o, ErrorCode))
        seen = set()
        for c in codes:
            if c.code in seen: raise RuntimeError(f"Duplicate: {c.code}")
            seen.add(c.code)
        return cls(codes=codes)

REGISTRY: Final = _Registry.build()
