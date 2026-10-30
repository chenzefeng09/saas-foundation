"""Crypto service error codes (FOUNDATION.CRYPTO.<CAT>.<NAME>)."""

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
        code=f"FOUNDATION.CRYPTO.{category}.{name}",
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


# --- POLICY (403) ---
PERMISSION_DENIED: Final = _ec(
    "POLICY", "PERMISSION_DENIED", 403,
    "Permission denied",
    "Subject does not have the requested crypto permission.",
    "您没有执行此密码学操作的权限。",
)
TENANT_MISMATCH: Final = _ec(
    "POLICY", "TENANT_MISMATCH", 403,
    "Tenant mismatch",
    "KEK belongs to a different tenant than the authenticated context.",
    "密钥所属租户与当前上下文不一致。",
)
FOUR_EYES_REQUIRED: Final = _ec(
    "POLICY", "FOUR_EYES_REQUIRED", 403,
    "Four-eyes approval required",
    "Destruction of a KEK requires a second approver distinct from the actor.",
    "密钥销毁需要第二位审批人。",
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
ALGORITHM_UNSUPPORTED: Final = _ec(
    "INPUT", "ALGORITHM_UNSUPPORTED", 422,
    "Algorithm unsupported",
    "Algorithm is not registered or has been deprecated.",
    "算法不被支持或已弃用。",
)
ENVELOPE_SCHEMA_UNSUPPORTED: Final = _ec(
    "INPUT", "ENVELOPE_SCHEMA_UNSUPPORTED", 422,
    "Envelope schema version unsupported",
    "Envelope was produced by a newer/older schema than this service supports.",
    "信封格式版本不兼容。",
)


# --- RESOURCE (404 / 409) ---
KEK_NOT_FOUND: Final = _ec(
    "RESOURCE", "KEK_NOT_FOUND", 404,
    "KEK not found",
    "Key encryption key does not exist in this tenant.",
    "密钥不存在。",
)
KEK_LABEL_CONFLICT: Final = _ec(
    "RESOURCE", "KEK_LABEL_CONFLICT", 409,
    "KEK label conflict",
    "A KEK with this label already exists in this tenant.",
    "同名密钥已存在。",
)
ALGORITHM_NOT_FOUND: Final = _ec(
    "RESOURCE", "ALGORITHM_NOT_FOUND", 404,
    "Algorithm not found",
    "Algorithm ID is not in the registry.",
    "算法未在注册表中。",
)


# --- STATE (409 / 422) ---
KEK_NOT_ACTIVE: Final = _ec(
    "STATE", "KEK_NOT_ACTIVE", 409,
    "KEK not active",
    "Operation requires an ACTIVE KEK; current status forbids it.",
    "密钥当前状态不支持该操作。",
)
KEK_NOT_DESTRUCTIBLE: Final = _ec(
    "STATE", "KEK_NOT_DESTRUCTIBLE", 409,
    "KEK not destructible yet",
    "KEK must be marked for destruction and pass cooling-off before destroy.",
    "密钥尚未通过冷静期，无法销毁。",
)
KEK_ALREADY_MARKED: Final = _ec(
    "STATE", "KEK_ALREADY_MARKED", 409,
    "KEK already marked for destruction",
    "KEK is already in MARKED_FOR_DESTRUCTION state.",
    "密钥已处于销毁标记状态。",
)
KEK_DESTROYED: Final = _ec(
    "STATE", "KEK_DESTROYED", 410,
    "KEK destroyed",
    "KEK has been permanently destroyed; ciphertext is unrecoverable.",
    "密钥已永久销毁，密文无法恢复。",
)
ENVELOPE_TAMPERED: Final = _ec(
    "STATE", "ENVELOPE_TAMPERED", 422,
    "Envelope integrity check failed",
    "Envelope ciphertext, nonce, wrapped DEK, or AAD has been altered.",
    "信封完整性校验失败，可能被篡改。",
)


# --- DEPENDENCY (502 / 503 / 504) ---
VAULT_UNAVAILABLE: Final = _ec(
    "DEPENDENCY", "VAULT_UNAVAILABLE", 503,
    "Vault unavailable",
    "Key backend (Vault transit / HSM) is currently unreachable.",
    "密钥后端暂不可用。",
)
VAULT_TIMEOUT: Final = _ec(
    "DEPENDENCY", "VAULT_TIMEOUT", 504,
    "Vault timeout",
    "Key backend operation exceeded the timeout budget.",
    "密钥后端超时。",
)
VAULT_DECISION_ERROR: Final = _ec(
    "DEPENDENCY", "VAULT_DECISION_ERROR", 502,
    "Vault returned an unexpected response",
    "Key backend returned an error or malformed response.",
    "密钥后端返回异常。",
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
