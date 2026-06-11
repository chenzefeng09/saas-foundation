"""Storage error codes (FOUNDATION.STORAGE.<CATEGORY>.<NAME>)."""

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
    """Base class for typed Foundation errors carrying an ErrorCode."""

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


class StorageError(FoundationError):
    """Generic storage-layer failure (network, S3 5xx, …)."""


class QuotaExceededError(StorageError):
    """Tenant has exceeded their bucket-purpose quota."""


class ObjectNotFoundError(StorageError):
    """S3 returned NoSuchKey / 404 for the requested object."""


class KeyValidationError(StorageError):
    """ObjectKey failed structural validation or tenant scope check."""


class ObjectLockedError(StorageError):
    """Delete denied because the object is under WORM retention."""


def _ec(
    category: str,
    name: str,
    http: int,
    title: str,
    detail: str,
    user_msg: str,
) -> ErrorCode:
    return ErrorCode(
        code=f"FOUNDATION.STORAGE.{category}.{name}",
        http_status=http,
        title=title,
        default_detail=detail,
        default_user_message=user_msg,
    )


QUOTA_EXCEEDED: Final = _ec(
    "QUOTA",
    "EXCEEDED",
    429,
    "Quota exceeded",
    "Tenant has exceeded the storage quota for this bucket purpose.",
    "存储配额已用尽。",
)
OBJECT_NOT_FOUND: Final = _ec(
    "OBJECT",
    "NOT_FOUND",
    404,
    "Object not found",
    "Object does not exist in the storage backend.",
    "对象不存在。",
)
KEY_INVALID: Final = _ec(
    "KEY",
    "INVALID",
    400,
    "Invalid object key",
    "Object key failed validation.",
    "对象键格式错误。",
)
OBJECT_LOCKED: Final = _ec(
    "OBJECT",
    "LOCKED",
    409,
    "Object locked",
    "Object is under WORM retention and cannot be deleted.",
    "对象处于 WORM 保留期，无法删除。",  # noqa: RUF001
)
STORAGE_UNAVAILABLE: Final = _ec(
    "BACKEND",
    "UNAVAILABLE",
    503,
    "Storage backend unavailable",
    "Storage backend returned an unexpected error.",
    "存储服务暂不可用。",
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
