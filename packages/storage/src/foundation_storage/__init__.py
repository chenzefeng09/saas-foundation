"""foundation-storage — tenant-scoped S3/MinIO abstraction (Phase 1)."""

from __future__ import annotations

__version__ = "1.0.0a1"

from foundation_storage.access_control import (
    AccessDecision,
    DLPStorageAccessChecker,
    StorageAccessChecker,
)
from foundation_storage.client import StorageClient
from foundation_storage.config import StorageSettings, get_settings
from foundation_storage.errors import (
    AccessControlError,
    KeyValidationError,
    ObjectLockedError,
    ObjectNotFoundError,
    QuotaExceededError,
    StorageError,
)
from foundation_storage.keys import BucketPurpose, ObjectKey
from foundation_storage.models import ObjectMeta
from foundation_storage.quota import (
    NoopQuotaChecker,
    PostgresQuotaChecker,
    QuotaChecker,
)

__all__ = [
    "AccessControlError",
    "AccessDecision",
    "BucketPurpose",
    "DLPStorageAccessChecker",
    "KeyValidationError",
    "NoopQuotaChecker",
    "ObjectKey",
    "ObjectLockedError",
    "ObjectMeta",
    "ObjectNotFoundError",
    "PostgresQuotaChecker",
    "QuotaChecker",
    "QuotaExceededError",
    "StorageClient",
    "StorageAccessChecker",
    "StorageError",
    "StorageSettings",
    "__version__",
    "get_settings",
]
