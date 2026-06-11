"""ENV-driven settings for foundation-storage (env_prefix=STORAGE_)."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class StorageSettings(BaseSettings):
    """Storage configuration; loaded from STORAGE_* env vars with dev-safe defaults."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="STORAGE_",
        case_sensitive=False,
        extra="ignore",
    )

    # S3 / MinIO connection. ``endpoint`` is None → AWS S3 default endpoint.
    endpoint: str | None = "http://127.0.0.1:9001"
    region: str = "cn-default"
    access_key: str = "foundation"
    secret_key: str = "minio_change_me_min_12_chars"

    # Logical bucket → physical bucket name mapping (§4.3).
    bucket_audit: str = "foundation-audit"
    bucket_workspace: str = "foundation-workspace"
    bucket_kb_raw: str = "foundation-kb-raw"
    bucket_kb_derived: str = "foundation-kb-derived"

    # Presigned URL & multipart thresholds.
    presigned_url_ttl_seconds: int = 3600
    multipart_threshold_bytes: int = 52428800  # 50 MiB

    # Quota.  Phase 1: only an interface; real DB-backed checker arrives in Phase 3.
    quota_check_enabled: bool = True
    quota_db_dsn: str | None = None


@lru_cache(maxsize=1)
def get_settings() -> StorageSettings:
    """Return a cached StorageSettings instance loaded from environment."""
    return StorageSettings()
