"""ENV-driven settings for audit-service."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import AnyHttpUrl, Field, PostgresDsn
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", env_prefix="AUDIT_",
        case_sensitive=False, extra="ignore",
    )

    service_name: str = "audit-service"
    env: Literal["dev", "staging", "production"] = "dev"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_format: Literal["json", "console"] = "json"

    http_host: str = "0.0.0.0"  # noqa: S104
    http_port: int = 8005
    api_prefix: str = "/api/audit/v1"

    # Postgres (outbox + metadata)
    db_dsn: PostgresDsn = Field(default=PostgresDsn("postgresql+asyncpg://app_user:app_user_change_me@127.0.0.1:6432/foundation"))
    db_dsn_migrator: PostgresDsn = Field(default=PostgresDsn("postgresql+asyncpg://app_migrator:app_migrator_change_me@127.0.0.1:5432/foundation"))
    db_pool_size: int = 10
    db_max_overflow: int = 10

    # ClickHouse (hot storage)
    clickhouse_host: str = "127.0.0.1"
    clickhouse_port: int = 8123
    clickhouse_user: str = "foundation"
    clickhouse_password: str = "clickhouse_change_me"
    clickhouse_database: str = "audit"
    clickhouse_connect_timeout: int = 10

    # Crypto service (for signing batches)
    crypto_url: AnyHttpUrl = Field(default=AnyHttpUrl("http://127.0.0.1:8004/api/crypto/v1"))
    crypto_signing_key_label: str = "audit.hashchain"

    # Batch worker
    batch_max_events: int = 10000
    batch_max_seconds: int = 300  # 5 min
    worker_poll_interval_seconds: float = 5.0

    # Hash chain
    hash_algorithm: Literal["SHA-256", "SM3"] = "SHA-256"

    # Retention (default; per-tenant override in compliance)
    retention_days_default: int = 365  # 1 year default

    # OTel
    otel_enabled: bool = True
    otel_exporter_endpoint: str = "http://127.0.0.1:4317"
    otel_exporter_protocol: Literal["grpc", "http"] = "grpc"

    # Multi-tenancy
    require_tenant_context: bool = True

    # TSA (RFC 3161 Time-Stamp Authority)
    # Default: FreeTSA (free, public, RFC 3161 compliant)
    # Override with NTSC for finance/equal-protection-4 compliance mode
    tsa_url: AnyHttpUrl = Field(default=AnyHttpUrl("https://freetsa.org/tsr"))
    tsa_provider: str = "freetsa"
    tsa_enabled: bool = True  # set False in dev if FreeTSA is unreachable

    # S3 / MinIO WORM Object Lock
    s3_endpoint: str = "http://127.0.0.1:9001"
    s3_access_key: str = "foundation"
    s3_secret_key: str = "minio_change_me_min_12_chars"
    worm_bucket: str = "foundation-audit-worm"
    worm_enabled: bool = False   # disabled by default; enable in production
    worm_retention_years: int = 7


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
