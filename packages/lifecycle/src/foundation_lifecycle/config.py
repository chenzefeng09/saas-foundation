"""ENV-driven settings."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import PostgresDsn, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", env_prefix="LIFECYCLE_", case_sensitive=False, extra="ignore")

    service_name: str = "lifecycle-service"
    env: Literal["dev", "staging", "production"] = "dev"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_format: Literal["json", "console"] = "json"

    http_host: str = "0.0.0.0"  # noqa: S104
    http_port: int = 8006
    api_prefix: str = "/api/lifecycle/v1"

    db_dsn: PostgresDsn = Field(default=PostgresDsn("postgresql+asyncpg://app_user:app_user_change_me@127.0.0.1:6432/foundation"))
    db_dsn_migrator: PostgresDsn = Field(default=PostgresDsn("postgresql+asyncpg://app_migrator:app_migrator_change_me@127.0.0.1:5432/foundation"))
    db_pool_size: int = 10; db_max_overflow: int = 10

    # Sweep cron
    sweep_enabled: bool = True
    sweep_interval_minutes: int = 60  # every hour in dev
    sweep_batch_size: int = 500

    # Storage quota reconcile cron (Phase 3). Scans every tenant_storage_quota
    # row, recomputes used_bytes via S3 listing, and warns if the drift is
    # over reconcile_drift_alert_pct.
    reconcile_enabled: bool = True
    reconcile_cron: str = "0 3 * * *"  # daily 03:00
    reconcile_drift_alert_pct: float = 1.0

    # Crypto service (for key destruction via KEK)
    crypto_url: str = "http://127.0.0.1:8004/api/crypto/v1"

    otel_enabled: bool = True
    otel_exporter_endpoint: str = "http://127.0.0.1:4317"
    otel_exporter_protocol: Literal["grpc", "http"] = "grpc"

    require_tenant_context: bool = True


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
