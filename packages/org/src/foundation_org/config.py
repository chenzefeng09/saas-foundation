"""ENV-driven settings (pydantic-settings)."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, PostgresDsn, RedisDsn
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All service config; reads from environment (and `.env` in dev)."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="ORG_",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------ Service
    service_name: str = "org-service"
    env: Literal["dev", "staging", "production"] = "dev"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_format: Literal["json", "console"] = "json"

    # ------------------------------------------------------------ HTTP
    http_host: str = "0.0.0.0"  # noqa: S104
    http_port: int = 8003
    api_prefix: str = "/api/org/v1"

    # ------------------------------------------------------------ Database
    db_dsn: PostgresDsn = Field(
        default=PostgresDsn(
            "postgresql+asyncpg://app_user:app_user_change_me@127.0.0.1:6432/foundation"
        ),
    )
    db_dsn_migrator: PostgresDsn = Field(
        default=PostgresDsn(
            "postgresql+asyncpg://app_migrator:app_migrator_change_me@127.0.0.1:5432/foundation"
        ),
    )
    db_pool_size: int = 10
    db_max_overflow: int = 10
    db_pool_timeout_seconds: int = 30
    db_echo: bool = False

    # ------------------------------------------------------------ Redis
    redis_dsn: RedisDsn = Field(
        default=RedisDsn("redis://:redis_change_me@127.0.0.1:6379/2"),
    )
    # Tree cache TTL (full tenant tree). Invalidated on any OU write.
    tree_cache_ttl_seconds: int = 60

    # ------------------------------------------------------------ Audit / events
    audit_publisher_kind: Literal["outbox_db", "http_direct", "log_only"] = "outbox_db"

    # ------------------------------------------------------------ OTel
    otel_enabled: bool = True
    otel_exporter_endpoint: str = "http://127.0.0.1:4317"
    otel_exporter_protocol: Literal["grpc", "http"] = "grpc"

    # ------------------------------------------------------------ Multi-tenancy
    require_tenant_context: bool = True

    # ------------------------------------------------------------ Org-specific
    # Subtree move: synchronous if descendants count below threshold,
    # otherwise an async job is queued (M1 just records intent in outbox).
    sync_move_threshold: int = 1000
    # Hard cap on OU depth (matches CHECK constraint in migration).
    max_org_unit_depth: int = 12


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
