"""ENV-driven settings."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import AnyHttpUrl, Field, PostgresDsn
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="DLP_",
        case_sensitive=False,
        extra="ignore",
    )
    service_name: str = "dlp-service"
    env: Literal["dev", "staging", "production"] = "dev"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_format: Literal["json", "console"] = "json"
    http_host: str = "0.0.0.0"  # noqa: S104
    http_port: int = 8007
    api_prefix: str = "/api/dlp/v1"
    db_dsn: PostgresDsn = Field(
        default=PostgresDsn(
            "postgresql+asyncpg://app_user:app_user_change_me@127.0.0.1:6432/foundation"
        )
    )
    db_dsn_migrator: PostgresDsn = Field(
        default=PostgresDsn(
            "postgresql+asyncpg://app_migrator:app_migrator_change_me@127.0.0.1:5432/foundation"
        )
    )
    db_pool_size: int = 10
    db_max_overflow: int = 10
    otel_enabled: bool = True
    otel_exporter_endpoint: str = "http://127.0.0.1:4317"
    otel_exporter_protocol: Literal["grpc", "http"] = "grpc"
    # Identity is the authority for a user's L1-L5 clearance.  The URL includes
    # the identity API prefix so the provider only appends /users/{user_id}.
    identity_url: AnyHttpUrl = AnyHttpUrl("http://127.0.0.1:8001/api/identity/v1")
    identity_timeout_seconds: float = Field(default=2.0, gt=0.0, le=30.0)
    # Resources without an explicit classification fail to the company-wide
    # employee baseline.  This is intentionally configurable for stricter tenants.
    # The fallback may only be tightened. L1/L2 must always be an explicit label,
    # otherwise an omitted classification would silently widen access.
    unclassified_sensitivity: Literal["L3", "L4", "L5"] = "L3"
    require_tenant_context: bool = True


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
