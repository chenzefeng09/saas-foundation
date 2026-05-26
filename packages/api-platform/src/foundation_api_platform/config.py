"""ENV-driven settings (pydantic-settings)."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import AnyHttpUrl, PostgresDsn
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8",
        env_prefix="API_PLATFORM_", case_sensitive=False, extra="ignore",
    )

    service_name: str = "api-platform"
    env: Literal["dev", "staging", "production"] = "dev"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_format: Literal["json", "console"] = "json"

    http_host: str = "0.0.0.0"
    http_port: int = 8010
    api_prefix: str = "/api/api-platform/v1"

    db_dsn: PostgresDsn = PostgresDsn("postgresql+asyncpg://app_user:app_user_change_me@127.0.0.1:6432/foundation")
    db_dsn_migrator: PostgresDsn = PostgresDsn("postgresql+asyncpg://app_migrator:app_migrator_change_me@127.0.0.1:5432/foundation")
    db_pool_size: int = 10
    db_max_overflow: int = 10
    db_pool_timeout_seconds: int = 30
    db_echo: bool = False

    otel_enabled: bool = True
    otel_exporter_endpoint: str = "http://127.0.0.1:4317"
    require_tenant_context: bool = True


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
