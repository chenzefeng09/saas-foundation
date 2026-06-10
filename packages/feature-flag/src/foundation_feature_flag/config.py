from functools import lru_cache
from typing import Literal

from pydantic import PostgresDsn
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="FEATURE_FLAG_", extra="ignore")

    service_name: str = "feature-flag"
    env: Literal["dev", "staging", "production"] = "dev"
    http_host: str = "0.0.0.0"
    http_port: int = 8012
    api_prefix: str = "/api/feature-flag/v1"

    db_dsn: PostgresDsn = PostgresDsn(
        "postgresql+asyncpg://app_user:app_user_change_me@127.0.0.1:6432/foundation"
    )
    db_dsn_migrator: PostgresDsn = PostgresDsn(
        "postgresql+asyncpg://app_migrator:app_migrator_change_me@127.0.0.1:5432/foundation"
    )
    db_pool_size: int = 10
    db_max_overflow: int = 10
    db_pool_timeout_seconds: int = 30
    db_echo: bool = False

    otel_enabled: bool = True
    otel_exporter_endpoint: str = "http://127.0.0.1:4317"
    require_tenant_context: bool = True

    # ------------------------------------------------------------------
    # Unleash 集成（下阶段接 client，先预留字段）
    # ------------------------------------------------------------------
    unleash_enabled: bool = True
    unleash_url: str = "http://localhost:4242"
    unleash_api_token: str = "*:*.unleash-insecure-admin-api-token"
    unleash_admin_token: str = "*:*.unleash-insecure-admin-api-token"
    unleash_app_name: str = "feature-flag-service"
    # Admin API project/environment — v5+ 的创建/启停端点都是 project 维度
    unleash_project: str = "default"
    unleash_environment: str = "development"
    unleash_refresh_interval: int = 15          # seconds
    unleash_metrics_interval: int = 60          # seconds
    unleash_fail_open_flags: list[str] = []     # flags that default to True on Unleash error


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
