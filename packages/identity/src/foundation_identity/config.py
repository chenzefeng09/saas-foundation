"""ENV-driven settings (pydantic-settings)."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import AnyHttpUrl, Field, PostgresDsn, RedisDsn, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All service config; reads from environment (and `.env` in dev)."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="IDENTITY_",
        case_sensitive=False,
        extra="ignore",
    )

    # -------------------------------------------------------------------------
    # Service
    # -------------------------------------------------------------------------
    service_name: str = "identity-service"
    env: Literal["dev", "staging", "production"] = "dev"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_format: Literal["json", "console"] = "json"

    # -------------------------------------------------------------------------
    # HTTP
    # -------------------------------------------------------------------------
    http_host: str = "0.0.0.0"  # noqa: S104  intentional for container deploys
    http_port: int = 8001
    api_prefix: str = "/api/identity/v1"

    # -------------------------------------------------------------------------
    # Database — 走 PgBouncer (transaction mode)
    # -------------------------------------------------------------------------
    db_dsn: PostgresDsn = Field(
        default=PostgresDsn("postgresql+asyncpg://app_user:app_user_change_me@localhost:6432/foundation"),
        description="PgBouncer DSN; transaction-mode pool",
    )
    db_dsn_migrator: PostgresDsn = Field(
        default=PostgresDsn("postgresql+asyncpg://app_migrator:app_migrator_change_me@localhost:5432/foundation"),
        description="Alembic 用，直连 PG（绕过 PgBouncer），且角色 BYPASSRLS",
    )
    db_pool_size: int = 10
    db_max_overflow: int = 10
    db_pool_timeout_seconds: int = 30
    db_echo: bool = False  # 调试 SQL 输出

    # -------------------------------------------------------------------------
    # Redis (session cache / rate-limit counters)
    # -------------------------------------------------------------------------
    redis_dsn: RedisDsn = Field(
        default=RedisDsn("redis://:redis_change_me@localhost:6379/0"),
    )

    # -------------------------------------------------------------------------
    # Keycloak Admin
    # -------------------------------------------------------------------------
    # Use 127.0.0.1 not 'localhost' — on macOS the latter resolves to IPv6 ::1
    # which Docker Desktop's `-p 8080:8080` does NOT bind to (IPv4 only),
    # producing an empty 502 from the Docker network proxy.
    keycloak_base_url: AnyHttpUrl = Field(default=AnyHttpUrl("http://127.0.0.1:8080"))
    keycloak_realm: str = "foundation"
    keycloak_admin_realm: str = "master"
    keycloak_admin_client_id: str = "admin-cli"
    keycloak_admin_user: str = "admin"
    keycloak_admin_password: SecretStr = SecretStr("keycloak_admin_change_me")
    keycloak_timeout_seconds: float = 5.0

    # JWT verification (issuer + JWKS endpoint)
    jwt_issuer: AnyHttpUrl = Field(
        default=AnyHttpUrl("http://127.0.0.1:8080/realms/foundation"),
    )
    jwt_audience: str = "foundation-api"
    jwks_cache_ttl_seconds: int = 600

    # -------------------------------------------------------------------------
    # Audit publisher
    # -------------------------------------------------------------------------
    audit_publisher_kind: Literal["outbox_db", "http_direct", "log_only"] = "outbox_db"
    audit_http_endpoint: AnyHttpUrl | None = None

    # -------------------------------------------------------------------------
    # OpenTelemetry
    # -------------------------------------------------------------------------
    otel_enabled: bool = True
    otel_exporter_endpoint: str = "http://localhost:4317"
    otel_exporter_protocol: Literal["grpc", "http"] = "grpc"

    # -------------------------------------------------------------------------
    # Security / password policy baseline
    # （租户级覆盖在 DB 表 password_policy 里；此处是 hard floor）
    # -------------------------------------------------------------------------
    password_min_length_floor: int = 8
    password_max_failed_attempts_floor: int = 5
    session_idle_timeout_floor_seconds: int = 30 * 60  # 30 min
    session_absolute_timeout_floor_seconds: int = 8 * 60 * 60  # 8h
    session_max_concurrent_floor: int = 2

    # -------------------------------------------------------------------------
    # Multi-tenancy
    # -------------------------------------------------------------------------
    # DB session 启用时强制 set local app.tenant_id；None 走 platform-admin role
    require_tenant_context: bool = True


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings singleton; safe to call from any layer."""
    return Settings()
