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
        env_prefix="AUTHZ_",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------ Service
    service_name: str = "authz-service"
    env: Literal["dev", "staging", "production"] = "dev"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_format: Literal["json", "console"] = "json"

    # ------------------------------------------------------------ HTTP
    http_host: str = "0.0.0.0"  # noqa: S104
    http_port: int = 8002
    api_prefix: str = "/api/authz/v1"

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
        default=RedisDsn("redis://:redis_change_me@127.0.0.1:6379/1"),
    )
    # Cache for "user X effective roles" — invalidate on binding change.
    binding_cache_ttl_seconds: int = 60

    # ------------------------------------------------------------ OPA sidecar
    # In dev we point at the shared docker-compose OPA (8181). In prod it's a
    # per-pod sidecar on 127.0.0.1:8181, but the URL stays identical.
    opa_url: AnyHttpUrl = Field(default=AnyHttpUrl("http://127.0.0.1:8181"))
    opa_decision_path: str = "/v1/data/foundation/authz/allow"
    opa_timeout_seconds: float = 0.5  # SUPER tight: authz check is on critical path
    # When OPA is unreachable: fail-closed (deny) or fail-open (allow with audit).
    opa_unavailable_behaviour: Literal["FAIL_CLOSE", "FAIL_OPEN"] = "FAIL_CLOSE"

    # ------------------------------------------------------------ Audit
    audit_publisher_kind: Literal["outbox_db", "http_direct", "log_only"] = "outbox_db"

    # ------------------------------------------------------------ OTel
    otel_enabled: bool = True
    otel_exporter_endpoint: str = "http://127.0.0.1:4317"
    otel_exporter_protocol: Literal["grpc", "http"] = "grpc"

    # ------------------------------------------------------------ Platform admin
    # Pre-shared secret carried in X-Internal-Admin-Token by platform-internal
    # callers (the BFF admin path).  When present and matching, the request is
    # allowed to assert actor=ADMIN — which the admin_all RLS policies honour to
    # bypass tenant isolation.  Empty string (the default) disables the feature:
    # any X-Actor=ADMIN from an external caller is silently downgraded to USER.
    # External/client requests MUST NOT know this secret.  Env: AUTHZ_INTERNAL_ADMIN_TOKEN.
    internal_admin_token: SecretStr = SecretStr("")

    # ------------------------------------------------------------ Multi-tenancy
    require_tenant_context: bool = True


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
