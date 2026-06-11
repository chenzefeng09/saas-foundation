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
    # app_admin is the privileged PG role that owns admin_all RLS policies.
    # Used exclusively by platform-admin code paths after super_admin authz check.
    # Falls back to db_dsn if unset (acceptable for dev/test).
    db_dsn_admin: PostgresDsn | None = Field(
        default=None,
        description=(
            "DSN for app_admin PG role — bypasses RLS when app.actor=ADMIN is set "
            "inside the transaction.  Must be set in production."
        ),
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
    # Browser-facing Keycloak base URL.  Inside Docker the in-cluster hostname is
    # ``http://keycloak:8080`` (used by service-to-service /token + JWKS calls),
    # but a user's browser must hit a host-reachable address (``http://127.0.0.1:8080``).
    # The /sso/.../authorize-url endpoint builds a URL the *browser* follows, so it
    # uses this value.  Falls back to ``keycloak_base_url`` when unset.
    keycloak_public_base_url: str | None = None
    keycloak_realm: str = "foundation"
    keycloak_admin_realm: str = "master"
    keycloak_admin_client_id: str = "admin-cli"
    keycloak_admin_user: str = "admin"
    keycloak_admin_password: SecretStr = SecretStr("keycloak_admin_change_me")
    keycloak_timeout_seconds: float = 5.0

    # OIDC client used by identity-service to call Keycloak's /token endpoint
    # on behalf of end users (password grant) and itself (client_credentials).
    # MUST exist in the realm with directAccessGrantsEnabled + serviceAccountsEnabled.
    # This same client is used by the browser SSO code flow (authorize-url +
    # authorization_code grant), so it MUST also have a valid redirect URI configured.
    oidc_client_id: str = "foundation-identity-service"
    foundation_identity_client_secret: SecretStr = SecretStr(
        "dev-identity-service-secret-change-me",
    )

    # JWT verification (issuer + JWKS endpoint)
    jwt_issuer: AnyHttpUrl = Field(
        default=AnyHttpUrl("http://127.0.0.1:8080/realms/foundation"),
    )
    jwt_audience: str = "foundation-api"
    jwks_cache_ttl_seconds: int = 300

    # Fallback tenant when an authenticated token does NOT carry a tenant_id
    # claim (e.g. service-account tokens minted via client_credentials).  In
    # production this should be a platform-admin tenant id, never a real
    # business tenant.
    default_tenant_id: str = "tnt_01J5DEVXX00000000000000001"

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
    # How long an account stays locked after exceeding the failed-attempt floor.
    password_lockout_minutes_floor: int = 30
    session_idle_timeout_floor_seconds: int = 30 * 60  # 30 min
    session_absolute_timeout_floor_seconds: int = 8 * 60 * 60  # 8h
    session_max_concurrent_floor: int = 2

    # Refresh-token rotation / reuse detection.
    #   * rotation_enabled: Keycloak realm/client must ALSO have rotation on;
    #     this gates the foundation-side blacklist write + reuse check.
    #   * reuse_detection_enabled: when a rotated (already-used) refresh token is
    #     presented again, revoke ALL of the user's sessions as a breach signal.
    #   * refresh_token_lifespan_seconds: TTL for the reuse-blacklist Redis key
    #     (a used jti only needs to be remembered until it would have expired).
    refresh_token_rotation_enabled: bool = True
    refresh_reuse_detection_enabled: bool = True
    refresh_token_lifespan_seconds: int = 8 * 60 * 60  # 8h, matches absolute floor

    # Symmetric key (urlsafe-base64, 32 bytes) used to encrypt TOTP secrets at
    # rest via Fernet, so identity.mfa_method.secret_ref never holds plaintext.
    # Dev default is fixed; production MUST override with a generated key
    # (`Fernet.generate_key()`).  Rotating this invalidates existing TOTP secrets.
    mfa_secret_encryption_key: SecretStr = SecretStr(
        "ZGV2LW1mYS10b3RwLWtleS1jaGFuZ2UtbWUtMzJieXQ="
    )
    # Number of one-time recovery codes generated when a user first enrols MFA.
    mfa_recovery_code_count: int = 8

    # -------------------------------------------------------------------------
    # Downstream service URLs (used by provisioning service)
    # -------------------------------------------------------------------------
    org_url: str = "http://org:8003/api/org/v1"
    billing_url: str = "http://billing:8007/api/billing/v1"

    # -------------------------------------------------------------------------
    # Platform admin
    # -------------------------------------------------------------------------
    # Pre-shared secret carried in X-Internal-Admin-Token by the BFF admin path.
    # When present and correct, platform-admin endpoints may open an
    # admin_session_scope.  Empty string means the feature is disabled
    # (suitable for tenant-service-only deployments; platform endpoints will
    # always 403 if authz check fails anyway — this is defence-in-depth).
    internal_admin_token: SecretStr = SecretStr("")
    authz_url: str = "http://authz:8002/api/authz/v1"

    # -------------------------------------------------------------------------
    # Multi-tenancy
    # -------------------------------------------------------------------------
    # DB session 启用时强制 set local app.tenant_id；None 走 platform-admin role
    require_tenant_context: bool = True


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings singleton; safe to call from any layer."""
    return Settings()
