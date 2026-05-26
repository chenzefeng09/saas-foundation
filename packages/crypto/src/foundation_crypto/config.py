"""ENV-driven settings (pydantic-settings)."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import AnyHttpUrl, Field, PostgresDsn
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All service config; reads from environment (and `.env` in dev)."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="CRYPTO_",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------ Service
    service_name: str = "crypto-service"
    env: Literal["dev", "staging", "production"] = "dev"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_format: Literal["json", "console"] = "json"

    # ------------------------------------------------------------ HTTP
    http_host: str = "0.0.0.0"  # noqa: S104
    http_port: int = 8004
    api_prefix: str = "/api/crypto/v1"

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

    # ------------------------------------------------------------ Vault
    # Default points at the docker-compose dev Vault. Prod uses Raft + HSM unseal.
    vault_url: AnyHttpUrl = Field(default=AnyHttpUrl("http://127.0.0.1:8200"))
    vault_token: str = "dev-root-token"  # dev only; prod uses approle / k8s auth
    vault_transit_mount: str = "transit"
    vault_timeout_seconds: float = 2.0
    # When Vault is unreachable: only FAIL_CLOSE is allowed (crypto is critical
    # path). Setting kept as a literal so failure mode is explicit in config.
    vault_unavailable_behaviour: Literal["FAIL_CLOSE"] = "FAIL_CLOSE"

    # ------------------------------------------------------------ Provider selection
    # v1.0: Vault transit provider
    # v1.1: Tongsuo PKCS#11 HSM provider (国密 SM2/SM3/SM4 hardware-backed)
    crypto_provider: Literal["vault", "local_test", "tongsuo_pkcs11"] = "vault"

    # ------------------------------------------------------------ PKCS#11 (v1.1)
    # Path to the PKCS#11 shared library (Tongsuo libtongs.so or softhsm2 libsofthsm2.so)
    pkcs11_module_path: str = "/usr/lib/libtongs.so"
    # PKCS#11 slot ID for the HSM token
    pkcs11_slot_id: int = 0
    # PKCS#11 token label (optional)
    pkcs11_token_label: str = "foundation"
    # PKCS#11 user PIN — MUST be injected via env/secrets, not hardcoded
    pkcs11_pin: str = ""

    # ------------------------------------------------------------ Envelope schema
    envelope_schema_version: int = 1

    # ------------------------------------------------------------ KEK lifecycle
    kek_default_rotation_days: int = 90
    kek_destruction_cooling_off_days: int = 30
    # When True, destroy() requires at least one approver_id distinct from the
    # actor (four-eyes). Enforced in the service layer.
    kek_destroy_requires_four_eyes: bool = True

    # ------------------------------------------------------------ Password hashing
    # OWASP defaults; tunable per-tenant via crypto.tenant_algorithm_policy later.
    argon2_memory_kib: int = 65536  # 64 MiB
    argon2_time_cost: int = 3
    argon2_parallelism: int = 4
    argon2_hash_len: int = 32
    argon2_salt_len: int = 16

    # ------------------------------------------------------------ Audit
    audit_publisher_kind: Literal["outbox_db", "log_only"] = "outbox_db"
    # Sampling (encrypt 100% / decrypt 1% / sign 100% / destroy 100%) is enforced
    # in the EnvelopeService.
    decrypt_audit_sample_rate: float = 0.01

    # ------------------------------------------------------------ OTel
    otel_enabled: bool = True
    otel_exporter_endpoint: str = "http://127.0.0.1:4317"
    otel_exporter_protocol: Literal["grpc", "http"] = "grpc"

    # ------------------------------------------------------------ Multi-tenancy
    require_tenant_context: bool = True


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
