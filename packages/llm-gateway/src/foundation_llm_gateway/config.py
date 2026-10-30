from functools import lru_cache; from typing import Literal
from pydantic import Field, PostgresDsn; from pydantic_settings import BaseSettings, SettingsConfigDict
class Settings(BaseSettings):
    model_config=SettingsConfigDict(env_file=".env",env_prefix="LLM_GATEWAY_",extra="ignore")
    service_name:str="llm-gateway"; env:Literal["dev","staging","production"]="dev"
    http_host:str="0.0.0.0"; http_port:int=8011; api_prefix:str="/api/llm-gateway/v1"
    db_dsn:PostgresDsn=PostgresDsn("postgresql+asyncpg://app_user:app_user_change_me@127.0.0.1:6432/foundation")
    # app_admin is granted by the admin_all RLS policy once ``app.actor = 'ADMIN'``
    # is set in-transaction (db.admin_session_scope). Background jobs only.
    db_dsn_admin:PostgresDsn=PostgresDsn("postgresql+asyncpg://app_admin:app_admin_change_me@127.0.0.1:6432/foundation")
    db_dsn_migrator:PostgresDsn=PostgresDsn("postgresql+asyncpg://app_migrator:app_migrator_change_me@127.0.0.1:5432/foundation")
    db_pool_size:int=10; db_max_overflow:int=10; db_pool_timeout_seconds:int=30; db_echo:bool=False
    otel_enabled:bool=True; otel_exporter_endpoint:str="http://127.0.0.1:4317"; require_tenant_context:bool=True
    # P1: External service URLs (fail-open when unreachable)
    billing_url:str="http://127.0.0.1:8017"; crypto_url:str="http://127.0.0.1:8004"
    audit_url:str="http://127.0.0.1:8013"; external_timeout_seconds:float=5.0
    # Ephemeral-key purge (jobs.py). A run-scoped key stops authenticating the
    # moment it expires; the grace period only keeps its row (key -> tenant/run)
    # for incident forensics. 7 days = a week to look into a leaked key.
    ephemeral_key_purge_enabled:bool=True; ephemeral_key_purge_cron:str="0 * * * *"
    ephemeral_key_purge_grace_hours:int=Field(default=168,ge=0); ephemeral_key_purge_batch_size:int=Field(default=500,ge=1)
@lru_cache(maxsize=1)
def get_settings()->Settings:return Settings()
