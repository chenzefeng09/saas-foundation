from functools import lru_cache; from typing import Literal
from pydantic import PostgresDsn; from pydantic_settings import BaseSettings, SettingsConfigDict
class Settings(BaseSettings):
    model_config=SettingsConfigDict(env_file=".env",env_prefix="SEARCH_",extra="ignore")
    service_name:str="search"; env:Literal["dev","staging","production"]="dev"
    http_host:str="0.0.0.0"; http_port:int=8009; api_prefix:str="/api/search/v1"
    db_dsn:PostgresDsn=PostgresDsn("postgresql+asyncpg://app_user:app_user_change_me@127.0.0.1:6432/foundation")
    db_dsn_migrator:PostgresDsn=PostgresDsn("postgresql+asyncpg://app_migrator:app_migrator_change_me@127.0.0.1:5432/foundation")
    db_pool_size:int=10; db_max_overflow:int=10; db_pool_timeout_seconds:int=30; db_echo:bool=False
    otel_enabled:bool=True; otel_exporter_endpoint:str="http://127.0.0.1:4317"; require_tenant_context:bool=True
@lru_cache(maxsize=1)
def get_settings()->Settings:return Settings()
