from functools import lru_cache
from typing import Literal

from pydantic import AnyHttpUrl, PostgresDsn
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SEARCH_", extra="ignore")

    service_name: str = "search"
    env: Literal["dev", "staging", "production"] = "dev"

    # HTTP server
    http_host: str = "0.0.0.0"
    http_port: int = 8009
    api_prefix: str = "/api/search/v1"

    # Postgres
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

    # OpenSearch — used in M2 query/index phase
    opensearch_url: str = "http://127.0.0.1:9200"
    opensearch_index: str = "foundation-search-v1"
    opensearch_alias: str = "foundation-search"

    # Authz service — for ACL ID resolution (list-accessible-ids)
    authz_url: str = "http://127.0.0.1:8002/api/authz/v1"

    # Observability
    otel_enabled: bool = True
    otel_exporter_endpoint: str = "http://127.0.0.1:4317"
    require_tenant_context: bool = True


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()

