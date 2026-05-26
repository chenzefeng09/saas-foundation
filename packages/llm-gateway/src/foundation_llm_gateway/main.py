"""FastAPI application factory + uvicorn entrypoint."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from foundation_llm_gateway import __version__
from foundation_llm_gateway.api.exception_handlers import install_exception_handlers
from foundation_llm_gateway.api.middleware import RequestIdMiddleware, TenantContextMiddleware
from foundation_llm_gateway.api.v1 import api_v1
from foundation_llm_gateway.config import get_settings
from foundation_llm_gateway.domain.db import dispose_engine
from foundation_llm_gateway.observability import get_logger, setup_observability

log = get_logger(__name__)

@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    log.info("startup", version=__version__, service="llm-gateway")
    yield
    log.info("shutdown")
    await dispose_engine()

def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="LLM Gateway Service API", version=__version__,
        description="SaaS Foundation — LLM Gateway Service",
        openapi_url=f"{settings.api_prefix}/openapi.json",
        docs_url=f"{settings.api_prefix}/docs", redoc_url=f"{settings.api_prefix}/redoc",
        lifespan=_lifespan)
    app.add_middleware(TenantContextMiddleware)
    app.add_middleware(RequestIdMiddleware)
    install_exception_handlers(app)
    setup_observability(app)
    app.include_router(api_v1, prefix=settings.api_prefix)
    return app

app = create_app()

def run() -> None:
    settings = get_settings()
    uvicorn.run("foundation_llm_gateway.main:app", host=settings.http_host,
                port=settings.http_port, reload=settings.env == "dev", access_log=False)

if __name__ == "__main__":
    run()
