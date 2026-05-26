"""FastAPI app factory."""

from __future__ import annotations
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
import uvicorn
from fastapi import FastAPI
from foundation_lifecycle import __version__
from foundation_lifecycle.api.exception_handlers import install_exception_handlers
from foundation_lifecycle.api.middleware import RequestIdMiddleware, TenantContextMiddleware
from foundation_lifecycle.api.v1 import api_v1
from foundation_lifecycle.config import get_settings
from foundation_lifecycle.domain.db import dispose_engine
from foundation_lifecycle.observability import get_logger, setup_observability

log = get_logger(__name__)

@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    log.info("startup", version=__version__)
    yield; log.info("shutdown"); await dispose_engine()

def create_app() -> FastAPI:
    s = get_settings()
    app = FastAPI(title="Lifecycle Service API", version=__version__,
        description="SaaS Foundation — Lifecycle Service",
        openapi_url=f"{s.api_prefix}/openapi.json", docs_url=f"{s.api_prefix}/docs",
        redoc_url=f"{s.api_prefix}/redoc", lifespan=_lifespan)
    app.add_middleware(TenantContextMiddleware); app.add_middleware(RequestIdMiddleware)
    install_exception_handlers(app); setup_observability(app)
    app.include_router(api_v1, prefix=s.api_prefix)
    return app

app = create_app()

def run() -> None:
    s = get_settings()
    uvicorn.run("foundation_lifecycle.main:app", host=s.http_host, port=s.http_port, reload=s.env == "dev", access_log=False)

if __name__ == "__main__": run()
