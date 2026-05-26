"""FastAPI application factory + uvicorn entrypoint."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from foundation_crypto import __version__
from foundation_crypto.api.exception_handlers import install_exception_handlers
from foundation_crypto.api.middleware import RequestIdMiddleware, TenantContextMiddleware
from foundation_crypto.api.v1 import api_v1
from foundation_crypto.config import get_settings
from foundation_crypto.domain.db import dispose_engine
from foundation_crypto.observability import get_logger, setup_observability

log = get_logger(__name__)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:  # noqa: ARG001
    log.info("startup", version=__version__)
    yield
    log.info("shutdown")
    await dispose_engine()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Crypto Service API",
        version=__version__,
        description="SaaS Foundation — Crypto Service (envelope encryption + KEK lifecycle + signatures + password hashing)",
        openapi_url=f"{settings.api_prefix}/openapi.json",
        docs_url=f"{settings.api_prefix}/docs",
        redoc_url=f"{settings.api_prefix}/redoc",
        lifespan=_lifespan,
    )
    app.add_middleware(TenantContextMiddleware)
    app.add_middleware(RequestIdMiddleware)
    install_exception_handlers(app)
    setup_observability(app)
    app.include_router(api_v1, prefix=settings.api_prefix)
    return app


app = create_app()


def run() -> None:
    settings = get_settings()
    uvicorn.run(
        "foundation_crypto.main:app",
        host=settings.http_host,
        port=settings.http_port,
        reload=settings.env == "dev",
        access_log=False,
    )


if __name__ == "__main__":
    run()
