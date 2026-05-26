"""FastAPI application factory + uvicorn entrypoint."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from foundation_identity import __version__
from foundation_identity.api.exception_handlers import install_exception_handlers
from foundation_identity.api.middleware import RequestIdMiddleware, TenantContextMiddleware
from foundation_identity.api.v1 import api_v1
from foundation_identity.config import get_settings
from foundation_identity.domain.db import dispose_engine
from foundation_identity.observability import get_logger, setup_observability

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
        title="Identity Service API",
        version=__version__,
        description="SaaS Foundation — Identity Service",
        openapi_url=f"{settings.api_prefix}/openapi.json",
        docs_url=f"{settings.api_prefix}/docs",
        redoc_url=f"{settings.api_prefix}/redoc",
        lifespan=_lifespan,
    )

    # Order matters: middleware added last runs FIRST. We want RequestId outermost.
    app.add_middleware(TenantContextMiddleware)
    app.add_middleware(RequestIdMiddleware)

    install_exception_handlers(app)
    setup_observability(app)

    app.include_router(api_v1, prefix=settings.api_prefix)
    return app


# Uvicorn-discoverable
app = create_app()


def run() -> None:
    settings = get_settings()
    uvicorn.run(
        "foundation_identity.main:app",
        host=settings.http_host,
        port=settings.http_port,
        reload=settings.env == "dev",
        access_log=False,
    )


if __name__ == "__main__":
    run()
