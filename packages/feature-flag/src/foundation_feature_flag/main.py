"""FastAPI application factory + uvicorn entrypoint."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from foundation_feature_flag import __version__
from foundation_feature_flag.api.exception_handlers import install_exception_handlers
from foundation_feature_flag.api.middleware import RequestIdMiddleware, TenantContextMiddleware
from foundation_feature_flag.api.v1 import api_v1
from foundation_feature_flag.config import get_settings
from foundation_feature_flag.domain.db import dispose_engine
from foundation_feature_flag.observability import get_logger, setup_observability
from foundation_feature_flag.services.feature_flag_service import FeatureFlagService
from foundation_feature_flag.services.unleash_gateway import get_gateway

log = get_logger(__name__)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    log.info("startup", version=__version__, service="feature-flag")

    # Initialize Unleash gateway (blocking: fetches toggles from Unleash)
    gateway = get_gateway()
    gateway.initialize()

    # Load standard flag presets (registers fallback defaults into gateway)
    svc = FeatureFlagService(gateway=gateway)
    svc.load_presets()

    # Store service on app state so endpoints can access it
    app.state.feature_flag_service = svc
    app.state.unleash_gateway = gateway

    yield

    log.info("shutdown")
    gateway.destroy()
    await dispose_engine()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Feature Flag Service API",
        version=__version__,
        description="SaaS Foundation — Feature Flag Service",
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
        "foundation_feature_flag.main:app",
        host=settings.http_host,
        port=settings.http_port,
        reload=settings.env == "dev",
        access_log=False,
    )


if __name__ == "__main__":
    run()
