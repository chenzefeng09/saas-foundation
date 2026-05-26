"""OpenTelemetry + structured logging initialisation.

Call `setup_observability(app)` once from `main.py` after creating the FastAPI app.
"""

from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING

import structlog
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.sdk.resources import SERVICE_NAME, SERVICE_VERSION, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from foundation_identity import __version__
from foundation_identity.config import get_settings

if TYPE_CHECKING:
    from fastapi import FastAPI


def _configure_logging() -> None:
    settings = get_settings()
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=settings.log_level,
    )

    processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    if settings.log_format == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelName(settings.log_level),
        ),
        cache_logger_on_first_use=True,
    )


def _configure_tracing() -> None:
    settings = get_settings()
    if not settings.otel_enabled:
        return
    resource = Resource.create(
        {
            SERVICE_NAME: settings.service_name,
            SERVICE_VERSION: __version__,
            "deployment.environment": settings.env,
        }
    )
    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(endpoint=settings.otel_exporter_endpoint, insecure=True)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)


def setup_observability(app: FastAPI) -> None:
    """Install logging + OTel; call once from FastAPI app factory."""
    _configure_logging()
    _configure_tracing()

    settings = get_settings()
    if settings.otel_enabled:
        FastAPIInstrumentor.instrument_app(app, excluded_urls="/healthz,/readyz,/metrics")
        HTTPXClientInstrumentor().instrument()
        SQLAlchemyInstrumentor().instrument(enable_commenter=True)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Get a structured logger; safe to call from any layer."""
    return structlog.get_logger(name or "foundation_identity")
