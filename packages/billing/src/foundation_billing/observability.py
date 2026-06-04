"""OpenTelemetry + structured logging initialisation."""

from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING

import structlog

from foundation_billing import __version__
from foundation_billing.config import get_settings

if TYPE_CHECKING:
    from fastapi import FastAPI


def _configure_logging() -> None:
    settings = get_settings()
    log_level = getattr(settings, "log_level", "INFO")
    log_format = getattr(settings, "log_format", "json")
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=log_level)
    processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    if log_format == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelName(log_level),
        ),
        cache_logger_on_first_use=True,
    )


def _configure_tracing() -> None:
    settings = get_settings()
    if not getattr(settings, "otel_enabled", False):
        return
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import SERVICE_NAME, SERVICE_VERSION, Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        return

    resource = Resource.create(
        {
            SERVICE_NAME: getattr(settings, "service_name", "billing"),
            SERVICE_VERSION: __version__,
            "deployment.environment": getattr(settings, "env", "dev"),
        }
    )
    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(
        endpoint=getattr(settings, "otel_exporter_endpoint", "http://127.0.0.1:4317"),
        insecure=True,
    )
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)


def setup_observability(app: FastAPI) -> None:
    _configure_logging()
    _configure_tracing()
    settings = get_settings()
    if not getattr(settings, "otel_enabled", False):
        return
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

        FastAPIInstrumentor.instrument_app(app, excluded_urls="/healthz,/readyz,/metrics")
        HTTPXClientInstrumentor().instrument()
        SQLAlchemyInstrumentor().instrument(enable_commenter=True)
    except ImportError:
        pass


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name or "foundation_billing")
