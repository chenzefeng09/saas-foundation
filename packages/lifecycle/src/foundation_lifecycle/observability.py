"""OTel + structlog (minimal — mirrors sibling services).

Phase 7: registers a global MeterProvider so storage_quota_reconcile +
PostgresQuotaChecker can publish metrics over OTLP gRPC.  The collector's
``prometheus`` exporter (dev.yml) scrapes them at :8889.
"""

from __future__ import annotations
import logging, sys
from typing import TYPE_CHECKING
import structlog
from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import SERVICE_NAME, SERVICE_VERSION, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from foundation_lifecycle import __version__
from foundation_lifecycle.config import get_settings

if TYPE_CHECKING: from fastapi import FastAPI

def setup_observability(app: FastAPI) -> None:
    s = get_settings()
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=s.log_level)
    processors = [structlog.contextvars.merge_contextvars, structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(), structlog.processors.format_exc_info]
    if s.log_format == "json": processors.append(structlog.processors.JSONRenderer())
    else: processors.append(structlog.dev.ConsoleRenderer())
    structlog.configure(processors=processors, wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(s.log_level)), cache_logger_on_first_use=True)
    if s.otel_enabled:
        resource = Resource.create({SERVICE_NAME: s.service_name, SERVICE_VERSION: __version__, "deployment.environment": s.env})
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=s.otel_exporter_endpoint, insecure=True)))
        trace.set_tracer_provider(provider)
        # Phase 7: metrics pipeline for storage.quota.* gauges + counters.
        metric_reader = PeriodicExportingMetricReader(
            OTLPMetricExporter(endpoint=s.otel_exporter_endpoint, insecure=True)
        )
        meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
        metrics.set_meter_provider(meter_provider)
        FastAPIInstrumentor.instrument_app(app, excluded_urls="/healthz,/readyz,/metrics")
        HTTPXClientInstrumentor().instrument(); SQLAlchemyInstrumentor().instrument(enable_commenter=True)

def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name or "foundation_lifecycle")


def get_meter(name: str | None = None) -> metrics.Meter:
    """Return a Meter bound to the global MeterProvider.

    Safe to call before ``setup_observability`` — OTel falls back to a
    no-op provider until one is registered.
    """
    return metrics.get_meter(name or "foundation_lifecycle")
