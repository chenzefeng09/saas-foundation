"""OTel + structlog (minimal)."""

from __future__ import annotations
import logging, sys
from typing import TYPE_CHECKING
import structlog
from prometheus_client import Counter
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.sdk.resources import SERVICE_NAME, SERVICE_VERSION, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from foundation_dlp import __version__
from foundation_dlp.config import get_settings

if TYPE_CHECKING: from fastapi import FastAPI

# ---------------------------------------------------------------------------
# Prometheus metrics (module-level singletons; .inc() never raises)
# ---------------------------------------------------------------------------
dlp_scan_total = Counter(
    "dlp_scan_total", "Total DLP content scans, by resulting action", ["action"])
dlp_scan_hits_total = Counter(
    "dlp_scan_hits_total", "Total DLP content scans that produced at least one rule hit")
dlp_check_total = Counter(
    "dlp_check_total", "Total DLP access checks, by check type and decision",
    ["check_type", "decision"])

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
        FastAPIInstrumentor.instrument_app(app, excluded_urls="/healthz,/readyz,/metrics")
        HTTPXClientInstrumentor().instrument()

def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name or "foundation_dlp")
