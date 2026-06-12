"""Logging + metering helpers.

The library does NOT configure structlog or a MeterProvider — that's the
embedding service's job.  ``get_meter`` returns a Meter bound to whichever
provider the host registered; until one is, OTel hands back a no-op Meter
so instrumented call sites stay zero-cost.
"""

from __future__ import annotations

import structlog
from opentelemetry import metrics


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a bound structlog logger, namespaced under ``foundation_storage``."""
    logger: structlog.stdlib.BoundLogger = structlog.get_logger(name or "foundation_storage")
    return logger


def get_meter(name: str | None = None) -> metrics.Meter:
    """Return an OTel Meter, namespaced under ``foundation_storage``.

    Phase 7: ``PostgresQuotaChecker`` uses this to publish
    ``storage.quota.upload_total`` counters.  When the host hasn't called
    ``set_meter_provider`` yet (tests, scripts), OTel returns a no-op
    Meter — increments are dropped silently rather than crashing.
    """
    return metrics.get_meter(name or "foundation_storage")
