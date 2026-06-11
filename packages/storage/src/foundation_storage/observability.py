"""Logging helper.  Library does NOT configure structlog — that's the app's job."""

from __future__ import annotations

import structlog


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a bound structlog logger, namespaced under ``foundation_storage``."""
    logger: structlog.stdlib.BoundLogger = structlog.get_logger(name or "foundation_storage")
    return logger
