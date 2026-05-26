"""OTel + structlog (minimal)."""

from __future__ import annotations
import logging, sys; from typing import TYPE_CHECKING
import structlog
if TYPE_CHECKING: from fastapi import FastAPI

def setup_observability(app: FastAPI) -> None:
    pass

def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name or "foundation_data_protection")
