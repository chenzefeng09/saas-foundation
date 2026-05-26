"""Retry policy for SDK HTTP calls."""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass

import httpx

from foundation_sdk.errors import DependencyError, FoundationError, QuotaExceededError, RateLimitedError

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 3
    base_delay_seconds: float = 0.5
    max_delay_seconds: float = 30.0
    jitter: bool = True

    def should_retry(self, exc: BaseException, attempt: int) -> bool:
        if attempt >= self.max_attempts:
            return False
        if isinstance(exc, (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteTimeout)):
            return True
        if isinstance(exc, DependencyError):
            return True
        if isinstance(exc, (QuotaExceededError, RateLimitedError)):
            return attempt < 1
        return False

    def delay_for(self, attempt: int, exc: BaseException | None = None) -> float:
        if isinstance(exc, FoundationError) and exc.retry_after is not None:
            return float(exc.retry_after)
        delay = min(self.base_delay_seconds * (2 ** attempt), self.max_delay_seconds)
        if self.jitter:
            delay *= 0.5 + random.random()
        return delay


DEFAULT_RETRY = RetryPolicy()
