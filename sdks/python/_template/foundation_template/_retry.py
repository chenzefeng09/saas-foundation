"""Retry policy — defaults defined in docs/errors.md §7.3."""

from __future__ import annotations

import logging
import random
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

import httpx

from foundation_template.errors import (
    DependencyError,
    FoundationError,
    QuotaExceededError,
    RateLimitedError,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 3
    base_delay_seconds: float = 0.5
    max_delay_seconds: float = 30.0
    jitter: bool = True

    def should_retry(self, exc: BaseException, attempt: int) -> bool:
        if attempt >= self.max_attempts:
            return False
        # Network-level retryable
        if isinstance(exc, (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteTimeout)):
            return True
        # Application-level retryable
        if isinstance(exc, DependencyError):
            return True
        if isinstance(exc, (QuotaExceededError, RateLimitedError)):
            # Only retry once, respecting Retry-After
            return attempt < 1
        return False

    def delay_for(self, attempt: int, exc: BaseException | None = None) -> float:
        # Respect server Retry-After when present
        if isinstance(exc, FoundationError) and exc.retry_after is not None:
            return float(exc.retry_after)
        delay = min(self.base_delay_seconds * (2**attempt), self.max_delay_seconds)
        if self.jitter:
            delay *= 0.5 + random.random()
        return delay


DEFAULT_RETRY = RetryPolicy()


def with_retry(
    func: Callable[[], T],
    policy: RetryPolicy = DEFAULT_RETRY,
    sleep: Callable[[float], None] | None = None,
) -> T:
    """Sync retry helper. Async equivalent lives in _transport.py."""
    import time

    sleep_fn = sleep or time.sleep

    attempt = 0
    while True:
        try:
            return func()
        except Exception as exc:
            if not policy.should_retry(exc, attempt):
                raise
            delay = policy.delay_for(attempt, exc)
            logger.warning(
                "Retrying after error",
                extra={"attempt": attempt + 1, "delay_s": delay, "error": str(exc)},
            )
            sleep_fn(delay)
            attempt += 1
