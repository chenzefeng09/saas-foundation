"""Shared fixtures for the audit tests."""

from __future__ import annotations

import time
from collections.abc import Iterator
from datetime import datetime, timedelta

import pytest


@pytest.fixture
def local_time_not_utc(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Run the test with local time at UTC+8.

    ClickHouse hands back ``DateTime64(3, 'UTC')`` as naive datetimes.  Code that
    reads one as local time instead of UTC only goes wrong where local time is
    not UTC, so a test of that handling proves nothing on a UTC host without this.
    """
    monkeypatch.setenv("TZ", "<+08>-8")  # POSIX form: needs no tz database
    time.tzset()
    assert datetime(2026, 10, 30).astimezone().utcoffset() == timedelta(hours=8)
    yield
    monkeypatch.undo()
    time.tzset()
