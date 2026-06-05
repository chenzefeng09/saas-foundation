"""Tests for SLA computation logic."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from foundation_security_ops.services.sla import (
    compute_due_at,
    days_overdue,
    incident_notification_sla_hours,
    is_overdue,
)


class TestComputeDueAt:
    def test_critical_24h(self):
        found = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
        due = compute_due_at(found, "CRITICAL")
        assert due == found + timedelta(days=1)

    def test_high_7d(self):
        found = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
        due = compute_due_at(found, "HIGH")
        assert due == found + timedelta(days=7)

    def test_medium_30d(self):
        found = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
        due = compute_due_at(found, "MEDIUM")
        assert due == found + timedelta(days=30)

    def test_low_60d(self):
        found = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
        due = compute_due_at(found, "LOW")
        assert due == found + timedelta(days=60)

    def test_case_insensitive(self):
        found = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
        assert compute_due_at(found, "critical") == compute_due_at(found, "CRITICAL")

    def test_unknown_severity_raises(self):
        found = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
        with pytest.raises(ValueError, match="Unknown severity"):
            compute_due_at(found, "UNKNOWN")


class TestIsOverdue:
    def test_not_overdue_when_before_due(self):
        due = datetime(2026, 12, 31, 0, 0, 0, tzinfo=UTC)
        now = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
        assert is_overdue(due, now=now) is False

    def test_overdue_when_past_due(self):
        due = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
        now = datetime(2026, 1, 2, 0, 0, 0, tzinfo=UTC)
        assert is_overdue(due, now=now) is True

    def test_exactly_at_due_not_overdue(self):
        ts = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
        assert is_overdue(ts, now=ts) is False


class TestDaysOverdue:
    def test_two_days_overdue(self):
        due = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
        now = datetime(2026, 1, 3, 0, 0, 0, tzinfo=UTC)
        assert abs(days_overdue(due, now=now) - 2.0) < 0.01

    def test_five_days_remaining(self):
        due = datetime(2026, 1, 10, 0, 0, 0, tzinfo=UTC)
        now = datetime(2026, 1, 5, 0, 0, 0, tzinfo=UTC)
        val = days_overdue(due, now=now)
        assert val < 0  # negative = days remaining


class TestIncidentNotificationSla:
    def test_critical_1h(self):
        assert incident_notification_sla_hours("CRITICAL") == 1.0

    def test_high_4h(self):
        assert incident_notification_sla_hours("HIGH") == 4.0

    def test_medium_24h(self):
        assert incident_notification_sla_hours("MEDIUM") == 24.0

    def test_unknown_raises(self):
        with pytest.raises(ValueError):
            incident_notification_sla_hours("BOGUS")
