"""SLA calculation helpers.

SLA table (from design doc §4):
  CRITICAL  notify 1h   fix 24h   verify 7d
  HIGH      notify 24h  fix 7d    verify 14d
  MEDIUM    notify 7d   fix 30d   verify 60d
  LOW       notify 30d  fix 60d   verify 90d (quarterly)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Final

# ── fix SLA in days, keyed by severity ─────────────────────────────────────

_FIX_DAYS: Final[dict[str, int]] = {
    "CRITICAL": 1,   # 24 h
    "HIGH": 7,
    "MEDIUM": 30,
    "LOW": 60,
}

_NOTIFY_HOURS: Final[dict[str, float]] = {
    "CRITICAL": 1,
    "HIGH": 24,
    "MEDIUM": 7 * 24,
    "LOW": 30 * 24,
}

_INCIDENT_NOTIFY_HOURS: Final[dict[str, float]] = {
    "CRITICAL": 1,
    "HIGH": 4,
    "MEDIUM": 24,
    "LOW": 7 * 24,
}


def compute_due_at(found_at: datetime, severity: str) -> datetime:
    """Return the SLA fix deadline for a vulnerability.

    severity must be one of CRITICAL / HIGH / MEDIUM / LOW.
    Raises ValueError for unknown severities.
    """
    days = _FIX_DAYS.get(severity.upper())
    if days is None:
        raise ValueError(f"Unknown severity: {severity!r}")
    return found_at + timedelta(days=days)


def is_overdue(vuln_due_at: datetime, now: datetime | None = None) -> bool:
    """Return True if the vulnerability SLA has been exceeded."""
    now = now or datetime.now(UTC)
    return now > vuln_due_at


def days_overdue(vuln_due_at: datetime, now: datetime | None = None) -> float:
    """Return number of days overdue (negative = days remaining)."""
    now = now or datetime.now(UTC)
    delta = now - vuln_due_at
    return delta.total_seconds() / 86400


def incident_notification_sla_hours(severity: str) -> float:
    """Return the number of hours within which an incident must be reported."""
    hours = _INCIDENT_NOTIFY_HOURS.get(severity.upper())
    if hours is None:
        raise ValueError(f"Unknown severity: {severity!r}")
    return hours
