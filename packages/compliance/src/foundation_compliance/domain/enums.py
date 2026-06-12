"""Compliance domain enums — centralized constrained vocabularies.

These enums back the API request models so FastAPI auto-validates (HTTP 422)
unknown values, and back the Alembic CHECK constraints so the DB rejects
out-of-vocabulary rows defensively.
"""

from __future__ import annotations

from enum import Enum


class LegalBasis(str, Enum):
    """Lawful basis for processing personal data.

    GDPR Art.6 bases plus PIPL Art.13 bases merged into one vocabulary;
    PIPL members are prefixed ``PIPL_`` to keep the two regimes distinct.
    """

    # GDPR Art.6
    CONSENT = "CONSENT"
    CONTRACT = "CONTRACT"
    LEGAL_OBLIGATION = "LEGAL_OBLIGATION"
    VITAL_INTEREST = "VITAL_INTEREST"
    PUBLIC_TASK = "PUBLIC_TASK"
    LEGITIMATE_INTEREST = "LEGITIMATE_INTEREST"

    # PIPL Art.13
    PIPL_CONSENT = "PIPL_CONSENT"
    PIPL_SEPARATE_CONSENT = "PIPL_SEPARATE_CONSENT"
    PIPL_CONTRACT = "PIPL_CONTRACT"
    PIPL_HR_MANAGEMENT = "PIPL_HR_MANAGEMENT"
    PIPL_LEGAL_DUTY = "PIPL_LEGAL_DUTY"
    PIPL_PUBLIC_HEALTH = "PIPL_PUBLIC_HEALTH"
    PIPL_PUBLIC_INTEREST = "PIPL_PUBLIC_INTEREST"
    PIPL_PUBLIC_DATA = "PIPL_PUBLIC_DATA"


class DsarRequestType(str, Enum):
    """Type of a Data Subject Access Request (GDPR Art.15-22 / PIPL ch.IV)."""

    ACCESS = "ACCESS"
    RECTIFICATION = "RECTIFICATION"
    ERASURE = "ERASURE"
    RESTRICTION = "RESTRICTION"
    PORTABILITY = "PORTABILITY"
    OBJECTION = "OBJECTION"
    AUTOMATED_DECISION = "AUTOMATED_DECISION"
