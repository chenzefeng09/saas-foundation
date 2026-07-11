"""Change the classification fallback default to L3.

Revision ID: 0003_dlp_default_sensitivity_l3
Revises: 0002_dlp_default_rules
Create Date: 2026-07-10 00:00:00 UTC
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_dlp_default_sensitivity_l3"
down_revision: str | None = "0002_dlp_default_rules"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "classification",
        "sensitivity",
        schema="dlp",
        existing_type=sa.String(length=2),
        server_default="L3",
        existing_nullable=False,
    )
    op.create_check_constraint(
        "ck_dlp_classification_sensitivity",
        "classification",
        "sensitivity IN ('L1','L2','L3','L4','L5')",
        schema="dlp",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_dlp_classification_sensitivity",
        "classification",
        schema="dlp",
        type_="check",
    )
    op.alter_column(
        "classification",
        "sensitivity",
        schema="dlp",
        existing_type=sa.String(length=2),
        server_default="L2",
        existing_nullable=False,
    )
