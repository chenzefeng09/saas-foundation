"""Add ``clearance`` column to identity.user.

Adds a global per-user security-clearance attribute (values ``"L1".."L5"``).
Nullable so existing rows are unaffected; the read side defaults a missing
value to ``L2``.

Revision ID: 0010_add_user_clearance
Revises: 0009_widen_id_cols
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0010_add_user_clearance"
down_revision = "0009_widen_id_cols"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "user",
        sa.Column("clearance", sa.String(length=2), nullable=True),
        schema="identity",
    )


def downgrade() -> None:
    op.drop_column("user", "clearance", schema="identity")
