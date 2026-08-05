"""Backfill and enforce the L3 default for user clearance.

Legacy rows created after revision 0010 may have NULL clearance.  Their
effective read value is already L3 in the application; this migration makes the
stored value match, installs the database default, and prevents values outside
the supported L1-L5 range.

Revision ID: 0011_enforce_user_clearance_l3
Revises: 0010_add_user_clearance
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0011_enforce_user_clearance_l3"
down_revision = "0010_add_user_clearance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("UPDATE identity.\"user\" SET clearance = 'L3' WHERE clearance IS NULL")
    op.alter_column(
        "user",
        "clearance",
        schema="identity",
        existing_type=sa.String(length=2),
        nullable=False,
        server_default="L3",
    )
    op.create_check_constraint(
        "ck_user_clearance",
        "user",
        "clearance IN ('L1','L2','L3','L4','L5')",
        schema="identity",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_user_clearance",
        "user",
        schema="identity",
        type_="check",
    )
    op.alter_column(
        "user",
        "clearance",
        schema="identity",
        existing_type=sa.String(length=2),
        nullable=True,
        server_default=None,
    )
