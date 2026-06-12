"""Widen identity.session.id from varchar(30) to varchar(40).

Session ids are generated as ``f"sess_{ulid.new()}"`` = ``sess_`` (5) + a
26-char ULID = 31 characters, which overflows the original varchar(30) and
raises ``StringDataRightTruncationError`` on every login.  Widen to 40 to match
the ``sso_routing_rule.id`` column and leave headroom for the prefix.

Revision ID: 0008_widen_session_id
Revises: 0007_risk_session_score
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0008_widen_session_id"
down_revision = "0007_risk_session_score"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "session",
        "id",
        type_=sa.String(length=40),
        existing_type=sa.String(length=30),
        existing_nullable=False,
        schema="identity",
    )


def downgrade() -> None:
    op.alter_column(
        "session",
        "id",
        type_=sa.String(length=30),
        existing_type=sa.String(length=40),
        existing_nullable=False,
        schema="identity",
    )
