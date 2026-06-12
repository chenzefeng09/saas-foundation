"""Widen identity prefix+ULID id columns from varchar(30) to varchar(40).

Several identity tables generate their primary key as ``f"<prefix>_{ulid.new()}"``
where the prefix is 4 chars (e.g. ``mfa_``, ``rec_``, ``rsk_``, ``sso_``,
``evt_``) plus a 26-char ULID = 30 characters, sitting exactly at the
varchar(30) boundary with zero headroom.  This is the same truncation class of
bug already fixed for ``session.id`` (0008): a 5-char prefix would overflow.
Widen these to 40 to match ``session.id`` / ``sso_routing_rule.id`` and leave
headroom for the prefix.

Affected columns (all schema ``identity``):
  * mfa_method.id    (mfa_)
  * recovery_code.id (rec_)
  * risk_signal.id   (rsk_)
  * sso_provider.id  (sso_)
  * outbox.id        (evt_)

Revision ID: 0009_widen_id_cols
Revises: 0008_widen_session_id
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0009_widen_id_cols"
down_revision = "0008_widen_session_id"
branch_labels = None
depends_on = None

_TABLES = ("mfa_method", "recovery_code", "risk_signal", "sso_provider", "outbox")


def upgrade() -> None:
    for table in _TABLES:
        op.alter_column(
            table,
            "id",
            type_=sa.String(length=40),
            existing_type=sa.String(length=30),
            existing_nullable=False,
            schema="identity",
        )


def downgrade() -> None:
    for table in _TABLES:
        op.alter_column(
            table,
            "id",
            type_=sa.String(length=30),
            existing_type=sa.String(length=40),
            existing_nullable=False,
            schema="identity",
        )
