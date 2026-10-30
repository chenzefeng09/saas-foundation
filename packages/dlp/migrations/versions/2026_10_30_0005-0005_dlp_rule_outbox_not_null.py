"""Make dlp_rule.created_at and dlp_event_outbox.occurred_at NOT NULL; comment min_sensitivity.

0001 created both timestamps nullable and left out the ``min_sensitivity``
comment that the model declares, so ``alembic check`` reported drift.  The
models are right: every writer (0002's seed rows, ``POST /sensitive-words``,
``DLPService._emit``) leaves the column to its ``now()`` default, nothing
gives a NULL a meaning (as a NULL ``published_at`` means "not relayed yet"),
and docs/multi-tenancy.md §6.1 makes ``created_at`` NOT NULL.

So a NULL can only have been written by hand, and the row keeps no record of
the real time.  The backfill takes the tightest upper bound the row carries:
for an outbox event its ``published_at`` when set, since an event is
published after it occurs; otherwise the migration's ``now()``, which is what
``ADD COLUMN ... NOT NULL DEFAULT now()`` gives existing rows.

Revision ID: 0005_dlp_rule_outbox_not_null
Revises: 0004_dlp_cls_updated_at
Create Date: 2026-10-30 00:00:00 UTC
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_dlp_rule_outbox_not_null"
down_revision: str | None = "0004_dlp_cls_updated_at"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_MIN_SENSITIVITY_COMMENT = "Minimum sensitivity triggered when this rule matches"


def upgrade() -> None:
    # Both tables are FORCE ROW LEVEL SECURITY with policies for the app roles
    # only (dlp_rule also holds the NULL-tenant global rules), so a role subject
    # to RLS would backfill nothing.  The migrator bypasses RLS
    # (docs/multi-tenancy.md §8.1); with row_security off, Postgres raises
    # instead of filtering if it ever does not.
    op.execute("SET LOCAL row_security = off")
    op.execute("UPDATE dlp.dlp_rule SET created_at = now() WHERE created_at IS NULL")
    op.execute(
        "UPDATE dlp.dlp_event_outbox SET occurred_at = coalesce(published_at, now()) "
        "WHERE occurred_at IS NULL"
    )
    op.execute("RESET row_security")
    # dlp_rule before the outbox: a scan reads the rules before it writes the
    # outbox, so taking ACCESS EXCLUSIVE in this order cannot deadlock with one.
    op.alter_column(
        "dlp_rule",
        "created_at",
        schema="dlp",
        existing_type=sa.DateTime(timezone=True),
        nullable=False,
    )
    op.alter_column(
        "dlp_rule",
        "min_sensitivity",
        schema="dlp",
        existing_type=sa.String(length=2),
        existing_nullable=False,
        comment=_MIN_SENSITIVITY_COMMENT,
        existing_comment=None,
    )
    op.alter_column(
        "dlp_event_outbox",
        "occurred_at",
        schema="dlp",
        existing_type=sa.DateTime(timezone=True),
        nullable=False,
    )


def downgrade() -> None:
    # The backfill is not undone: the NULLs it replaced carried no information.
    # Same table order as upgrade, for the same reason.
    op.alter_column(
        "dlp_rule",
        "created_at",
        schema="dlp",
        existing_type=sa.DateTime(timezone=True),
        nullable=True,
    )
    op.alter_column(
        "dlp_rule",
        "min_sensitivity",
        schema="dlp",
        existing_type=sa.String(length=2),
        existing_nullable=False,
        comment=None,
        existing_comment=_MIN_SENSITIVITY_COMMENT,
    )
    op.alter_column(
        "dlp_event_outbox",
        "occurred_at",
        schema="dlp",
        existing_type=sa.DateTime(timezone=True),
        nullable=True,
    )
