"""Backfill classification.updated_at, make it NOT NULL and index the label list.

0001 created ``updated_at`` nullable although the model declares it non-null.
``GET /core/classifications`` keyset-pages on ``(updated_at, id)`` newest first
(``services.pagination``): a NULL sorts first under DESC, never satisfies the
row comparison that selects a later page, and a page ending on one cannot
encode its cursor.  A label never changed since it was tagged has
``updated_at = tagged_at`` (both default to the inserting transaction's
``now()``), so that is the backfill.

``class_tenant_updated_idx`` matches the list's order, so a page is an index
scan starting at the cursor instead of a sort of every label the tenant has.

Revision ID: 0004_dlp_cls_updated_at
Revises: 0003_dlp_default_sensitivity_l3
Create Date: 2026-10-30 00:00:00 UTC
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_dlp_cls_updated_at"
down_revision: str | None = "0003_dlp_default_sensitivity_l3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # classification is FORCE ROW LEVEL SECURITY and its policies are for app_user
    # and app_admin only, so a role subject to RLS sees no rows here and would
    # backfill none.  The migrator bypasses RLS (docs/multi-tenancy.md §8.1); with
    # row_security off, Postgres raises instead of filtering if it ever does not.
    op.execute("SET LOCAL row_security = off")
    op.execute("UPDATE dlp.classification SET updated_at = tagged_at WHERE updated_at IS NULL")
    op.execute("RESET row_security")
    op.alter_column(
        "classification",
        "updated_at",
        schema="dlp",
        existing_type=sa.DateTime(timezone=True),
        nullable=False,
    )
    op.create_index(
        "class_tenant_updated_idx",
        "classification",
        ["tenant_id", "updated_at", "id"],
        schema="dlp",
    )


def downgrade() -> None:
    # The backfill is not undone: the NULLs it replaced carried no information.
    op.drop_index("class_tenant_updated_idx", table_name="classification", schema="dlp")
    op.alter_column(
        "classification",
        "updated_at",
        schema="dlp",
        existing_type=sa.DateTime(timezone=True),
        nullable=True,
    )
