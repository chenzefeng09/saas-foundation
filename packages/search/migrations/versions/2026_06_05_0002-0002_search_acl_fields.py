"""Add acl_team_ids, owner_id, visibility to search_index (M2 ACL expansion)

Revision ID: 0002_search_acl_fields
Revises: 0001_search_init
Create Date: 2026-06-05 00:00:00 UTC
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_search_acl_fields"
down_revision: str | None = "0001_search_init"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "search_index",
        sa.Column("acl_team_ids", postgresql.ARRAY(sa.String()), nullable=True),
        schema="search",
    )
    op.add_column(
        "search_index",
        sa.Column("owner_id", sa.String(64), nullable=True),
        schema="search",
    )
    op.add_column(
        "search_index",
        sa.Column("visibility", sa.String(30), nullable=True),
        schema="search",
    )


def downgrade() -> None:
    op.drop_column("search_index", "visibility", schema="search")
    op.drop_column("search_index", "owner_id", schema="search")
    op.drop_column("search_index", "acl_team_ids", schema="search")
