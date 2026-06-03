"""init search schema

Revision ID: 0001_search_init
Revises:
Create Date: 2026-06-03 00:00:00 UTC
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_search_init"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS search")

    op.create_table(
        "search_index",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False),
        sa.Column("resource_type", sa.String(50), nullable=False),
        sa.Column("resource_id", sa.String(64), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.String(32), nullable=False),
        sa.Column("tags", postgresql.ARRAY(sa.String())),
        sa.Column("acl_user_ids", postgresql.ARRAY(sa.String())),
        sa.Column("metadata", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("indexed_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("deleted_at", sa.DateTime(timezone=True)),
        schema="search",
    )
    op.create_index("si_tenant_type_idx", "search_index", ["tenant_id", "resource_type"], schema="search")

    op.create_table(
        "search_query_log",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), nullable=False),
        sa.Column("query", sa.Text(), nullable=False),
        sa.Column("user_id", sa.String(30)),
        sa.Column("result_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("searched_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="search",
    )

    op.create_table(
        "search_event_outbox",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(30)),
        sa.Column("event_type", sa.String(200), nullable=False),
        sa.Column("aggregate_id", sa.String(64)),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("request_id", sa.String(64)),
        sa.Column("occurred_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="search",
    )

    op.execute("GRANT USAGE ON SCHEMA search TO app_user, app_admin, app_observability")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA search TO app_user, app_admin")
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA search TO app_observability")


def downgrade() -> None:
    op.execute("DROP SCHEMA IF EXISTS search CASCADE")
