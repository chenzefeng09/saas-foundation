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

_TENANT_TABLES = ("search_index", "search_query_log")


def _enable_tenant_rls(table: str) -> None:
    op.execute(f'ALTER TABLE search."{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE search."{table}" FORCE ROW LEVEL SECURITY')
    tenant_match = "tenant_id = current_setting('app.tenant_id', true)"
    for cmd in ("SELECT", "INSERT", "UPDATE", "DELETE"):
        policy_name = f"tenant_{cmd.lower()}"
        if cmd == "INSERT":
            clauses = f"WITH CHECK ({tenant_match})"
        elif cmd == "UPDATE":
            clauses = f"USING ({tenant_match}) WITH CHECK ({tenant_match})"
        else:
            clauses = f"USING ({tenant_match})"
        op.execute(
            f'CREATE POLICY {policy_name} ON search."{table}" '
            f"FOR {cmd} TO app_user, app_admin {clauses}"
        )
    op.execute(
        f'CREATE POLICY admin_all ON search."{table}" '
        f"FOR ALL TO app_admin "
        f"USING (current_setting('app.actor', true) = 'ADMIN') "
        f"WITH CHECK (current_setting('app.actor', true) = 'ADMIN')"
    )


def _enable_outbox_rls() -> None:
    op.execute("ALTER TABLE search.search_event_outbox ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE search.search_event_outbox FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY outbox_tenant_insert ON search.search_event_outbox "
        "FOR INSERT TO app_user, app_admin "
        "WITH CHECK ("
        "  tenant_id IS NULL OR tenant_id = current_setting('app.tenant_id', true)"
        ")"
    )
    op.execute(
        "CREATE POLICY outbox_tenant_select ON search.search_event_outbox "
        "FOR SELECT TO app_user, app_admin "
        "USING (tenant_id = current_setting('app.tenant_id', true))"
    )
    op.execute(
        "CREATE POLICY outbox_system_all ON search.search_event_outbox "
        "FOR ALL TO app_observability, app_admin "
        "USING (current_setting('app.actor', true) = 'SYSTEM') "
        "WITH CHECK (current_setting('app.actor', true) = 'SYSTEM')"
    )


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

    for table in _TENANT_TABLES:
        _enable_tenant_rls(table)
    _enable_outbox_rls()

    op.execute("GRANT USAGE ON SCHEMA search TO app_user, app_admin, app_observability")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA search TO app_user, app_admin")
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA search TO app_observability")


def downgrade() -> None:
    op.execute("DROP SCHEMA IF EXISTS search CASCADE")
