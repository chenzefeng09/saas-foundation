"""audit init schema

Revision ID: 0001_audit_init
Revises:
Create Date: 2026-05-26 18:00:00 UTC

Tables:
  - audit.outbox (transactional event buffer before ClickHouse ingestion)
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_audit_init"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS audit")

    op.create_table(
        "outbox",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(30), nullable=False),
        sa.Column("event_json", sa.dialects.postgresql.JSONB(), nullable=False),
        sa.Column("enqueued_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text()),
        schema="audit",
    )
    op.create_index("ix_audit_outbox_pending", "outbox", ["id"], schema="audit",
                    postgresql_where="delivered_at IS NULL")

    # RLS
    op.execute('ALTER TABLE audit."outbox" ENABLE ROW LEVEL SECURITY')
    op.execute('ALTER TABLE audit."outbox" FORCE ROW LEVEL SECURITY')
    tenant_match = "tenant_id = current_setting('app.tenant_id', true)"
    for cmd, clause in [("SELECT", f"USING ({tenant_match})"),
                         ("INSERT", f"WITH CHECK ({tenant_match})"),
                         ("UPDATE", f"USING ({tenant_match}) WITH CHECK ({tenant_match})"),
                         ("DELETE", f"USING ({tenant_match})")]:
        op.execute(f'CREATE POLICY tenant_{cmd.lower()} ON audit."outbox" FOR {cmd} TO app_user, app_admin {clause}')

    # audit-worker connects as app_user but uses system_session_scope (app.actor='SYSTEM')
    # to drain the outbox cross-tenant. This policy enables that cross-tenant access.
    op.execute(
        "CREATE POLICY system_all ON audit.\"outbox\" "
        "FOR ALL TO app_user, app_admin "
        "USING (current_setting('app.actor', true) = 'SYSTEM') "
        "WITH CHECK (current_setting('app.actor', true) = 'SYSTEM')"
    )

    # Grants
    op.execute("GRANT USAGE ON SCHEMA audit TO app_user, app_admin, app_observability")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA audit TO app_user, app_admin")
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA audit TO app_observability")


def downgrade() -> None:
    op.execute("DROP SCHEMA IF EXISTS audit CASCADE")
