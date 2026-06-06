"""init pam schema

Revision ID: 0001_pam_init
Revises:
Create Date: 2026-06-03 00:00:00 UTC
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_pam_init"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _enable_tenant_rls(table: str) -> None:
    op.execute(f'ALTER TABLE pam."{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE pam."{table}" FORCE ROW LEVEL SECURITY')
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
            f'CREATE POLICY {policy_name} ON pam."{table}" '
            f"FOR {cmd} TO app_user, app_admin {clauses}"
        )
    op.execute(
        f'CREATE POLICY admin_all ON pam."{table}" '
        f"FOR ALL TO app_admin "
        f"USING (current_setting('app.actor', true) = 'ADMIN') "
        f"WITH CHECK (current_setting('app.actor', true) = 'ADMIN')"
    )


def _enable_outbox_rls() -> None:
    op.execute("ALTER TABLE pam.pam_event_outbox ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE pam.pam_event_outbox FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY outbox_tenant_insert ON pam.pam_event_outbox "
        "FOR INSERT TO app_user, app_admin "
        "WITH CHECK (tenant_id IS NULL OR tenant_id = current_setting('app.tenant_id', true))"
    )
    op.execute(
        "CREATE POLICY outbox_tenant_select ON pam.pam_event_outbox "
        "FOR SELECT TO app_user, app_admin "
        "USING (tenant_id = current_setting('app.tenant_id', true))"
    )
    op.execute(
        "CREATE POLICY outbox_system_all ON pam.pam_event_outbox "
        "FOR ALL TO app_observability, app_admin "
        "USING (current_setting('app.actor', true) = 'SYSTEM') "
        "WITH CHECK (current_setting('app.actor', true) = 'SYSTEM')"
    )


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS pam")

    op.create_table(
        "pam_elevation_request",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.String(30), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("target_permissions", postgresql.ARRAY(sa.String())),
        sa.Column("duration_minutes", sa.Integer(), nullable=False),
        sa.Column("ticket_reference", sa.String(200)),
        sa.Column("status", sa.String(20), nullable=False, server_default="PENDING"),
        sa.Column("requested_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_by", sa.String(30)),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
        sa.Column("approval_reason", sa.Text()),
        schema="pam",
    )
    op.create_index("pam_req_tenant_idx", "pam_elevation_request", ["tenant_id"], schema="pam")

    op.create_table(
        "pam_session",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False),
        sa.Column("elevation_request_id", sa.String(30), nullable=False),
        sa.Column("user_id", sa.String(30), nullable=False),
        sa.Column("approved_by", sa.String(30), nullable=False),
        sa.Column("permissions", postgresql.ARRAY(sa.String())),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_by", sa.String(30)),
        sa.Column("revocation_reason", sa.Text()),
        schema="pam",
    )
    op.create_index("pam_sess_active_idx", "pam_session", ["tenant_id", "is_active"], schema="pam")

    op.create_table(
        "pam_event_outbox",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(30)),
        sa.Column("event_type", sa.String(200), nullable=False),
        sa.Column("aggregate_id", sa.String(64)),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("request_id", sa.String(64)),
        sa.Column("occurred_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="pam",
    )

    op.execute("GRANT USAGE ON SCHEMA pam TO app_user, app_admin, app_observability")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA pam TO app_user, app_admin")
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA pam TO app_observability")

    _enable_tenant_rls("pam_elevation_request")
    _enable_tenant_rls("pam_session")
    _enable_outbox_rls()


def downgrade() -> None:
    op.execute("DROP SCHEMA IF EXISTS pam CASCADE")
