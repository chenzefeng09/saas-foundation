"""init data_protection schema

Revision ID: 0001_data_protection_init
Revises:
Create Date: 2026-06-03 00:00:00 UTC
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_data_protection_init"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _enable_tenant_rls(table: str) -> None:
    op.execute(f'ALTER TABLE data_protection."{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE data_protection."{table}" FORCE ROW LEVEL SECURITY')
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
            f'CREATE POLICY {policy_name} ON data_protection."{table}" '
            f"FOR {cmd} TO app_user, app_admin {clauses}"
        )
    op.execute(
        f'CREATE POLICY admin_all ON data_protection."{table}" '
        f"FOR ALL TO app_admin "
        f"USING (current_setting('app.actor', true) = 'ADMIN') "
        f"WITH CHECK (current_setting('app.actor', true) = 'ADMIN')"
    )


def _enable_outbox_rls() -> None:
    op.execute("ALTER TABLE data_protection.dp_event_outbox ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE data_protection.dp_event_outbox FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY outbox_tenant_insert ON data_protection.dp_event_outbox "
        "FOR INSERT TO app_user, app_admin "
        "WITH CHECK (tenant_id IS NULL OR tenant_id = current_setting('app.tenant_id', true))"
    )
    op.execute(
        "CREATE POLICY outbox_tenant_select ON data_protection.dp_event_outbox "
        "FOR SELECT TO app_user, app_admin "
        "USING (tenant_id = current_setting('app.tenant_id', true))"
    )
    op.execute(
        "CREATE POLICY outbox_system_all ON data_protection.dp_event_outbox "
        "FOR ALL TO app_observability, app_admin "
        "USING (current_setting('app.actor', true) = 'SYSTEM') "
        "WITH CHECK (current_setting('app.actor', true) = 'SYSTEM')"
    )


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS data_protection")

    op.create_table(
        "cross_border_transfer",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False),
        sa.Column("data_country", sa.String(10), nullable=False),
        sa.Column("destination_country", sa.String(10), nullable=False),
        sa.Column("data_type", sa.String(100), nullable=False),
        sa.Column("data_size_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("has_standard_contract", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("has_safety_assessment", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("decision", sa.String(20), nullable=False),
        sa.Column("risks", postgresql.ARRAY(sa.String())),
        sa.Column("checked_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("request_id", sa.String(64)),
        schema="data_protection",
    )
    op.create_index("cbt_tenant_idx", "cross_border_transfer", ["tenant_id"], schema="data_protection")

    op.create_table(
        "data_destruction_request",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False),
        sa.Column("resource_type", sa.String(50), nullable=False),
        sa.Column("resource_ids", postgresql.JSONB()),
        sa.Column("destruction_method", sa.String(30), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("requested_by", sa.String(30), nullable=False),
        sa.Column("witness_user_id", sa.String(30)),
        sa.Column("status", sa.String(30), nullable=False, server_default="PENDING_APPROVAL"),
        sa.Column("approved_by", sa.String(30)),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("request_id", sa.String(64)),
        schema="data_protection",
    )
    op.create_index("ddr_tenant_idx", "data_destruction_request", ["tenant_id"], schema="data_protection")

    op.create_table(
        "consent_record",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.String(30), nullable=False),
        sa.Column("consent_type", sa.String(50), nullable=False),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column("granted", sa.Boolean(), nullable=False),
        sa.Column("ip_address", sa.String(45)),
        sa.Column("recorded_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("request_id", sa.String(64)),
        schema="data_protection",
    )
    op.create_index("cr_tenant_user_idx", "consent_record", ["tenant_id", "user_id"], schema="data_protection")

    op.create_table(
        "dp_event_outbox",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(30)),
        sa.Column("event_type", sa.String(200), nullable=False),
        sa.Column("aggregate_id", sa.String(64)),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("request_id", sa.String(64)),
        sa.Column("occurred_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        schema="data_protection",
    )

    op.execute("GRANT USAGE ON SCHEMA data_protection TO app_user, app_admin, app_observability")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA data_protection TO app_user, app_admin")
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA data_protection TO app_observability")

    _enable_tenant_rls("cross_border_transfer")
    _enable_tenant_rls("data_destruction_request")
    _enable_tenant_rls("consent_record")
    _enable_outbox_rls()


def downgrade() -> None:
    op.execute("DROP SCHEMA IF EXISTS data_protection CASCADE")
