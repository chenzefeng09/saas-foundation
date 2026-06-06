"""init compliance schema

Revision ID: 0001_compliance_init
Revises:
Create Date: 2026-06-03 00:00:00 UTC
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_compliance_init"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _enable_tenant_rls(table: str) -> None:
    op.execute(f'ALTER TABLE compliance."{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE compliance."{table}" FORCE ROW LEVEL SECURITY')
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
            f'CREATE POLICY {policy_name} ON compliance."{table}" '
            f"FOR {cmd} TO app_user, app_admin {clauses}"
        )
    op.execute(
        f'CREATE POLICY admin_all ON compliance."{table}" '
        f"FOR ALL TO app_admin "
        f"USING (current_setting('app.actor', true) = 'ADMIN') "
        f"WITH CHECK (current_setting('app.actor', true) = 'ADMIN')"
    )


def _enable_outbox_rls() -> None:
    op.execute("ALTER TABLE compliance.compliance_event_outbox ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE compliance.compliance_event_outbox FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY outbox_tenant_insert ON compliance.compliance_event_outbox "
        "FOR INSERT TO app_user, app_admin "
        "WITH CHECK (tenant_id IS NULL OR tenant_id = current_setting('app.tenant_id', true))"
    )
    op.execute(
        "CREATE POLICY outbox_tenant_select ON compliance.compliance_event_outbox "
        "FOR SELECT TO app_user, app_admin "
        "USING (tenant_id = current_setting('app.tenant_id', true))"
    )
    op.execute(
        "CREATE POLICY outbox_system_all ON compliance.compliance_event_outbox "
        "FOR ALL TO app_observability, app_admin "
        "USING (current_setting('app.actor', true) = 'SYSTEM') "
        "WITH CHECK (current_setting('app.actor', true) = 'SYSTEM')"
    )


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS compliance")

    op.create_table(
        "ropa_record",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False),
        sa.Column("service", sa.String(50), nullable=False),
        sa.Column("data_category", sa.String(100), nullable=False),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column("legal_basis", sa.String(100), nullable=False),
        sa.Column("data_subjects", postgresql.ARRAY(sa.String())),
        sa.Column("recipients", postgresql.ARRAY(sa.String())),
        sa.Column("retention_days", sa.Integer(), nullable=False, server_default="365"),
        sa.Column("cross_border", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("destination_countries", postgresql.ARRAY(sa.String())),
        sa.Column("recorded_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="compliance",
    )
    op.create_index("ropa_tenant_idx", "ropa_record", ["tenant_id"], schema="compliance")

    op.create_table(
        "dpia",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False),
        sa.Column("project_name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("data_categories", postgresql.ARRAY(sa.String())),
        sa.Column("risks", postgresql.JSONB()),
        sa.Column("mitigations", postgresql.JSONB()),
        sa.Column("conclusion", sa.String(50), nullable=False),
        sa.Column("residual_risks", sa.Text()),
        sa.Column("assessed_by", sa.String(30), nullable=False),
        sa.Column("approved_by", sa.String(30)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        schema="compliance",
    )

    op.create_table(
        "dsar_request",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.String(30), nullable=False),
        sa.Column("request_type", sa.String(30), nullable=False),
        sa.Column("details", sa.Text(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="RECEIVED"),
        sa.Column("sla_deadline", sa.DateTime(timezone=True), nullable=False),
        sa.Column("response", sa.Text()),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="compliance",
    )
    op.create_index("dsar_tenant_user_idx", "dsar_request", ["tenant_id", "user_id"], schema="compliance")

    op.create_table(
        "compliance_report",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False),
        sa.Column("report_type", sa.String(50), nullable=False),
        sa.Column("compliance_modes", postgresql.ARRAY(sa.String())),
        sa.Column("content", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("generated_by", sa.String(30), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="compliance",
    )

    op.create_table(
        "compliance_event_outbox",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(30)),
        sa.Column("event_type", sa.String(200), nullable=False),
        sa.Column("aggregate_id", sa.String(64)),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("request_id", sa.String(64)),
        sa.Column("occurred_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="compliance",
    )

    op.execute("GRANT USAGE ON SCHEMA compliance TO app_user, app_admin, app_observability")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA compliance TO app_user, app_admin")
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA compliance TO app_observability")

    _enable_tenant_rls("ropa_record")
    _enable_tenant_rls("dpia")
    _enable_tenant_rls("dsar_request")
    _enable_tenant_rls("compliance_report")
    _enable_outbox_rls()


def downgrade() -> None:
    op.execute("DROP SCHEMA IF EXISTS compliance CASCADE")
