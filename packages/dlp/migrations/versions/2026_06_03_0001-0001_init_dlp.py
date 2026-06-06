"""init dlp schema

Revision ID: 0001_dlp_init
Revises:
Create Date: 2026-06-03 00:00:00 UTC
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_dlp_init"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _tenant_match() -> str:
    return "tenant_id = current_setting('app.tenant_id', true)"


def _enable_tenant_rls(table: str) -> None:
    op.execute(f'ALTER TABLE dlp."{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE dlp."{table}" FORCE ROW LEVEL SECURITY')

    tenant_match = _tenant_match()
    for cmd in ("SELECT", "INSERT", "UPDATE", "DELETE"):
        policy_name = f"tenant_{cmd.lower()}"
        if cmd == "INSERT":
            clauses = f"WITH CHECK ({tenant_match})"
        elif cmd == "UPDATE":
            clauses = f"USING ({tenant_match}) WITH CHECK ({tenant_match})"
        else:
            clauses = f"USING ({tenant_match})"
        op.execute(
            f'CREATE POLICY {policy_name} ON dlp."{table}" '
            f"FOR {cmd} TO app_user, app_admin {clauses}"
        )

    op.execute(
        f'CREATE POLICY admin_all ON dlp."{table}" '
        f"FOR ALL TO app_admin "
        f"USING (current_setting('app.actor', true) = 'ADMIN') "
        f"WITH CHECK (current_setting('app.actor', true) = 'ADMIN')"
    )


def _enable_rule_rls() -> None:
    table = "dlp_rule"
    op.execute(f'ALTER TABLE dlp."{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE dlp."{table}" FORCE ROW LEVEL SECURITY')

    tenant_or_global = f"tenant_id IS NULL OR {_tenant_match()}"
    tenant_match = _tenant_match()
    op.execute(
        f'CREATE POLICY tenant_select ON dlp."{table}" '
        f"FOR SELECT TO app_user, app_admin USING ({tenant_or_global})"
    )
    op.execute(
        f'CREATE POLICY tenant_insert ON dlp."{table}" '
        f"FOR INSERT TO app_user, app_admin WITH CHECK ({tenant_match})"
    )
    op.execute(
        f'CREATE POLICY tenant_update ON dlp."{table}" '
        f"FOR UPDATE TO app_user, app_admin "
        f"USING ({tenant_match}) WITH CHECK ({tenant_match})"
    )
    op.execute(
        f'CREATE POLICY tenant_delete ON dlp."{table}" '
        f"FOR DELETE TO app_user, app_admin USING ({tenant_match})"
    )
    op.execute(
        f'CREATE POLICY admin_all ON dlp."{table}" '
        f"FOR ALL TO app_admin "
        f"USING (current_setting('app.actor', true) = 'ADMIN') "
        f"WITH CHECK (current_setting('app.actor', true) = 'ADMIN')"
    )


def _enable_outbox_rls() -> None:
    op.execute("ALTER TABLE dlp.dlp_event_outbox ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE dlp.dlp_event_outbox FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY outbox_tenant_insert ON dlp.dlp_event_outbox "
        "FOR INSERT TO app_user, app_admin "
        "WITH CHECK (tenant_id IS NULL OR tenant_id = current_setting('app.tenant_id', true))"
    )
    op.execute(
        "CREATE POLICY outbox_tenant_select ON dlp.dlp_event_outbox "
        "FOR SELECT TO app_user, app_admin "
        "USING (tenant_id = current_setting('app.tenant_id', true))"
    )
    op.execute(
        "CREATE POLICY outbox_system_all ON dlp.dlp_event_outbox "
        "FOR ALL TO app_observability, app_admin "
        "USING (current_setting('app.actor', true) = 'SYSTEM') "
        "WITH CHECK (current_setting('app.actor', true) = 'SYSTEM')"
    )


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS dlp")

    op.create_table(
        "classification",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False),
        sa.Column("resource_type", sa.String(50), nullable=False),
        sa.Column("resource_id", sa.String(64), nullable=False),
        sa.Column("sensitivity", sa.String(2), nullable=False, server_default="L2",
                  comment="L1/L2/L3/L4/L5"),
        sa.Column("tags", postgresql.ARRAY(sa.String())),
        sa.Column("reason", sa.Text()),
        sa.Column("auto_upgraded", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("tagged_by", sa.String(30)),
        sa.Column("tagged_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("downgradable", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.UniqueConstraint("tenant_id", "resource_type", "resource_id", name="uq_classification_resource"),
        schema="dlp",
    )
    op.create_index("class_tenant_idx", "classification", ["tenant_id"], schema="dlp")
    op.create_index("class_sensitivity_idx", "classification", ["sensitivity"], schema="dlp")

    op.create_table(
        "dlp_rule",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE")),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("rule_type", sa.String(30), nullable=False,
                  comment="REGEX / KEYWORD / ML_MODEL / COMPOSITE"),
        sa.Column("pattern", sa.Text(), nullable=False),
        sa.Column("min_sensitivity", sa.String(2), nullable=False, server_default="L3"),
        sa.Column("description", sa.Text()),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("created_by", sa.String(30)),
        schema="dlp",
    )
    op.create_index("dlp_rule_tenant_idx", "dlp_rule", ["tenant_id"], schema="dlp")

    op.create_table(
        "dlp_event",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(30), nullable=False),
        sa.Column("decision", sa.String(20), nullable=False,
                  comment="ALLOW / DENY / SCAN_REQUIRED / QUARANTINE"),
        sa.Column("check_type", sa.String(30), nullable=False,
                  comment="READ / DOWNLOAD / EXPORT / SCAN_UPLOAD"),
        sa.Column("user_id", sa.String(30)),
        sa.Column("resource_type", sa.String(50)),
        sa.Column("resource_id", sa.String(64)),
        sa.Column("reason_code", sa.String(100)),
        sa.Column("detail", sa.Text()),
        sa.Column("occurred_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("request_id", sa.String(64)),
        schema="dlp",
    )
    op.create_index("dlp_event_tenant_time_idx", "dlp_event", ["tenant_id", "occurred_at"], schema="dlp")

    op.create_table(
        "dlp_event_outbox",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(30)),
        sa.Column("event_type", sa.String(200), nullable=False),
        sa.Column("aggregate_id", sa.String(64)),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("request_id", sa.String(64)),
        sa.Column("occurred_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        schema="dlp",
    )

    op.execute("GRANT USAGE ON SCHEMA dlp TO app_user, app_admin, app_observability")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA dlp TO app_user, app_admin")
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA dlp TO app_observability")

    _enable_tenant_rls("classification")
    _enable_rule_rls()
    _enable_tenant_rls("dlp_event")
    _enable_outbox_rls()


def downgrade() -> None:
    op.execute("DROP SCHEMA IF EXISTS dlp CASCADE")
