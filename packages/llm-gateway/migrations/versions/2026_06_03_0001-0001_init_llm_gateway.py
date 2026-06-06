"""init llm_gateway schema

Revision ID: 0001_llm_gateway_init
Revises:
Create Date: 2026-06-03 00:00:00 UTC
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_llm_gateway_init"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TENANT_TABLES = ("llm_provider", "llm_tenant_key", "llm_usage_record")


def _enable_tenant_rls(table: str) -> None:
    op.execute(f'ALTER TABLE llm_gateway."{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE llm_gateway."{table}" FORCE ROW LEVEL SECURITY')
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
            f'CREATE POLICY {policy_name} ON llm_gateway."{table}" '
            f"FOR {cmd} TO app_user, app_admin {clauses}"
        )
    op.execute(
        f'CREATE POLICY admin_all ON llm_gateway."{table}" '
        f"FOR ALL TO app_admin "
        f"USING (current_setting('app.actor', true) = 'ADMIN') "
        f"WITH CHECK (current_setting('app.actor', true) = 'ADMIN')"
    )


def _enable_outbox_rls() -> None:
    op.execute("ALTER TABLE llm_gateway.llm_gateway_event_outbox ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE llm_gateway.llm_gateway_event_outbox FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY outbox_tenant_insert ON llm_gateway.llm_gateway_event_outbox "
        "FOR INSERT TO app_user, app_admin "
        "WITH CHECK ("
        "  tenant_id IS NULL OR tenant_id = current_setting('app.tenant_id', true)"
        ")"
    )
    op.execute(
        "CREATE POLICY outbox_tenant_select ON llm_gateway.llm_gateway_event_outbox "
        "FOR SELECT TO app_user, app_admin "
        "USING (tenant_id = current_setting('app.tenant_id', true))"
    )
    op.execute(
        "CREATE POLICY outbox_system_all ON llm_gateway.llm_gateway_event_outbox "
        "FOR ALL TO app_observability, app_admin "
        "USING (current_setting('app.actor', true) = 'SYSTEM') "
        "WITH CHECK (current_setting('app.actor', true) = 'SYSTEM')"
    )


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS llm_gateway")

    op.create_table(
        "llm_provider",
        sa.Column("id", sa.String(40), primary_key=True),
        sa.Column("tenant_id", sa.String(30), sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("base_url", sa.String(500), nullable=False),
        sa.Column("api_key_encrypted", sa.Text(), nullable=False),
        sa.Column("models", postgresql.ARRAY(sa.String())),
        sa.Column("default_model", sa.String(100), nullable=False),
        sa.Column("capabilities", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="llm_gateway",
    )
    op.create_index("llmp_tenant_idx", "llm_provider", ["tenant_id"], schema="llm_gateway")

    op.create_table(
        "llm_tenant_key",
        sa.Column("id", sa.String(40), primary_key=True),
        sa.Column("tenant_id", sa.String(30), sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provider_id", sa.String(40), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("virtual_key", sa.String(200), nullable=False),
        sa.Column("rate_limit_rpm", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="llm_gateway",
    )
    op.create_index("llmk_tenant_idx", "llm_tenant_key", ["tenant_id"], schema="llm_gateway")

    op.create_table(
        "llm_usage_record",
        sa.Column("id", sa.String(40), primary_key=True),
        sa.Column("tenant_id", sa.String(30), nullable=False),
        sa.Column("provider_id", sa.String(40), nullable=False),
        sa.Column("model", sa.String(100), nullable=False),
        sa.Column("prompt_tokens", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("completion_tokens", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("total_tokens", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("cost_usd", sa.Float(), nullable=False, server_default="0"),
        sa.Column("latency_ms", sa.Float(), nullable=False, server_default="0"),
        sa.Column("request_id", sa.String(64)),
        sa.Column("recorded_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="llm_gateway",
    )
    op.create_index("llmu_tenant_time_idx", "llm_usage_record", ["tenant_id", "recorded_at"], schema="llm_gateway")

    op.create_table(
        "llm_gateway_event_outbox",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(30)),
        sa.Column("event_type", sa.String(200), nullable=False),
        sa.Column("aggregate_id", sa.String(64)),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("request_id", sa.String(64)),
        sa.Column("occurred_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="llm_gateway",
    )

    for table in _TENANT_TABLES:
        _enable_tenant_rls(table)
    _enable_outbox_rls()

    op.execute("GRANT USAGE ON SCHEMA llm_gateway TO app_user, app_admin, app_observability")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA llm_gateway TO app_user, app_admin")
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA llm_gateway TO app_observability")


def downgrade() -> None:
    op.execute("DROP SCHEMA IF EXISTS llm_gateway CASCADE")
