"""init api_platform schema

Revision ID: 0001_api_platform_init
Revises:
Create Date: 2026-06-03 00:00:00 UTC
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_api_platform_init"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TENANT_TABLES = ("api_key", "oauth_app", "webhook_subscription")


def _enable_tenant_rls(table: str) -> None:
    op.execute(f'ALTER TABLE api_platform."{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE api_platform."{table}" FORCE ROW LEVEL SECURITY')
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
            f'CREATE POLICY {policy_name} ON api_platform."{table}" '
            f"FOR {cmd} TO app_user, app_admin {clauses}"
        )
    op.execute(
        f'CREATE POLICY admin_all ON api_platform."{table}" '
        f"FOR ALL TO app_admin "
        f"USING (current_setting('app.actor', true) = 'ADMIN') "
        f"WITH CHECK (current_setting('app.actor', true) = 'ADMIN')"
    )


def _enable_outbox_rls() -> None:
    op.execute("ALTER TABLE api_platform.api_platform_event_outbox ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE api_platform.api_platform_event_outbox FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY outbox_tenant_insert ON api_platform.api_platform_event_outbox "
        "FOR INSERT TO app_user, app_admin "
        "WITH CHECK ("
        "  tenant_id IS NULL OR tenant_id = current_setting('app.tenant_id', true)"
        ")"
    )
    op.execute(
        "CREATE POLICY outbox_tenant_select ON api_platform.api_platform_event_outbox "
        "FOR SELECT TO app_user, app_admin "
        "USING (tenant_id = current_setting('app.tenant_id', true))"
    )
    op.execute(
        "CREATE POLICY outbox_system_all ON api_platform.api_platform_event_outbox "
        "FOR ALL TO app_observability, app_admin "
        "USING (current_setting('app.actor', true) = 'SYSTEM') "
        "WITH CHECK (current_setting('app.actor', true) = 'SYSTEM')"
    )


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS api_platform")

    op.create_table(
        "api_key",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False),
        sa.Column("scopes", postgresql.ARRAY(sa.String())),
        sa.Column("ip_whitelist", postgresql.ARRAY(sa.String())),
        sa.Column("rate_limit_rpm", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("created_by", sa.String(30), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="api_platform",
    )
    op.create_index("apk_tenant_idx", "api_key", ["tenant_id"], schema="api_platform")

    op.create_table(
        "oauth_app",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("client_id", sa.String(100), nullable=False),
        sa.Column("client_secret_hash", sa.String(64), nullable=False),
        sa.Column("redirect_uris", postgresql.ARRAY(sa.String())),
        sa.Column("scopes", postgresql.ARRAY(sa.String())),
        sa.Column("created_by", sa.String(30), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="api_platform",
    )

    op.create_table(
        "webhook_subscription",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False),
        sa.Column("url", sa.String(500), nullable=False),
        sa.Column("event_types", postgresql.ARRAY(sa.String())),
        sa.Column("secret", sa.String(200), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="api_platform",
    )
    op.create_index("whs_tenant_idx", "webhook_subscription", ["tenant_id"], schema="api_platform")

    op.create_table(
        "webhook_delivery",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("subscription_id", sa.String(30), nullable=False),
        sa.Column("event_type", sa.String(200), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("response_status", sa.Integer()),
        sa.Column("response_body", sa.Text()),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="api_platform",
    )

    op.create_table(
        "api_platform_event_outbox",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(30)),
        sa.Column("event_type", sa.String(200), nullable=False),
        sa.Column("aggregate_id", sa.String(64)),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("request_id", sa.String(64)),
        sa.Column("occurred_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="api_platform",
    )

    for table in _TENANT_TABLES:
        _enable_tenant_rls(table)
    _enable_outbox_rls()

    op.execute("GRANT USAGE ON SCHEMA api_platform TO app_user, app_admin, app_observability")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA api_platform TO app_user, app_admin")
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA api_platform TO app_observability")


def downgrade() -> None:
    op.execute("DROP SCHEMA IF EXISTS api_platform CASCADE")
