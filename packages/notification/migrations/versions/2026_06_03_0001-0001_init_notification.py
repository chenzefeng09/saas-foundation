"""init notification schema

Revision ID: 0001_notification_init
Revises:
Create Date: 2026-06-03 00:00:00 UTC
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_notification_init"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _enable_tenant_rls(table: str) -> None:
    op.execute(f'ALTER TABLE notification."{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE notification."{table}" FORCE ROW LEVEL SECURITY')
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
            f'CREATE POLICY {policy_name} ON notification."{table}" '
            f"FOR {cmd} TO app_user, app_admin {clauses}"
        )
    op.execute(
        f'CREATE POLICY admin_all ON notification."{table}" '
        f"FOR ALL TO app_admin "
        f"USING (current_setting('app.actor', true) = 'ADMIN') "
        f"WITH CHECK (current_setting('app.actor', true) = 'ADMIN')"
    )


def _enable_outbox_rls() -> None:
    op.execute("ALTER TABLE notification.notification_event_outbox ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE notification.notification_event_outbox FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY outbox_tenant_insert ON notification.notification_event_outbox "
        "FOR INSERT TO app_user, app_admin "
        "WITH CHECK (tenant_id IS NULL OR tenant_id = current_setting('app.tenant_id', true))"
    )
    op.execute(
        "CREATE POLICY outbox_tenant_select ON notification.notification_event_outbox "
        "FOR SELECT TO app_user, app_admin "
        "USING (tenant_id = current_setting('app.tenant_id', true))"
    )
    op.execute(
        "CREATE POLICY outbox_system_all ON notification.notification_event_outbox "
        "FOR ALL TO app_observability, app_admin "
        "USING (current_setting('app.actor', true) = 'SYSTEM') "
        "WITH CHECK (current_setting('app.actor', true) = 'SYSTEM')"
    )


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS notification")

    op.create_table(
        "notification_template",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_type", sa.String(200), nullable=False),
        sa.Column("locale", sa.String(10), nullable=False, server_default="zh-CN"),
        sa.Column("subject_template", sa.Text(), nullable=False),
        sa.Column("body_template", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="notification",
    )
    op.create_index("nt_tenant_event_idx", "notification_template", ["tenant_id", "event_type"], schema="notification")

    op.create_table(
        "notification_channel",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False),
        sa.Column("channel", sa.String(20), nullable=False),
        sa.Column("config", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.UniqueConstraint("tenant_id", "channel", name="uq_channel"),
        schema="notification",
    )

    op.create_table(
        "notification_subscription",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False),
        sa.Column("subscriber_kind", sa.String(20), nullable=False),
        sa.Column("subscriber_id", sa.String(64), nullable=False),
        sa.Column("event_types", postgresql.ARRAY(sa.String())),
        sa.Column("channel", sa.String(20), nullable=False, server_default="EMAIL"),
        sa.Column("config", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        schema="notification",
    )
    op.create_index("nsub_tenant_idx", "notification_subscription", ["tenant_id"], schema="notification")

    op.create_table(
        "notification_log",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), nullable=False),
        sa.Column("event_type", sa.String(200), nullable=False),
        sa.Column("recipient", sa.String(200), nullable=False),
        sa.Column("channel", sa.String(20), nullable=False),
        sa.Column("subject", sa.String(500), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("detail", sa.Text()),
        sa.Column("sent_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("request_id", sa.String(64)),
        schema="notification",
    )
    op.create_index("nlog_tenant_time_idx", "notification_log", ["tenant_id", "sent_at"], schema="notification")

    op.create_table(
        "notification_event_outbox",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(30)),
        sa.Column("event_type", sa.String(200), nullable=False),
        sa.Column("aggregate_id", sa.String(64)),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("request_id", sa.String(64)),
        sa.Column("occurred_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        schema="notification",
    )

    op.execute("GRANT USAGE ON SCHEMA notification TO app_user, app_admin, app_observability")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA notification TO app_user, app_admin")
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA notification TO app_observability")

    _enable_tenant_rls("notification_template")
    _enable_tenant_rls("notification_channel")
    _enable_tenant_rls("notification_subscription")
    _enable_tenant_rls("notification_log")
    _enable_outbox_rls()


def downgrade() -> None:
    op.execute("DROP SCHEMA IF EXISTS notification CASCADE")
