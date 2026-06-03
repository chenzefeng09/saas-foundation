"""init billing schema

Revision ID: 0001_billing_init
Revises:
Create Date: 2026-06-03 00:00:00 UTC
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_billing_init"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS billing")

    op.create_table(
        "subscription_plan",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("tier", sa.String(20), nullable=False),
        sa.Column("quotas", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("price_monthly_usd", sa.Float(), nullable=False, server_default="0"),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        schema="billing",
    )

    op.create_table(
        "tenant_subscription",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False),
        sa.Column("plan_id", sa.String(30), nullable=False),
        sa.Column("mode", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="ACTIVE"),
        sa.Column("current_period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("current_period_end", sa.DateTime(timezone=True), nullable=False),
        schema="billing",
    )
    op.create_index("ts_tenant_idx", "tenant_subscription", ["tenant_id"], schema="billing")

    op.create_table(
        "quota_usage",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False),
        sa.Column("dimension", sa.String(30), nullable=False),
        sa.Column("current_value", sa.Float(), nullable=False, server_default="0"),
        sa.Column("last_updated", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="billing",
    )
    op.create_index("qu_tenant_dim_idx", "quota_usage", ["tenant_id", "dimension"], schema="billing")

    op.create_table(
        "invoice",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False),
        sa.Column("invoice_number", sa.String(100), nullable=False),
        sa.Column("items", postgresql.JSONB()),
        sa.Column("total_amount", sa.Float(), nullable=False),
        sa.Column("currency", sa.String(10), nullable=False, server_default="CNY"),
        sa.Column("status", sa.String(20), nullable=False, server_default="DRAFT"),
        sa.Column("due_date", sa.Date(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="billing",
    )
    op.create_index("inv_tenant_idx", "invoice", ["tenant_id"], schema="billing")

    op.create_table(
        "billing_event_outbox",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(30)),
        sa.Column("event_type", sa.String(200), nullable=False),
        sa.Column("aggregate_id", sa.String(64)),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("request_id", sa.String(64)),
        sa.Column("occurred_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="billing",
    )

    op.execute("GRANT USAGE ON SCHEMA billing TO app_user, app_admin, app_observability")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA billing TO app_user, app_admin")
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA billing TO app_observability")


def downgrade() -> None:
    op.execute("DROP SCHEMA IF EXISTS billing CASCADE")
