"""orphan_reconcile_report + admin_all on tenant_storage_quota (Phase 7)

Revision ID: 0003_add_orphan_reconcile_report
Revises: 0002_add_tenant_storage_quota
Create Date: 2026-06-12 10:00:00 UTC

Two changes:

1. New table ``lifecycle.orphan_reconcile_report`` — one row per
   orphan-reconcile sweep (run_at, duration, dry_run, grace_period,
   3 counters from OrphanReconcileReport).  Cross-tenant, no RLS —
   same pattern as ``destruction_job``.  Reports are append-only via
   the scheduler.

2. Add ``admin_all`` RLS policy to ``lifecycle.tenant_storage_quota``
   so platform-admin endpoints opened through admin_session_scope
   (Phase 7) can read/write rows across tenants.  Existing tenant
   policies are kept; the admin policy activates only when
   ``current_setting('app.actor') = 'ADMIN'`` — the SET LOCAL guard
   inside admin_session_scope.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_add_orphan_reconcile_report"
down_revision: str | None = "0002_add_tenant_storage_quota"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ---- orphan_reconcile_report table (cross-tenant; no RLS) ----------
    op.create_table(
        "orphan_reconcile_report",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("duration_ms", sa.BigInteger(), nullable=False),
        sa.Column("dry_run", sa.Boolean(), nullable=False),
        sa.Column("grace_period_days", sa.Integer(), nullable=False),
        sa.Column(
            "direction_a_orphans",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "direction_a_deleted",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "direction_b_missing",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        schema="lifecycle",
    )
    op.create_index(
        "idx_orphan_report_started_at",
        "orphan_reconcile_report",
        [sa.text("started_at DESC")],
        schema="lifecycle",
    )

    # Grants — same shape as the rest of the lifecycle schema.
    op.execute(
        "GRANT SELECT, INSERT "
        "ON lifecycle.orphan_reconcile_report TO app_user, app_admin"
    )
    op.execute(
        "GRANT SELECT "
        "ON lifecycle.orphan_reconcile_report TO app_observability"
    )

    # ---- admin_all RLS policy on tenant_storage_quota -------------------
    # Lifecycle 0001/0002 only created tenant_* policies (USING tenant_id =
    # current_setting('app.tenant_id')) — admin_session_scope leaves
    # app.tenant_id blank, so the existing policies match nothing.  Add an
    # ADMIN-actor policy that activates exclusively under app_admin
    # transactions opened via admin_session_scope.
    op.execute(
        'CREATE POLICY admin_all ON lifecycle."tenant_storage_quota" '
        "FOR ALL TO app_admin "
        "USING (current_setting('app.actor', true) = 'ADMIN') "
        "WITH CHECK (current_setting('app.actor', true) = 'ADMIN')"
    )


def downgrade() -> None:
    op.execute(
        "DROP POLICY IF EXISTS admin_all ON lifecycle.tenant_storage_quota"
    )
    op.drop_index(
        "idx_orphan_report_started_at",
        table_name="orphan_reconcile_report",
        schema="lifecycle",
    )
    op.drop_table("orphan_reconcile_report", schema="lifecycle")
