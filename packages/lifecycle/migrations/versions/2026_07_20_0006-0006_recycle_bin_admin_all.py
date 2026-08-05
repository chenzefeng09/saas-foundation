"""admin_all RLS policy on recycle_bin

Revision ID: 0006_recycle_bin_admin_all
Revises: 0005_large_attach_subject_allow
Create Date: 2026-07-20 12:00:00 UTC

Migration 0003 added the ``admin_all`` policy to
``lifecycle.tenant_storage_quota`` so admin_session_scope transactions
(app_admin + SET LOCAL app.actor='ADMIN', NOBYPASSRLS) can read/write
across tenants — but ``lifecycle.recycle_bin`` was missed.  The table is
FORCE ROW LEVEL SECURITY with only tenant_* policies keyed on
``current_setting('app.tenant_id')``, which admin_session_scope leaves
blank, so the orphan-reconcile job's cross-tenant SELECT over
recycle_bin always returned 0 rows.

Add the same ``admin_all`` policy (USING + WITH CHECK on
``current_setting('app.actor', true) = 'ADMIN'``) to
``lifecycle.recycle_bin``.  Existing tenant policies are kept.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0006_recycle_bin_admin_all"
down_revision: str | None = "0005_large_attach_subject_allow"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ---- admin_all RLS policy on recycle_bin ----------------------------
    # Same pattern as 0003's admin_all on tenant_storage_quota: activates
    # exclusively under app_admin transactions opened via
    # admin_session_scope (SET LOCAL app.actor='ADMIN').
    op.execute(
        'CREATE POLICY admin_all ON lifecycle."recycle_bin" '
        "FOR ALL TO app_admin "
        "USING (current_setting('app.actor', true) = 'ADMIN') "
        "WITH CHECK (current_setting('app.actor', true) = 'ADMIN')"
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS admin_all ON lifecycle.recycle_bin")
