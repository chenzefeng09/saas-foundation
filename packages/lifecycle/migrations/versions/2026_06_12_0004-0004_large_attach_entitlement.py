"""large-attachment entitlement (two-layer admission)

Revision ID: 0004_large_attach_entitlement
Revises: 0003_add_orphan_reconcile_report
Create Date: 2026-06-12 12:00:00 UTC

Two tables implementing a BOOLEAN admission model (not a byte quota) that
gates whether a user may upload large attachments (which trigger the
large-memory sandbox tier):

* ``tenant_large_attachment_setting`` — one row per tenant; a tenant-wide
  switch controlling whether ANY user in the tenant may use large
  attachments at all.
* ``user_large_attachment_allow`` — per-user allowlist; which specific users
  are permitted once the tenant switch is on.

Resolution (see LargeAttachmentService.resolve): a user is allowed IFF the
tenant switch is on AND a user allow-row exists with allowed == true.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_large_attach_entitlement"
down_revision: str | None = "0003_add_orphan_reconcile_report"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ── tenant_large_attachment_setting ──────────────────────────────────────
    op.create_table(
        "tenant_large_attachment_setting",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(30),
            sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "large_attachment_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("updated_by", sa.Text(), nullable=True),
        sa.UniqueConstraint(
            "tenant_id", name="uq_large_attach_setting_tenant"
        ),
        schema="lifecycle",
    )
    op.create_index(
        "idx_large_attach_setting_tenant",
        "tenant_large_attachment_setting",
        ["tenant_id"],
        schema="lifecycle",
    )

    # ── user_large_attachment_allow ──────────────────────────────────────────
    op.create_table(
        "user_large_attachment_allow",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(30),
            sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("user_id", sa.String(30), nullable=False),
        sa.Column(
            "allowed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("updated_by", sa.Text(), nullable=True),
        sa.UniqueConstraint(
            "tenant_id", "user_id", name="uq_large_attach_allow_tenant_user"
        ),
        schema="lifecycle",
    )
    op.create_index(
        "idx_large_attach_allow_tenant",
        "user_large_attachment_allow",
        ["tenant_id"],
        schema="lifecycle",
    )

    # RLS — same pattern as 0001_lifecycle_init / 0002 for tenant-scoped tables.
    # Multi-statement DDL is split into separate execute() calls on purpose.
    tm = "tenant_id = current_setting('app.tenant_id', true)"
    for tbl in (
        "tenant_large_attachment_setting",
        "user_large_attachment_allow",
    ):
        op.execute(f'ALTER TABLE lifecycle."{tbl}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE lifecycle."{tbl}" FORCE ROW LEVEL SECURITY')
        for cmd, clause in [
            ("SELECT", f"USING ({tm})"),
            ("INSERT", f"WITH CHECK ({tm})"),
            ("UPDATE", f"USING ({tm}) WITH CHECK ({tm})"),
            ("DELETE", f"USING ({tm})"),
        ]:
            op.execute(
                f'CREATE POLICY tenant_{cmd.lower()} ON lifecycle."{tbl}" '
                f"FOR {cmd} TO app_user, app_admin {clause}"
            )

        # Grants for the new table (the app role is not the migration role).
        op.execute(
            "GRANT SELECT, INSERT, UPDATE, DELETE "
            f"ON lifecycle.{tbl} TO app_user, app_admin"
        )
        op.execute(f"GRANT SELECT ON lifecycle.{tbl} TO app_observability")


def downgrade() -> None:
    for tbl in (
        "user_large_attachment_allow",
        "tenant_large_attachment_setting",
    ):
        for cmd in ("select", "insert", "update", "delete"):
            op.execute(
                f'DROP POLICY IF EXISTS tenant_{cmd} ON lifecycle."{tbl}"'
            )
    op.drop_index(
        "idx_large_attach_allow_tenant",
        table_name="user_large_attachment_allow",
        schema="lifecycle",
    )
    op.drop_table("user_large_attachment_allow", schema="lifecycle")
    op.drop_index(
        "idx_large_attach_setting_tenant",
        table_name="tenant_large_attachment_setting",
        schema="lifecycle",
    )
    op.drop_table("tenant_large_attachment_setting", schema="lifecycle")
