"""tenant storage quota (Phase 3)

Revision ID: 0002_add_tenant_storage_quota
Revises: 0001_lifecycle_init
Create Date: 2026-06-12 09:00:00 UTC

Table: tenant_storage_quota — per-tenant, per-bucket-purpose storage
allowance and consumed bytes. Enforced by foundation_storage at upload
time; reconciled daily by lifecycle's APScheduler job.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_add_tenant_storage_quota"
down_revision: str | None = "0001_lifecycle_init"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "tenant_storage_quota",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(30),
            sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("bucket_purpose", sa.String(32), nullable=False),
        sa.Column(
            "limit_bytes",
            sa.BigInteger(),
            nullable=False,
            server_default="10737418240",  # 10 GiB
        ),
        sa.Column(
            "used_bytes",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "soft_warn_pct",
            sa.SmallInteger(),
            nullable=False,
            server_default="80",
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "tenant_id", "bucket_purpose", name="uq_storage_quota_tenant_purpose"
        ),
        schema="lifecycle",
    )
    op.create_index(
        "idx_storage_quota_tenant",
        "tenant_storage_quota",
        ["tenant_id"],
        schema="lifecycle",
    )

    # RLS — same pattern as 0001_lifecycle_init for tenant-scoped tables.
    op.execute('ALTER TABLE lifecycle."tenant_storage_quota" ENABLE ROW LEVEL SECURITY')
    op.execute('ALTER TABLE lifecycle."tenant_storage_quota" FORCE ROW LEVEL SECURITY')
    tm = "tenant_id = current_setting('app.tenant_id', true)"
    for cmd, clause in [
        ("SELECT", f"USING ({tm})"),
        ("INSERT", f"WITH CHECK ({tm})"),
        ("UPDATE", f"USING ({tm}) WITH CHECK ({tm})"),
        ("DELETE", f"USING ({tm})"),
    ]:
        op.execute(
            f'CREATE POLICY tenant_{cmd.lower()} ON lifecycle."tenant_storage_quota" '
            f"FOR {cmd} TO app_user, app_admin {clause}"
        )

    # Grants for the new table (inherits the schema-level grants too, but be
    # explicit for clarity).
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE "
        "ON lifecycle.tenant_storage_quota TO app_user, app_admin"
    )
    op.execute(
        "GRANT SELECT ON lifecycle.tenant_storage_quota TO app_observability"
    )


def downgrade() -> None:
    op.execute(
        'DROP POLICY IF EXISTS tenant_select ON lifecycle."tenant_storage_quota"'
    )
    op.execute(
        'DROP POLICY IF EXISTS tenant_insert ON lifecycle."tenant_storage_quota"'
    )
    op.execute(
        'DROP POLICY IF EXISTS tenant_update ON lifecycle."tenant_storage_quota"'
    )
    op.execute(
        'DROP POLICY IF EXISTS tenant_delete ON lifecycle."tenant_storage_quota"'
    )
    op.drop_index(
        "idx_storage_quota_tenant",
        table_name="tenant_storage_quota",
        schema="lifecycle",
    )
    op.drop_table("tenant_storage_quota", schema="lifecycle")
