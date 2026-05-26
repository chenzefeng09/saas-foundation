"""lifecycle init schema

Revision ID: 0001_lifecycle_init
Revises:
Create Date: 2026-05-26 19:00:00 UTC

Tables: resource_type, retention_policy_override, recycle_bin, legal_hold,
        destruction_certificate, destruction_job, lifecycle_event_outbox
"""

from __future__ import annotations
from collections.abc import Sequence
import sqlalchemy as sa
from alembic import op

revision: str = "0001_lifecycle_init"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS lifecycle")

    # resource_type
    op.create_table("resource_type",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("service", sa.String(50), nullable=False),
        sa.Column("kind", sa.String(50), nullable=False),
        sa.Column("display_name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("retention_days_default", sa.Integer(), nullable=False, server_default="365"),
        sa.Column("retention_anchor", sa.String(20), nullable=False, server_default="created_at"),
        sa.Column("recycle_bin_days", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("destruction_method", sa.String(30), nullable=False, server_default="truncate"),
        sa.Column("requires_destruction_certificate", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_system", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("created_by", sa.String(30)),
        schema="lifecycle")

    # retention_policy_override
    op.create_table("retention_policy_override",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False),
        sa.Column("resource_type_id", sa.String(30), sa.ForeignKey("lifecycle.resource_type.id"), nullable=False),
        sa.Column("retention_days", sa.Integer()),
        sa.Column("recycle_bin_days", sa.Integer()),
        sa.Column("locked_by_compliance", sa.String(50)),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("updated_by", sa.String(30)),
        sa.UniqueConstraint("tenant_id", "resource_type_id", name="uq_retention_override"),
        schema="lifecycle")

    # recycle_bin
    op.create_table("recycle_bin",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False),
        sa.Column("resource_type_id", sa.String(30), sa.ForeignKey("lifecycle.resource_type.id"), nullable=False),
        sa.Column("resource_id", sa.String(64), nullable=False),
        sa.Column("resource_name", sa.String(500)),
        sa.Column("deleted_by", sa.String(30), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("restored_at", sa.DateTime(timezone=True)),
        sa.Column("restored_by", sa.String(30)),
        sa.Column("hard_deleted_at", sa.DateTime(timezone=True)),
        sa.Column("original_location", sa.Text()),
        schema="lifecycle")
    op.create_index("rb_tenant_type_idx", "recycle_bin", ["tenant_id", "resource_type_id"], schema="lifecycle")
    op.execute("CREATE INDEX rb_expires_idx ON lifecycle.recycle_bin (expires_at) WHERE restored_at IS NULL AND hard_deleted_at IS NULL")

    # legal_hold
    op.create_table("legal_hold",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False),
        sa.Column("resource_type_id", sa.String(30), nullable=False),
        sa.Column("resource_id", sa.String(64), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("placed_by", sa.String(30), nullable=False),
        sa.Column("placed_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("released_at", sa.DateTime(timezone=True)),
        sa.Column("released_by", sa.String(30)),
        sa.Column("case_reference", sa.String(200)),
        schema="lifecycle")
    op.create_index("lh_tenant_resource_idx", "legal_hold", ["tenant_id", "resource_type_id", "resource_id"], schema="lifecycle")

    # destruction_certificate
    op.create_table("destruction_certificate",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"), nullable=False),
        sa.Column("resource_type_id", sa.String(30), nullable=False),
        sa.Column("resource_ids", sa.dialects.postgresql.JSONB()),
        sa.Column("destruction_method", sa.String(30), nullable=False),
        sa.Column("destroyed_by", sa.String(30), nullable=False),
        sa.Column("witness_user_id", sa.String(30)),
        sa.Column("destroyed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("certificate_hash", sa.String(64), nullable=False),
        sa.Column("certificate_pdf_uri", sa.String(500)),
        sa.Column("audit_event_id", sa.String(30)),
        schema="lifecycle")

    # destruction_job
    op.create_table("destruction_job",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="SCHEDULED"),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("resources_destroyed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("errors_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_detail", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="lifecycle")

    # outbox
    op.create_table("lifecycle_event_outbox",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(30)),
        sa.Column("event_type", sa.String(200), nullable=False),
        sa.Column("aggregate_id", sa.String(64)),
        sa.Column("payload", sa.dialects.postgresql.JSONB(), nullable=False),
        sa.Column("request_id", sa.String(64)),
        sa.Column("occurred_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text()),
        schema="lifecycle")

    # RLS for tenant-scoped tables
    tenant_tables = ["retention_policy_override", "recycle_bin", "legal_hold", "destruction_certificate"]
    for tbl in tenant_tables:
        op.execute(f'ALTER TABLE lifecycle."{tbl}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE lifecycle."{tbl}" FORCE ROW LEVEL SECURITY')
        tm = "tenant_id = current_setting('app.tenant_id', true)"
        for cmd, clause in [("SELECT", f"USING ({tm})"), ("INSERT", f"WITH CHECK ({tm})"),
                             ("UPDATE", f"USING ({tm}) WITH CHECK ({tm})"), ("DELETE", f"USING ({tm})")]:
            op.execute(f'CREATE POLICY tenant_{cmd.lower()} ON lifecycle."{tbl}" FOR {cmd} TO app_user, app_admin {clause}')

    op.execute("GRANT USAGE ON SCHEMA lifecycle TO app_user, app_admin, app_observability")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA lifecycle TO app_user, app_admin")
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA lifecycle TO app_observability")


def downgrade() -> None:
    op.execute("DROP SCHEMA IF EXISTS lifecycle CASCADE")
