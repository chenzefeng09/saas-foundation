"""four-eyes approval requests

Revision ID: 0007_approval_request
Revises: 0006_recycle_bin_admin_all
Create Date: 2026-10-30 12:00:00 UTC

Table: approval_request — a hard-delete or legal-hold release waiting for a
second person (lifecycle-v1 §4.4). Asking for either operation only opens a
request; it takes effect when another user approves it with a request of their
own, within the approval window. The check constraints keep the rule in the
database as well: an approved request names an approver other than the
requester.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007_approval_request"
down_revision: str | None = "0006_recycle_bin_admin_all"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "approval_request",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(30),
            sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("operation", sa.String(30), nullable=False),
        sa.Column("target_id", sa.String(30), nullable=False),
        sa.Column("requested_by", sa.String(30), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="PENDING"),
        sa.Column("decided_by", sa.String(30)),
        sa.Column("decided_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "operation IN ('HARD_DELETE', 'RELEASE_LEGAL_HOLD')",
            name="ck_approval_request_operation",
        ),
        sa.CheckConstraint(
            "status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED')",
            name="ck_approval_request_status",
        ),
        sa.CheckConstraint(
            "status <> 'APPROVED' OR (decided_by IS NOT NULL AND decided_by <> requested_by)",
            name="ck_approval_request_four_eyes",
        ),
        schema="lifecycle",
    )
    # One open request per target: asking again returns it instead of opening another.
    op.execute(
        "CREATE UNIQUE INDEX ar_pending_target_uq ON lifecycle.approval_request "
        "(tenant_id, operation, target_id) WHERE status = 'PENDING'"
    )
    op.create_index(
        "ar_tenant_requested_idx",
        "approval_request",
        ["tenant_id", "requested_at"],
        schema="lifecycle",
    )

    # RLS — same pattern as 0001_lifecycle_init for tenant-scoped tables.
    op.execute('ALTER TABLE lifecycle."approval_request" ENABLE ROW LEVEL SECURITY')
    op.execute('ALTER TABLE lifecycle."approval_request" FORCE ROW LEVEL SECURITY')
    tm = "tenant_id = current_setting('app.tenant_id', true)"
    for cmd, clause in [
        ("SELECT", f"USING ({tm})"),
        ("INSERT", f"WITH CHECK ({tm})"),
        ("UPDATE", f"USING ({tm}) WITH CHECK ({tm})"),
        ("DELETE", f"USING ({tm})"),
    ]:
        op.execute(
            f'CREATE POLICY tenant_{cmd.lower()} ON lifecycle."approval_request" '
            f"FOR {cmd} TO app_user, app_admin {clause}"
        )

    # 0001's schema-wide GRANT covered only the tables that existed then.
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE "
        "ON lifecycle.approval_request TO app_user, app_admin"
    )
    op.execute("GRANT SELECT ON lifecycle.approval_request TO app_observability")


def downgrade() -> None:
    # Dropping the table drops its indexes, constraints and policies with it.
    op.drop_table("approval_request", schema="lifecycle")
