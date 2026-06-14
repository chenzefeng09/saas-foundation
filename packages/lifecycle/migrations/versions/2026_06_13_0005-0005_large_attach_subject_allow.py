"""large-attachment subject allowlist (USER / TEAM / ORG_UNIT)

Revision ID: 0005_large_attach_subject_allow
Revises: 0004_large_attach_entitlement
Create Date: 2026-06-13 12:00:00 UTC

Generalizes the per-user large-attachment allowlist into a single
``large_attachment_subject_allow`` table keyed by ``subject_type`` /
``subject_id`` supporting three subject kinds (aligned with authz
BindingSubjectType): USER | TEAM | ORG_UNIT.

Back-compat:
* The legacy ``user_large_attachment_allow`` table is **kept** (the old
  routes are rewritten to ``subject_type=USER`` by the service layer); it is
  retained as an alias target and is NOT dropped here.
* Existing rows from ``user_large_attachment_allow`` are backfilled into the
  new table as ``subject_type='USER'`` (id reused verbatim — ``ula_<ULID>``
  ids are unique, so reusing them as the new PK is safe and idempotent).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_large_attach_subject_allow"
down_revision: str | None = "0004_large_attach_entitlement"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ── large_attachment_subject_allow ───────────────────────────────────────
    op.create_table(
        "large_attachment_subject_allow",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(30),
            sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("subject_type", sa.String(16), nullable=False),
        sa.Column("subject_id", sa.String(64), nullable=False),
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
            "tenant_id",
            "subject_type",
            "subject_id",
            name="uq_large_attach_subject_allow",
        ),
        schema="lifecycle",
    )
    op.create_index(
        "idx_large_attach_subject_allow_tenant",
        "large_attachment_subject_allow",
        ["tenant_id"],
        schema="lifecycle",
    )

    # RLS — same pattern as 0001_lifecycle_init / 0004 for tenant-scoped tables.
    # Multi-statement DDL is split into separate execute() calls on purpose.
    tm = "tenant_id = current_setting('app.tenant_id', true)"
    tbl = "large_attachment_subject_allow"
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

    # ── back-compat backfill ─────────────────────────────────────────────────
    # Copy every existing per-user allow row as subject_type='USER'. The id is
    # reused verbatim (ula_<ULID> ids are unique → safe as the new PK), and the
    # source UNIQUE(tenant_id, user_id) guarantees the new
    # UNIQUE(tenant_id, subject_type='USER', subject_id=user_id) holds.
    op.execute(
        "INSERT INTO lifecycle.large_attachment_subject_allow "
        "(id, tenant_id, subject_type, subject_id, allowed, updated_at, updated_by) "
        "SELECT id, tenant_id, 'USER', user_id, allowed, updated_at, updated_by "
        "FROM lifecycle.user_large_attachment_allow"
    )


def downgrade() -> None:
    tbl = "large_attachment_subject_allow"
    for cmd in ("select", "insert", "update", "delete"):
        op.execute(f'DROP POLICY IF EXISTS tenant_{cmd} ON lifecycle."{tbl}"')
    op.drop_index(
        "idx_large_attach_subject_allow_tenant",
        table_name="large_attachment_subject_allow",
        schema="lifecycle",
    )
    op.drop_table("large_attachment_subject_allow", schema="lifecycle")
