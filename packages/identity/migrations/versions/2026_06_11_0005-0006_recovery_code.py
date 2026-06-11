"""Add identity.recovery_code table (one-time MFA fallback codes).

Stores SHA-256 hashes of one-time recovery codes generated at MFA enrolment.
Carries the standard tenant RLS policy set (tenant_* + admin_all), matching the
other identity tables.

Revision ID: 0006_recovery_code
Revises: 0005_session_mfa_satisfied
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006_recovery_code"
down_revision = "0005_session_mfa_satisfied"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "recovery_code",
        sa.Column("id", sa.String(length=30), primary_key=True),
        sa.Column("tenant_id", sa.String(length=30), nullable=False),
        sa.Column("user_id", sa.String(length=30), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenant.tenant.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["identity.user.id"], ondelete="CASCADE"
        ),
        schema="identity",
    )
    op.create_index(
        "ix_recovery_code_tenant_id",
        "recovery_code",
        ["tenant_id"],
        schema="identity",
    )
    op.create_index(
        "ix_recovery_code_user_active",
        "recovery_code",
        ["tenant_id", "user_id", "used_at"],
        schema="identity",
    )

    # RLS — same pattern as the other identity tenant tables.
    op.execute('ALTER TABLE identity."recovery_code" ENABLE ROW LEVEL SECURITY')
    op.execute('ALTER TABLE identity."recovery_code" FORCE ROW LEVEL SECURITY')
    tenant_match = "tenant_id = current_setting('app.tenant_id', true)"
    for cmd in ("SELECT", "INSERT", "UPDATE", "DELETE"):
        if cmd == "INSERT":
            clauses = f"WITH CHECK ({tenant_match})"
        elif cmd == "UPDATE":
            clauses = f"USING ({tenant_match}) WITH CHECK ({tenant_match})"
        else:
            clauses = f"USING ({tenant_match})"
        op.execute(
            f'CREATE POLICY tenant_{cmd.lower()} ON identity."recovery_code" '
            f"FOR {cmd} TO app_user, app_admin {clauses}"
        )
    op.execute(
        'CREATE POLICY admin_all ON identity."recovery_code" '
        "FOR ALL TO app_admin "
        "USING (current_setting('app.actor', true) = 'ADMIN') "
        "WITH CHECK (current_setting('app.actor', true) = 'ADMIN')"
    )


def downgrade() -> None:
    op.drop_table("recovery_code", schema="identity")
