"""Add identity.risk_signal table + Session.risk_score column.

Risk signals capture per-login-attempt anomaly detections (NEW_DEVICE,
IP_SUBNET_JUMP, CONSECUTIVE_FAILURES, …) for both allowed and refused logins.
Session.risk_score persists the aggregated score for retrospective audit.

Revision ID: 0007_risk_signal_and_session_score
Revises: 0006_recovery_code
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0007_risk_signal_and_session_score"
down_revision = "0006_recovery_code"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1) Session.risk_score
    op.add_column(
        "session",
        sa.Column(
            "risk_score", sa.Integer(), nullable=False, server_default=sa.text("0")
        ),
        schema="identity",
    )

    # 2) risk_signal table
    op.create_table(
        "risk_signal",
        sa.Column("id", sa.String(length=30), primary_key=True),
        sa.Column("tenant_id", sa.String(length=30), nullable=False),
        sa.Column("user_id", sa.String(length=30), nullable=True),
        sa.Column("rule", sa.String(length=40), nullable=False),
        sa.Column("weight", sa.Integer(), nullable=False),
        sa.Column("decision", sa.String(length=20), nullable=False),
        sa.Column("ip", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.String(length=500), nullable=True),
        sa.Column("detail", sa.String(length=500), nullable=True),
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
        "ix_risk_signal_tenant_id",
        "risk_signal",
        ["tenant_id"],
        schema="identity",
    )
    op.create_index(
        "ix_risk_signal_user_time",
        "risk_signal",
        ["tenant_id", "user_id", "created_at"],
        schema="identity",
    )
    op.create_index(
        "ix_risk_signal_rule_time",
        "risk_signal",
        ["tenant_id", "rule", "created_at"],
        schema="identity",
    )

    # 3) RLS — same pattern as the other identity tenant tables.
    op.execute('ALTER TABLE identity."risk_signal" ENABLE ROW LEVEL SECURITY')
    op.execute('ALTER TABLE identity."risk_signal" FORCE ROW LEVEL SECURITY')
    tenant_match = "tenant_id = current_setting('app.tenant_id', true)"
    for cmd in ("SELECT", "INSERT", "UPDATE", "DELETE"):
        if cmd == "INSERT":
            clauses = f"WITH CHECK ({tenant_match})"
        elif cmd == "UPDATE":
            clauses = f"USING ({tenant_match}) WITH CHECK ({tenant_match})"
        else:
            clauses = f"USING ({tenant_match})"
        op.execute(
            f'CREATE POLICY tenant_{cmd.lower()} ON identity."risk_signal" '
            f"FOR {cmd} TO app_user, app_admin {clauses}"
        )
    op.execute(
        'CREATE POLICY admin_all ON identity."risk_signal" '
        "FOR ALL TO app_admin "
        "USING (current_setting('app.actor', true) = 'ADMIN') "
        "WITH CHECK (current_setting('app.actor', true) = 'ADMIN')"
    )


def downgrade() -> None:
    op.drop_table("risk_signal", schema="identity")
    op.drop_column("session", "risk_score", schema="identity")
