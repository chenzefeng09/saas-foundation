"""Add mfa_satisfied to identity.session.

Marks whether a session has cleared any required MFA step.  Defaults TRUE so
existing rows and password-only / SSO logins (no MFA required) are unaffected;
the password-then-MFA challenge flow explicitly issues the row only after the
second factor is verified.

Revision ID: 0005_session_mfa_satisfied
Revises: 0004_session_refresh_jti
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005_session_mfa_satisfied"
down_revision = "0004_session_refresh_jti"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "session",
        sa.Column(
            "mfa_satisfied",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
        schema="identity",
    )


def downgrade() -> None:
    op.drop_column("session", "mfa_satisfied", schema="identity")
