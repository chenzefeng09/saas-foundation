"""Add refresh_token_jti to identity.session.

Tracks the ``jti`` of the refresh token currently bound to each session, so
single-logout can blacklist the live token and refresh-rotation can relink the
row to the newly-issued refresh token.  Nullable: existing rows and
refresh-less login paths leave it NULL.

Revision ID: 0004_session_refresh_jti
Revises: 0003_outbox_admin_policy
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004_session_refresh_jti"
down_revision = "0003_outbox_admin_policy"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "session",
        sa.Column("refresh_token_jti", sa.String(length=64), nullable=True),
        schema="identity",
    )


def downgrade() -> None:
    op.drop_column("session", "refresh_token_jti", schema="identity")
