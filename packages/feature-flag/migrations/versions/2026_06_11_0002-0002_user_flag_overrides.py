"""add user_flag_override table and flag.user_overridable column

Revision ID: 0002_user_flag_overrides
Revises: 0001_feature_flag_init
Create Date: 2026-06-11 00:00:00 UTC
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_user_flag_overrides"
down_revision: str | None = "0001_feature_flag_init"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # -- flag.user_overridable column ------------------------------------------
    op.add_column(
        "flag",
        sa.Column("user_overridable", sa.Boolean(), nullable=False, server_default=sa.false()),
        schema="feature_flag",
    )

    # -- user_flag_override table ----------------------------------------------
    op.create_table(
        "user_flag_override",
        sa.Column("tenant_id", sa.String(30), nullable=False),
        sa.Column("user_id", sa.String(200), nullable=False),
        sa.Column("flag_key", sa.String(200), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("tenant_id", "user_id", "flag_key"),
        schema="feature_flag",
    )

    # -- grants ----------------------------------------------------------------
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE"
        ' ON feature_flag."user_flag_override"'
        " TO app_user, app_admin"
    )
    op.execute(
        'GRANT SELECT ON feature_flag."user_flag_override" TO app_observability'
    )

    # -- RLS -------------------------------------------------------------------
    op.execute(
        'ALTER TABLE feature_flag."user_flag_override" ENABLE ROW LEVEL SECURITY'
    )
    op.execute(
        'ALTER TABLE feature_flag."user_flag_override" FORCE ROW LEVEL SECURITY'
    )

    # Users can only manage their own overrides within their tenant.
    op.execute(
        'CREATE POLICY user_override_own ON feature_flag."user_flag_override"'
        " FOR ALL TO app_user, app_admin"
        " USING ("
        "   tenant_id = current_setting('app.tenant_id', true)"
        "   AND user_id = current_setting('app.user_id', true)"
        " )"
        " WITH CHECK ("
        "   tenant_id = current_setting('app.tenant_id', true)"
        "   AND user_id = current_setting('app.user_id', true)"
        " )"
    )

    # Admins can read all overrides within their tenant (for observability).
    op.execute(
        'CREATE POLICY user_override_admin_read ON feature_flag."user_flag_override"'
        " FOR SELECT TO app_admin"
        " USING ("
        "   current_setting('app.actor', true) = 'ADMIN'"
        "   AND tenant_id = current_setting('app.tenant_id', true)"
        " )"
    )


def downgrade() -> None:
    op.drop_table("user_flag_override", schema="feature_flag")
    op.drop_column("flag", "user_overridable", schema="feature_flag")
