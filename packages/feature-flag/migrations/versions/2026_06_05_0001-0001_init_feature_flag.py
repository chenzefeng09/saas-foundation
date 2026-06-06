"""init feature_flag schema

Revision ID: 0001_feature_flag_init
Revises:
Create Date: 2026-06-05 00:00:00 UTC
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_feature_flag_init"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _enable_flag_rls() -> None:
    op.execute('ALTER TABLE feature_flag."flag" ENABLE ROW LEVEL SECURITY')
    op.execute('ALTER TABLE feature_flag."flag" FORCE ROW LEVEL SECURITY')
    op.execute(
        'CREATE POLICY flag_read ON feature_flag."flag" '
        "FOR SELECT TO app_user, app_admin, app_observability USING (true)"
    )
    op.execute(
        'CREATE POLICY flag_admin_write ON feature_flag."flag" '
        "FOR ALL TO app_user, app_admin "
        "USING (current_setting('app.actor', true) = 'ADMIN') "
        "WITH CHECK (current_setting('app.actor', true) = 'ADMIN')"
    )


def _enable_kill_switch_log_rls() -> None:
    op.execute('ALTER TABLE feature_flag."kill_switch_log" ENABLE ROW LEVEL SECURITY')
    op.execute('ALTER TABLE feature_flag."kill_switch_log" FORCE ROW LEVEL SECURITY')
    tenant_or_global = "tenant_id IS NULL OR tenant_id = current_setting('app.tenant_id', true)"
    admin_actor = "current_setting('app.actor', true) = 'ADMIN'"
    op.execute(
        'CREATE POLICY kill_switch_admin_all ON feature_flag."kill_switch_log" '
        "FOR ALL TO app_user, app_admin "
        f"USING ({admin_actor} AND ({tenant_or_global})) "
        f"WITH CHECK ({admin_actor} AND ({tenant_or_global}))"
    )
    op.execute(
        'CREATE POLICY kill_switch_system_select ON feature_flag."kill_switch_log" '
        "FOR SELECT TO app_observability, app_admin "
        "USING (current_setting('app.actor', true) = 'SYSTEM')"
    )


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS feature_flag")

    op.create_table(
        "flag",
        sa.Column("key", sa.String(200), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("default_value", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("fail_open", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("owner_team", sa.String(100)),
        sa.Column("tags", postgresql.JSONB()),
        sa.Column("unleash_synced_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        schema="feature_flag",
    )

    op.create_table(
        "kill_switch_log",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("flag_key", sa.String(200), nullable=False),
        sa.Column("tenant_id", sa.String(30)),
        sa.Column("reason", sa.Text()),
        sa.Column("actor", sa.String(200), nullable=False),
        sa.Column("action", sa.String(10), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        schema="feature_flag",
    )
    op.create_index("ksl_flag_key_idx", "kill_switch_log", ["flag_key"], schema="feature_flag")
    op.create_index("ksl_tenant_idx", "kill_switch_log", ["tenant_id"], schema="feature_flag")

    op.execute("GRANT USAGE ON SCHEMA feature_flag TO app_user, app_admin, app_observability")
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA feature_flag"
        " TO app_user, app_admin"
    )
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA feature_flag TO app_observability")

    _enable_flag_rls()
    _enable_kill_switch_log_rls()


def downgrade() -> None:
    op.execute("DROP SCHEMA IF EXISTS feature_flag CASCADE")
