"""platform-scoped SSO providers + tenant routing rules

Revision ID: 0002_platform_sso
Revises: 0001_identity_init
Create Date: 2026-06-11 00:01:00 UTC

Adds platform-level SSO:
  * sso_provider.tenant_id becomes NULLABLE (NULL = platform-scoped provider).
  * sso_provider gains `scope` (TENANT|PLATFORM) + `default_tenant_id`.
  * SELECT RLS policy on sso_provider widened so tenants can READ platform rows
    (tenant_id IS NULL); INSERT/UPDATE/DELETE stay exact-match so tenant sessions
    cannot mutate platform rows (NULL never matches exact-match) — admin
    mutations go through the existing admin_all policy.
  * new table sso_routing_rule (platform config: provider → tenant routing).

IMPORTANT: every SQL statement is its own op.execute() — asyncpg cannot run
multi-statement strings.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_platform_sso"
down_revision: str | None = "0001_identity_init"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ----------------------------------------------- sso_provider column tweaks
    op.execute(
        "ALTER TABLE identity.sso_provider ALTER COLUMN tenant_id DROP NOT NULL"
    )
    op.execute(
        "ALTER TABLE identity.sso_provider "
        "ADD COLUMN scope VARCHAR(10) NOT NULL DEFAULT 'TENANT'"
    )
    op.execute(
        "ALTER TABLE identity.sso_provider "
        "ADD COLUMN default_tenant_id VARCHAR(30) "
        "REFERENCES tenant.tenant(id) ON DELETE SET NULL"
    )

    # ----------------------------------------------- widen SELECT RLS policy
    # Platform rows (tenant_id IS NULL) become readable by tenant sessions so
    # login-time provider lookup works.  Only the SELECT policy is rewritten;
    # insert/update/delete remain exact-match (NULL never matches), so tenant
    # sessions can never mutate platform rows.
    op.execute("DROP POLICY tenant_select ON identity.sso_provider")
    op.execute(
        'CREATE POLICY tenant_select ON identity."sso_provider" '
        "FOR SELECT TO app_user, app_admin "
        "USING ("
        "tenant_id = current_setting('app.tenant_id', true) "
        "OR tenant_id IS NULL"
        ")"
    )

    # ----------------------------------------------- sso_routing_rule table
    op.create_table(
        "sso_routing_rule",
        sa.Column("id", sa.String(40), primary_key=True),
        sa.Column(
            "provider_id",
            sa.String(40),
            sa.ForeignKey("identity.sso_provider.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("match_attribute", sa.String(100), nullable=False),
        sa.Column("match_type", sa.String(20), nullable=False),
        sa.Column("match_value", sa.Text(), nullable=False),
        sa.Column(
            "target_tenant_id",
            sa.String(30),
            sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("default_role", sa.String(50)),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
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
        sa.CheckConstraint(
            "match_type IN ('EMAIL_DOMAIN','EQUALS','CONTAINS','REGEX')",
            name="ck_sso_routing_rule_match_type",
        ),
        schema="identity",
    )
    op.create_index(
        "ix_sso_routing_rule_provider_priority",
        "sso_routing_rule",
        ["provider_id", "priority"],
        schema="identity",
    )

    # ----------------------------------------------- RLS on sso_routing_rule
    # Rules carry NO secrets and login-time tenant resolution must read them
    # under a tenant session, so SELECT is permissive (true).  Mutations are
    # platform-admin only via admin_all.
    op.execute(
        "ALTER TABLE identity.sso_routing_rule ENABLE ROW LEVEL SECURITY"
    )
    op.execute(
        "ALTER TABLE identity.sso_routing_rule FORCE ROW LEVEL SECURITY"
    )
    op.execute(
        'CREATE POLICY rules_select ON identity."sso_routing_rule" '
        "FOR SELECT TO app_user, app_admin "
        "USING (true)"
    )
    op.execute(
        'CREATE POLICY admin_all ON identity."sso_routing_rule" '
        "FOR ALL TO app_admin "
        "USING (current_setting('app.actor', true) = 'ADMIN') "
        "WITH CHECK (current_setting('app.actor', true) = 'ADMIN')"
    )

    # ----------------------------------------------- grants (match init pattern)
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON identity.sso_routing_rule "
        "TO app_user, app_admin"
    )
    op.execute(
        "GRANT SELECT ON identity.sso_routing_rule TO app_observability"
    )


def downgrade() -> None:
    # ----------------------------------------------- drop sso_routing_rule
    op.execute("DROP POLICY IF EXISTS admin_all ON identity.sso_routing_rule")
    op.execute("DROP POLICY IF EXISTS rules_select ON identity.sso_routing_rule")
    op.drop_index(
        "ix_sso_routing_rule_provider_priority",
        table_name="sso_routing_rule",
        schema="identity",
    )
    op.drop_table("sso_routing_rule", schema="identity")

    # ----------------------------------------------- restore SELECT RLS policy
    op.execute("DROP POLICY tenant_select ON identity.sso_provider")
    op.execute(
        'CREATE POLICY tenant_select ON identity."sso_provider" '
        "FOR SELECT TO app_user, app_admin "
        "USING (tenant_id = current_setting('app.tenant_id', true))"
    )

    # ----------------------------------------------- revert sso_provider columns
    op.execute("ALTER TABLE identity.sso_provider DROP COLUMN default_tenant_id")
    op.execute("ALTER TABLE identity.sso_provider DROP COLUMN scope")
    # Restore NOT NULL.  Existing platform rows (tenant_id IS NULL) would block
    # this; the downgrade assumes platform rows were removed first (they are
    # operator-managed config, not user data).
    op.execute(
        "ALTER TABLE identity.sso_provider ALTER COLUMN tenant_id SET NOT NULL"
    )
