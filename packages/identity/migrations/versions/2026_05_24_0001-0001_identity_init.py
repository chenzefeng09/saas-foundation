"""identity init schema (users / sessions / mfa / sso / password_policy / outbox)

Revision ID: 0001_identity_init
Revises:
Create Date: 2026-05-24 00:01:00 UTC

Important: RLS + FORCE RLS + 4 standard policies per docs/multi-tenancy.md §3.
The four standard policies all read `current_setting('app.tenant_id', true)`.

The 'SYSTEM' actor (outbox publisher background job) gets a permissive policy on
the outbox table only.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_identity_init"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# Tables that must carry the standard 4-policy set
_TENANT_TABLES = ("user", "session", "mfa_method", "sso_provider")


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS identity")

    # ----------------------------------------------------------------- user
    op.create_table(
        "user",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(30),
            sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("email", sa.String(254), nullable=False),
        sa.Column("display_name", sa.String(200)),
        sa.Column("status", sa.String(20), nullable=False, server_default="INVITED"),
        sa.Column("keycloak_user_id", sa.String(64)),
        sa.Column("external_id", sa.String(255)),
        sa.Column("roles", sa.ARRAY(sa.String())),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("locked_until", sa.DateTime(timezone=True)),
        sa.Column("failed_login_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_login_at", sa.DateTime(timezone=True)),
        sa.Column("deleted_at", sa.DateTime(timezone=True)),
        sa.Column("metadata", sa.JSON()),
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
        sa.UniqueConstraint("tenant_id", "email", name="uq_user_tenant_email"),
        sa.CheckConstraint(
            "id ~ '^usr_[0-9A-Z]{26}$'",
            name="ck_user_id_format",
        ),
        sa.CheckConstraint(
            "status IN ('ACTIVE','INVITED','SUSPENDED','LOCKED','DEACTIVATED','FROZEN')",
            name="ck_user_status",
        ),
        schema="identity",
    )
    op.create_index(
        "ix_user_tenant_status", "user", ["tenant_id", "status"], schema="identity"
    )
    op.create_index(
        "ix_user_external_id", "user", ["tenant_id", "external_id"], schema="identity"
    )

    # ----------------------------------------------------------------- session
    op.create_table(
        "session",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(30),
            sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            sa.String(30),
            sa.ForeignKey("identity.user.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("keycloak_session_id", sa.String(64)),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("revoke_reason", sa.String(100)),
        sa.Column("ip", sa.String(45)),
        sa.Column("user_agent", sa.String(500)),
        sa.Column("device_id", sa.String(100)),
        sa.Column("scopes", sa.ARRAY(sa.String())),
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
        sa.CheckConstraint("id ~ '^sess_[0-9A-Z]{26}$'", name="ck_session_id_format"),
        schema="identity",
    )
    op.create_index(
        "ix_session_user_active",
        "session",
        ["tenant_id", "user_id", "revoked_at"],
        schema="identity",
    )
    op.create_index(
        "ix_session_expires", "session", ["tenant_id", "expires_at"], schema="identity"
    )

    # ----------------------------------------------------------------- mfa_method
    op.create_table(
        "mfa_method",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(30),
            sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            sa.String(30),
            sa.ForeignKey("identity.user.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("label", sa.String(100)),
        sa.Column("secret_ref", sa.String(200)),
        sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("disabled_at", sa.DateTime(timezone=True)),
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
            "kind IN ('TOTP','SMS_OTP','WEBAUTHN','PUSH')", name="ck_mfa_kind"
        ),
        schema="identity",
    )
    op.create_index(
        "ix_mfa_method_user", "mfa_method", ["tenant_id", "user_id"], schema="identity"
    )

    # ----------------------------------------------------------------- sso_provider
    op.create_table(
        "sso_provider",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(30),
            sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("keycloak_idp_alias", sa.String(100)),
        sa.Column("config", sa.JSON(), nullable=False, server_default="{}"),
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
        sa.UniqueConstraint("tenant_id", "name", name="uq_sso_provider_tenant_name"),
        sa.CheckConstraint(
            "kind IN ('OIDC','SAML','AD','LDAP','DINGTALK_ENTERPRISE',"
            "'FEISHU_ENTERPRISE','WECOM')",
            name="ck_sso_kind",
        ),
        schema="identity",
    )

    # ----------------------------------------------------------------- password_policy
    op.create_table(
        "password_policy",
        sa.Column(
            "tenant_id",
            sa.String(30),
            sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("min_length", sa.Integer(), nullable=False, server_default="12"),
        sa.Column("require_upper", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("require_lower", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("require_digit", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("require_symbol", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("max_age_days", sa.Integer(), nullable=False, server_default="90"),
        sa.Column("history_size", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("max_failed_attempts", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("lockout_minutes", sa.Integer(), nullable=False, server_default="30"),
        sa.Column(
            "breach_check_enabled", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        schema="identity",
    )

    # ----------------------------------------------------------------- outbox
    op.create_table(
        "outbox",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30)),
        sa.Column("event_type", sa.String(200), nullable=False),
        sa.Column("aggregate_id", sa.String(64)),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("request_id", sa.String(64)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.Column("publish_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text()),
        schema="identity",
    )
    op.create_index(
        "ix_outbox_unpublished",
        "outbox",
        ["published_at", "created_at"],
        schema="identity",
    )

    # ----------------------------------------------------------------- RLS
    # Pattern: ENABLE + FORCE + 4 standard policies + admin/system overrides.
    # 'admin' actor (X-Actor=ADMIN) bypasses tenant filter; 'system' too (for outbox drain).
    for tbl in _TENANT_TABLES:
        op.execute(f"ALTER TABLE identity.\"{tbl}\" ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE identity.\"{tbl}\" FORCE ROW LEVEL SECURITY")
        for cmd in ("SELECT", "INSERT", "UPDATE", "DELETE"):
            policy_name = f"tenant_{cmd.lower()}"
            tenant_match = "tenant_id = current_setting('app.tenant_id', true)"
            # PostgreSQL grammar: INSERT accepts only WITH CHECK; SELECT/DELETE only USING;
            # UPDATE accepts both (we use both for row-level mutation safety).
            if cmd == "INSERT":
                clauses = f"WITH CHECK ({tenant_match})"
            elif cmd == "UPDATE":
                clauses = f"USING ({tenant_match}) WITH CHECK ({tenant_match})"
            else:  # SELECT, DELETE
                clauses = f"USING ({tenant_match})"
            op.execute(
                f"CREATE POLICY {policy_name} ON identity.\"{tbl}\" "
                f"FOR {cmd} TO app_user, app_admin "
                f"{clauses}"
            )
        # Admin override (rare; uses X-Actor=ADMIN signalled via app.actor)
        op.execute(
            f"CREATE POLICY admin_all ON identity.\"{tbl}\" "
            f"FOR ALL TO app_admin "
            f"USING (current_setting('app.actor', true) = 'ADMIN') "
            f"WITH CHECK (current_setting('app.actor', true) = 'ADMIN')"
        )

    # password_policy uses single PK = tenant_id; same pattern
    op.execute("ALTER TABLE identity.password_policy ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE identity.password_policy FORCE ROW LEVEL SECURITY")
    for cmd in ("SELECT", "INSERT", "UPDATE", "DELETE"):
        policy_name = f"tenant_{cmd.lower()}"
        tenant_match = "tenant_id = current_setting('app.tenant_id', true)"
        if cmd == "INSERT":
            clauses = f"WITH CHECK ({tenant_match})"
        elif cmd == "UPDATE":
            clauses = f"USING ({tenant_match}) WITH CHECK ({tenant_match})"
        else:
            clauses = f"USING ({tenant_match})"
        op.execute(
            f"CREATE POLICY {policy_name} ON identity.password_policy "
            f"FOR {cmd} TO app_user, app_admin "
            f"{clauses}"
        )

    # outbox: cross-tenant by design; only SYSTEM actor (background drain) sees all.
    op.execute("ALTER TABLE identity.outbox ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE identity.outbox FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY outbox_tenant_insert ON identity.outbox "
        "FOR INSERT TO app_user, app_admin "
        "WITH CHECK ("
        "  tenant_id IS NULL OR "
        "  tenant_id = current_setting('app.tenant_id', true)"
        ")"
    )
    op.execute(
        "CREATE POLICY outbox_tenant_select ON identity.outbox "
        "FOR SELECT TO app_user, app_admin "
        "USING (tenant_id = current_setting('app.tenant_id', true))"
    )
    op.execute(
        "CREATE POLICY outbox_system_all ON identity.outbox "
        "FOR ALL TO app_observability, app_admin "
        "USING (current_setting('app.actor', true) = 'SYSTEM') "
        "WITH CHECK (current_setting('app.actor', true) = 'SYSTEM')"
    )

    # ----------------------------------------------------------------- grants
    # Standard role privileges (read/write for app_user; admin everything except super)
    op.execute("GRANT USAGE ON SCHEMA identity TO app_user, app_admin, app_observability")
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA identity "
        "TO app_user, app_admin"
    )
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA identity TO app_observability")
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA identity "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user, app_admin"
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA identity "
        "GRANT SELECT ON TABLES TO app_observability"
    )


def downgrade() -> None:
    op.execute("DROP SCHEMA IF EXISTS identity CASCADE")
