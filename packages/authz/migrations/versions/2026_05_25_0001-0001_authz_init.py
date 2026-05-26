"""authz init schema

Revision ID: 0001_authz_init
Revises:
Create Date: 2026-05-25 13:00:00 UTC

Tables:
  - authz.permission_definition (global catalog; no tenant_id)
  - authz.role (tenant-scoped)
  - authz.role_binding (tenant-scoped; hot table)
  - authz.role_inherit (DAG with cycle-prevention trigger)
  - authz.outbox

RLS pattern:
  - role / role_binding / role_inherit: standard 4 policies (SELECT/INSERT/UPDATE/DELETE)
    keyed on tenant_id = current_setting('app.tenant_id', true).
    INSERT only WITH CHECK; UPDATE uses both USING + WITH CHECK.
  - permission_definition: NO RLS (global catalog).
  - outbox: tenant insert + system-all.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_authz_init"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_TENANT_TABLES = ("role", "role_binding", "role_inherit")


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS authz")

    # ----------------------------------------------------- permission_definition
    op.create_table(
        "permission_definition",
        sa.Column("id", sa.String(120), primary_key=True),
        sa.Column("service", sa.String(50), nullable=False),
        sa.Column("resource_type", sa.String(50), nullable=False),
        sa.Column("action", sa.String(50), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("risk_level", sa.String(10), nullable=False, server_default="LOW"),
        sa.Column("requires_mfa", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("requires_4eyes", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("requires_pam_jit", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "requires_business_hours", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("is_system", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("deprecated_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            "risk_level IN ('LOW','MEDIUM','HIGH','CRITICAL')", name="ck_perm_risk_level"
        ),
        schema="authz",
    )
    op.create_index(
        "permission_service_idx", "permission_definition", ["service"], schema="authz"
    )

    # ----------------------------------------------------- role
    op.create_table(
        "role",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(30),
            sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("display_name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("is_system", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("immutable", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("permissions", sa.ARRAY(sa.String())),
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
        sa.Column("deleted_at", sa.DateTime(timezone=True)),
        sa.Column("created_by", sa.String(30)),
        sa.CheckConstraint("id ~ '^rol_[0-9A-Z]{26}$'", name="ck_role_id_format"),
        schema="authz",
    )
    op.create_index("role_tenant_idx", "role", ["tenant_id"], schema="authz")
    # Partial unique: active roles per tenant by name
    op.execute(
        "CREATE UNIQUE INDEX role_tenant_name_idx ON authz.role (tenant_id, name) "
        "WHERE deleted_at IS NULL"
    )

    # ----------------------------------------------------- role_binding
    op.create_table(
        "role_binding",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(30),
            sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("principal_kind", sa.String(20), nullable=False),
        sa.Column("principal_id", sa.String(64), nullable=False),
        sa.Column(
            "role_id",
            sa.String(30),
            sa.ForeignKey("authz.role.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("scope_kind", sa.String(20), nullable=False),
        sa.Column("scope_id", sa.String(64)),
        sa.Column(
            "granted_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("granted_by", sa.String(30), nullable=False),
        sa.Column("grant_reason", sa.Text()),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_by", sa.String(30)),
        sa.Column("revoked_reason", sa.Text()),
        sa.Column("audit_event_id", sa.String(30)),
        sa.CheckConstraint("id ~ '^rbd_[0-9A-Z]{26}$'", name="ck_rbd_id_format"),
        sa.CheckConstraint(
            "principal_kind IN ('USER','TEAM','ORG_UNIT','API_KEY','SERVICE_ACCOUNT')",
            name="ck_rbd_principal_kind",
        ),
        sa.CheckConstraint(
            "scope_kind IN ('TENANT','ORG_UNIT','TEAM','RESOURCE','GLOBAL_SYSTEM')",
            name="ck_rbd_scope_kind",
        ),
        schema="authz",
    )
    op.create_index("rb_tenant_idx", "role_binding", ["tenant_id"], schema="authz")
    op.execute(
        "CREATE INDEX rb_principal_idx ON authz.role_binding "
        "(tenant_id, principal_kind, principal_id, revoked_at) "
        "WHERE revoked_at IS NULL"
    )
    op.create_index(
        "rb_role_idx", "role_binding", ["tenant_id", "role_id"], schema="authz"
    )
    op.create_index(
        "rb_scope_idx",
        "role_binding",
        ["tenant_id", "scope_kind", "scope_id"],
        schema="authz",
    )
    op.execute(
        "CREATE INDEX rb_active_idx ON authz.role_binding "
        "(tenant_id, principal_id) "
        "WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())"
    )
    op.execute(
        "CREATE INDEX rb_expires_idx ON authz.role_binding (expires_at) "
        "WHERE expires_at IS NOT NULL AND revoked_at IS NULL"
    )

    # ----------------------------------------------------- role_inherit
    op.create_table(
        "role_inherit",
        sa.Column("tenant_id", sa.String(30), nullable=False),
        sa.Column(
            "parent_role_id",
            sa.String(30),
            sa.ForeignKey("authz.role.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "child_role_id",
            sa.String(30),
            sa.ForeignKey("authz.role.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        schema="authz",
    )

    # Cycle-prevention trigger
    op.execute(
        """
        CREATE OR REPLACE FUNCTION authz.check_no_inherit_cycle()
        RETURNS TRIGGER AS $$
        DECLARE has_cycle BOOLEAN;
        BEGIN
            WITH RECURSIVE ancestors AS (
                SELECT parent_role_id, child_role_id, 1 AS depth
                  FROM authz.role_inherit
                 WHERE child_role_id = NEW.parent_role_id
                UNION ALL
                SELECT ri.parent_role_id, ri.child_role_id, a.depth + 1
                  FROM authz.role_inherit ri
                  JOIN ancestors a ON ri.child_role_id = a.parent_role_id
                 WHERE a.depth < 100
            )
            SELECT EXISTS (
                SELECT 1 FROM ancestors WHERE parent_role_id = NEW.child_role_id
            ) INTO has_cycle;
            IF has_cycle THEN
                RAISE EXCEPTION 'role_inherit cycle: % -> %',
                    NEW.parent_role_id, NEW.child_role_id;
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        "CREATE TRIGGER role_inherit_no_cycle "
        "BEFORE INSERT OR UPDATE ON authz.role_inherit "
        "FOR EACH ROW EXECUTE FUNCTION authz.check_no_inherit_cycle()"
    )

    # ----------------------------------------------------- outbox
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
        schema="authz",
    )
    op.create_index(
        "ix_authz_outbox_unpublished", "outbox", ["published_at", "created_at"], schema="authz"
    )

    # ----------------------------------------------------- RLS
    for tbl in _TENANT_TABLES:
        op.execute(f'ALTER TABLE authz."{tbl}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE authz."{tbl}" FORCE ROW LEVEL SECURITY')
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
                f'CREATE POLICY {policy_name} ON authz."{tbl}" '
                f"FOR {cmd} TO app_user, app_admin {clauses}"
            )
        op.execute(
            f'CREATE POLICY admin_all ON authz."{tbl}" '
            f"FOR ALL TO app_admin "
            f"USING (current_setting('app.actor', true) = 'ADMIN') "
            f"WITH CHECK (current_setting('app.actor', true) = 'ADMIN')"
        )

    # outbox RLS
    op.execute("ALTER TABLE authz.outbox ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE authz.outbox FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY outbox_tenant_insert ON authz.outbox "
        "FOR INSERT TO app_user, app_admin "
        "WITH CHECK ("
        "  tenant_id IS NULL OR tenant_id = current_setting('app.tenant_id', true)"
        ")"
    )
    op.execute(
        "CREATE POLICY outbox_tenant_select ON authz.outbox "
        "FOR SELECT TO app_user, app_admin "
        "USING (tenant_id = current_setting('app.tenant_id', true))"
    )
    op.execute(
        "CREATE POLICY outbox_system_all ON authz.outbox "
        "FOR ALL TO app_observability, app_admin "
        "USING (current_setting('app.actor', true) = 'SYSTEM') "
        "WITH CHECK (current_setting('app.actor', true) = 'SYSTEM')"
    )

    # ----------------------------------------------------- grants
    op.execute("GRANT USAGE ON SCHEMA authz TO app_user, app_admin, app_observability")
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA authz "
        "TO app_user, app_admin"
    )
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA authz TO app_observability")
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA authz "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user, app_admin"
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA authz "
        "GRANT SELECT ON TABLES TO app_observability"
    )


def downgrade() -> None:
    op.execute("DROP SCHEMA IF EXISTS authz CASCADE")
