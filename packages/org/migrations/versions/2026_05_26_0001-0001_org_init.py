"""org init schema

Revision ID: 0001_org_init
Revises:
Create Date: 2026-05-26 10:00:00 UTC

Tables (org-v1 §3):
  - org.org_unit            — adjacency list + ltree path (depth ≤ 12)
  - org.team                — leaves under OUs
  - org.user_membership     — user's primary OU
  - org.user_team_membership
  - org.user_org_unit_secondary
  - org.org_unit_history
  - org.org_event_outbox

Triggers:
  - compute_org_unit_path        BEFORE INSERT/UPDATE OF parent_id, code
  - reparent_org_unit_subtree    AFTER UPDATE OF parent_id (rewrites descendants)
  - prevent_org_unit_cycle       BEFORE UPDATE OF parent_id

RLS:
  - All tenant-scoped tables get 4 standard policies on (tenant_id =
    current_setting('app.tenant_id', true)) + an admin escape.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_org_init"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_TENANT_TABLES = (
    "org_unit",
    "team",
    "user_membership",
    "user_team_membership",
    "user_org_unit_secondary",
    "org_unit_history",
)


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS org")
    op.execute("CREATE EXTENSION IF NOT EXISTS ltree")

    # ----------------------------------------------------- org_unit
    op.execute(
        """
        CREATE TABLE org.org_unit (
            id              VARCHAR(30) PRIMARY KEY,
            tenant_id       VARCHAR(30) NOT NULL REFERENCES tenant.tenant(id) ON DELETE CASCADE,
            parent_id       VARCHAR(30) REFERENCES org.org_unit(id) ON DELETE RESTRICT,
            code            VARCHAR(32) NOT NULL,
            name            VARCHAR(200) NOT NULL,
            name_en         VARCHAR(200),
            description     TEXT,
            manager_user_id VARCHAR(30),
            kind            VARCHAR(20) NOT NULL DEFAULT 'DEPARTMENT',
            path            LTREE NOT NULL,
            depth           SMALLINT NOT NULL,
            sort_order      INT NOT NULL DEFAULT 0,
            is_archived     BOOLEAN NOT NULL DEFAULT false,
            metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            deleted_at      TIMESTAMPTZ,
            created_by      VARCHAR(30),
            updated_by      VARCHAR(30),
            CONSTRAINT ck_ou_id_format CHECK (id ~ '^ou_[0-9A-Z]{26}$'),
            CONSTRAINT ck_ou_code_format CHECK (code ~ '^[a-z][a-z0-9_-]{0,31}$'),
            CONSTRAINT ck_ou_kind CHECK (kind IN ('BU','DEPARTMENT','CENTER','OFFICE','VIRTUAL')),
            CONSTRAINT ck_ou_depth CHECK (depth <= 12),
            CONSTRAINT ck_ou_no_self_parent CHECK (parent_id IS NULL OR parent_id <> id),
            CONSTRAINT uq_org_unit_parent_code UNIQUE (tenant_id, parent_id, code)
        )
        """
    )
    op.execute("CREATE INDEX ou_tenant_id_idx ON org.org_unit (tenant_id)")
    op.execute("CREATE INDEX ou_parent_idx ON org.org_unit (tenant_id, parent_id)")
    op.execute("CREATE INDEX ou_path_gist ON org.org_unit USING GIST (path)")
    op.execute("CREATE INDEX ou_path_btree ON org.org_unit USING BTREE (path)")
    op.execute(
        "CREATE INDEX ou_manager_idx ON org.org_unit (manager_user_id) "
        "WHERE manager_user_id IS NOT NULL"
    )
    op.execute(
        "CREATE UNIQUE INDEX ou_tenant_path_idx ON org.org_unit (tenant_id, path) "
        "WHERE deleted_at IS NULL"
    )

    # ----------------------------------------------------- triggers
    op.execute(
        """
        CREATE OR REPLACE FUNCTION org.compute_org_unit_path() RETURNS TRIGGER AS $$
        DECLARE
            parent_path  LTREE;
            parent_depth SMALLINT;
        BEGIN
            IF NEW.parent_id IS NULL THEN
                NEW.path  := text2ltree(NEW.tenant_id || '.' || NEW.code);
                NEW.depth := 0;
            ELSE
                SELECT path, depth INTO parent_path, parent_depth
                    FROM org.org_unit WHERE id = NEW.parent_id;
                IF parent_path IS NULL THEN
                    RAISE EXCEPTION 'Parent % not found', NEW.parent_id;
                END IF;
                NEW.path  := parent_path || text2ltree(NEW.code);
                NEW.depth := parent_depth + 1;
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        "CREATE TRIGGER org_unit_path_compute "
        "BEFORE INSERT OR UPDATE OF parent_id, code, tenant_id ON org.org_unit "
        "FOR EACH ROW EXECUTE FUNCTION org.compute_org_unit_path()"
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION org.reparent_org_unit_subtree() RETURNS TRIGGER AS $$
        DECLARE
            old_path LTREE := OLD.path;
            new_path LTREE := NEW.path;
        BEGIN
            IF old_path = new_path THEN RETURN NEW; END IF;
            UPDATE org.org_unit
                SET path  = new_path || subpath(path, nlevel(old_path)),
                    depth = nlevel(new_path) + (nlevel(path) - nlevel(old_path))
                WHERE path <@ old_path AND id <> NEW.id;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        "CREATE TRIGGER org_unit_reparent "
        "AFTER UPDATE OF parent_id ON org.org_unit "
        "FOR EACH ROW WHEN (OLD.parent_id IS DISTINCT FROM NEW.parent_id) "
        "EXECUTE FUNCTION org.reparent_org_unit_subtree()"
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION org.prevent_org_unit_cycle() RETURNS TRIGGER AS $$
        BEGIN
            IF NEW.parent_id IS NOT NULL AND EXISTS (
                SELECT 1 FROM org.org_unit
                WHERE id = NEW.parent_id AND path <@ OLD.path
            ) THEN
                RAISE EXCEPTION 'Cycle detected: cannot make % child of its descendant', NEW.id;
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        "CREATE TRIGGER org_unit_no_cycle "
        "BEFORE UPDATE OF parent_id ON org.org_unit "
        "FOR EACH ROW EXECUTE FUNCTION org.prevent_org_unit_cycle()"
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION org.touch_updated_at() RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at := now();
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        "CREATE TRIGGER org_unit_touch_updated "
        "BEFORE UPDATE ON org.org_unit "
        "FOR EACH ROW EXECUTE FUNCTION org.touch_updated_at()"
    )

    # ----------------------------------------------------- team
    op.execute(
        """
        CREATE TABLE org.team (
            id              VARCHAR(30) PRIMARY KEY,
            tenant_id       VARCHAR(30) NOT NULL REFERENCES tenant.tenant(id) ON DELETE CASCADE,
            org_unit_id     VARCHAR(30) NOT NULL REFERENCES org.org_unit(id) ON DELETE RESTRICT,
            code            VARCHAR(32) NOT NULL,
            name            VARCHAR(200) NOT NULL,
            description     TEXT,
            lead_user_id    VARCHAR(30),
            kind            VARCHAR(20) NOT NULL DEFAULT 'PROJECT',
            is_archived     BOOLEAN NOT NULL DEFAULT false,
            metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            deleted_at      TIMESTAMPTZ,
            created_by      VARCHAR(30),
            updated_by      VARCHAR(30),
            CONSTRAINT ck_team_id_format CHECK (id ~ '^tm_[0-9A-Z]{26}$'),
            CONSTRAINT ck_team_code_format CHECK (code ~ '^[a-z][a-z0-9_-]{0,31}$'),
            CONSTRAINT ck_team_kind CHECK (kind IN ('PROJECT','SQUAD','GUILD','VIRTUAL')),
            CONSTRAINT uq_team_ou_code UNIQUE (tenant_id, org_unit_id, code)
        )
        """
    )
    op.execute("CREATE INDEX team_tenant_idx ON org.team (tenant_id)")
    op.execute("CREATE INDEX team_ou_idx ON org.team (tenant_id, org_unit_id)")
    op.execute(
        "CREATE INDEX team_lead_idx ON org.team (lead_user_id) "
        "WHERE lead_user_id IS NOT NULL"
    )
    op.execute(
        "CREATE TRIGGER team_touch_updated "
        "BEFORE UPDATE ON org.team "
        "FOR EACH ROW EXECUTE FUNCTION org.touch_updated_at()"
    )

    # ----------------------------------------------------- user_membership
    op.execute(
        """
        CREATE TABLE org.user_membership (
            user_id              VARCHAR(30) PRIMARY KEY,
            tenant_id            VARCHAR(30) NOT NULL REFERENCES tenant.tenant(id) ON DELETE CASCADE,
            primary_org_unit_id  VARCHAR(30) NOT NULL REFERENCES org.org_unit(id) ON DELETE RESTRICT,
            job_title            VARCHAR(200),
            employee_no          VARCHAR(64),
            join_date            DATE NOT NULL DEFAULT current_date,
            leave_date           DATE,
            manager_user_id      VARCHAR(30),
            employment_kind      VARCHAR(20) NOT NULL DEFAULT 'EMPLOYEE',
            metadata             JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_by           VARCHAR(30),
            CONSTRAINT ck_um_user_id_format CHECK (user_id ~ '^usr_[0-9A-Z]{26}$'),
            CONSTRAINT ck_um_employment_kind CHECK (
                employment_kind IN ('EMPLOYEE','CONTRACTOR','INTERN','EXTERNAL')
            )
        )
        """
    )
    op.execute("CREATE INDEX um_tenant_idx ON org.user_membership (tenant_id)")
    op.execute(
        "CREATE INDEX um_primary_ou_idx ON org.user_membership (tenant_id, primary_org_unit_id)"
    )
    op.execute(
        "CREATE INDEX um_manager_idx ON org.user_membership (manager_user_id) "
        "WHERE manager_user_id IS NOT NULL"
    )
    op.execute(
        "CREATE UNIQUE INDEX um_tenant_emp_idx "
        "ON org.user_membership (tenant_id, employee_no) "
        "WHERE employee_no IS NOT NULL"
    )
    op.execute(
        "CREATE TRIGGER user_membership_touch_updated "
        "BEFORE UPDATE ON org.user_membership "
        "FOR EACH ROW EXECUTE FUNCTION org.touch_updated_at()"
    )

    # ----------------------------------------------------- user_team_membership
    op.execute(
        """
        CREATE TABLE org.user_team_membership (
            user_id      VARCHAR(30) NOT NULL,
            team_id      VARCHAR(30) NOT NULL REFERENCES org.team(id) ON DELETE RESTRICT,
            tenant_id    VARCHAR(30) NOT NULL REFERENCES tenant.tenant(id) ON DELETE CASCADE,
            role_in_team VARCHAR(20) NOT NULL DEFAULT 'MEMBER',
            joined_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
            left_at      TIMESTAMPTZ,
            granted_by   VARCHAR(30),
            PRIMARY KEY (user_id, team_id),
            CONSTRAINT ck_utm_role CHECK (role_in_team IN ('MEMBER','LEAD','OBSERVER'))
        )
        """
    )
    op.execute(
        "CREATE INDEX utm_team_idx ON org.user_team_membership (tenant_id, team_id) "
        "WHERE left_at IS NULL"
    )
    op.execute(
        "CREATE INDEX utm_user_idx ON org.user_team_membership (tenant_id, user_id)"
    )

    # ----------------------------------------------------- user_org_unit_secondary
    op.execute(
        """
        CREATE TABLE org.user_org_unit_secondary (
            user_id     VARCHAR(30) NOT NULL,
            org_unit_id VARCHAR(30) NOT NULL REFERENCES org.org_unit(id) ON DELETE RESTRICT,
            valid_from  TIMESTAMPTZ NOT NULL DEFAULT now(),
            tenant_id   VARCHAR(30) NOT NULL REFERENCES tenant.tenant(id) ON DELETE CASCADE,
            reason      VARCHAR(20) NOT NULL DEFAULT 'TEMP_ASSIGN',
            valid_until TIMESTAMPTZ,
            granted_by  VARCHAR(30) NOT NULL,
            PRIMARY KEY (user_id, org_unit_id, valid_from),
            CONSTRAINT ck_uos_reason CHECK (reason IN ('TEMP_ASSIGN','DOTTED_LINE','CROSS_TEAM'))
        )
        """
    )
    op.execute(
        "CREATE INDEX uos_ou_idx ON org.user_org_unit_secondary (tenant_id, org_unit_id) "
        "WHERE valid_until IS NULL"
    )
    op.execute(
        "CREATE INDEX uos_user_idx ON org.user_org_unit_secondary (tenant_id, user_id)"
    )

    # ----------------------------------------------------- org_unit_history
    op.execute(
        """
        CREATE TABLE org.org_unit_history (
            id             BIGSERIAL PRIMARY KEY,
            tenant_id      VARCHAR(30) NOT NULL,
            org_unit_id    VARCHAR(30) NOT NULL,
            changed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
            changed_by     VARCHAR(30) NOT NULL,
            field          VARCHAR(50) NOT NULL,
            old_value      TEXT,
            new_value      TEXT,
            audit_event_id VARCHAR(30)
        )
        """
    )
    op.execute(
        "CREATE INDEX ouh_ou_time_idx "
        "ON org.org_unit_history (tenant_id, org_unit_id, changed_at DESC)"
    )

    # ----------------------------------------------------- org_event_outbox
    op.execute(
        """
        CREATE TABLE org.org_event_outbox (
            id           BIGSERIAL PRIMARY KEY,
            tenant_id    VARCHAR(30),
            event_type   VARCHAR(200) NOT NULL,
            aggregate_id VARCHAR(64),
            payload      JSON NOT NULL,
            request_id   VARCHAR(64),
            occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
            published_at TIMESTAMPTZ,
            attempts     INT NOT NULL DEFAULT 0,
            last_error   TEXT
        )
        """
    )
    op.execute(
        "CREATE INDEX outbox_pending_idx ON org.org_event_outbox (id) "
        "WHERE published_at IS NULL"
    )

    # ----------------------------------------------------- RLS
    for tbl in _TENANT_TABLES:
        op.execute(f'ALTER TABLE org."{tbl}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE org."{tbl}" FORCE ROW LEVEL SECURITY')
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
                f'CREATE POLICY {policy_name} ON org."{tbl}" '
                f"FOR {cmd} TO app_user, app_admin {clauses}"
            )
        op.execute(
            f'CREATE POLICY admin_all ON org."{tbl}" '
            f"FOR ALL TO app_admin "
            f"USING (current_setting('app.actor', true) = 'ADMIN') "
            f"WITH CHECK (current_setting('app.actor', true) = 'ADMIN')"
        )

    # outbox RLS
    op.execute("ALTER TABLE org.org_event_outbox ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE org.org_event_outbox FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY outbox_tenant_insert ON org.org_event_outbox "
        "FOR INSERT TO app_user, app_admin "
        "WITH CHECK ("
        "  tenant_id IS NULL OR tenant_id = current_setting('app.tenant_id', true)"
        ")"
    )
    op.execute(
        "CREATE POLICY outbox_tenant_select ON org.org_event_outbox "
        "FOR SELECT TO app_user, app_admin "
        "USING (tenant_id = current_setting('app.tenant_id', true))"
    )
    op.execute(
        "CREATE POLICY outbox_system_all ON org.org_event_outbox "
        "FOR ALL TO app_observability, app_admin "
        "USING (current_setting('app.actor', true) = 'SYSTEM') "
        "WITH CHECK (current_setting('app.actor', true) = 'SYSTEM')"
    )

    # ----------------------------------------------------- grants
    op.execute("GRANT USAGE ON SCHEMA org TO app_user, app_admin, app_observability")
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA org "
        "TO app_user, app_admin"
    )
    op.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA org TO app_user, app_admin")
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA org TO app_observability")
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA org "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user, app_admin"
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA org "
        "GRANT USAGE, SELECT ON SEQUENCES TO app_user, app_admin"
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA org "
        "GRANT SELECT ON TABLES TO app_observability"
    )


def downgrade() -> None:
    op.execute("DROP SCHEMA IF EXISTS org CASCADE")
