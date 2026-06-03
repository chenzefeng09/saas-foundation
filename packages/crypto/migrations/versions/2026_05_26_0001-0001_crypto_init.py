"""crypto init schema

Revision ID: 0001_crypto_init
Revises:
Create Date: 2026-05-26 15:00:00 UTC

Tables:
  - crypto.algorithm (global catalogue; no tenant_id)
  - crypto.tenant_algorithm_policy (per-tenant overrides)
  - crypto.kek (key encryption key metadata)
  - crypto.kek_history (state-machine audit log)
  - crypto.outbox (transactional event publication)

RLS pattern:
  - algorithm: NO RLS (global catalogue).
  - tenant_algorithm_policy: standard tenant RLS.
  - kek / kek_history: standard tenant RLS.
  - outbox: tenant insert + system-all.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_crypto_init"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TENANT_TABLES = ("tenant_algorithm_policy", "kek", "kek_history")


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS crypto")

    # ----------------------------------------------------- algorithm
    op.create_table(
        "algorithm",
        sa.Column("id", sa.String(60), primary_key=True),
        sa.Column(
            "kind",
            sa.String(30),
            nullable=False,
            comment="SYMMETRIC / ASYMMETRIC_SIGN / ASYMMETRIC_ENCRYPT / HASH / HMAC / KDF / PASSWORD_HASH / TLS_SUITE / RNG",
        ),
        sa.Column("family", sa.String(20), nullable=False),
        sa.Column(
            "provider",
            sa.String(20),
            nullable=False,
            comment="openssl / tongsuo / gmssl / hsm / vault",
        ),
        sa.Column("key_size_bits", sa.Integer()),
        sa.Column("fips_140", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("gm_certified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("deprecated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("description", sa.Text()),
        sa.Column("min_compliance_modes", sa.ARRAY(sa.String())),
        sa.Column("metadata", sa.dialects.postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        schema="crypto",
    )
    op.create_index("algorithm_kind_idx", "algorithm", ["kind"], schema="crypto")
    op.create_index("algorithm_provider_idx", "algorithm", ["provider"], schema="crypto")

    # ----------------------------------------------------- tenant_algorithm_policy
    op.create_table(
        "tenant_algorithm_policy",
        sa.Column(
            "tenant_id",
            sa.String(30),
            sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("symmetric_default", sa.String(60), sa.ForeignKey("crypto.algorithm.id")),
        sa.Column("sign_default", sa.String(60)),
        sa.Column("hash_default", sa.String(60)),
        sa.Column("password_hash_default", sa.String(60)),
        sa.Column("locked_by_compliance", sa.ARRAY(sa.String())),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("updated_by", sa.String(30)),
        schema="crypto",
    )

    # ----------------------------------------------------- kek
    op.create_table(
        "kek",
        sa.Column("id", sa.String(60), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(30),
            sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("label", sa.String(120), nullable=False),
        sa.Column(
            "purpose",
            sa.String(30),
            nullable=False,
            comment="FIELD_ENCRYPT / AUDIT_HMAC / JWT_SIGN / FILE_ENCRYPT",
        ),
        sa.Column(
            "algorithm_id",
            sa.String(60),
            sa.ForeignKey("crypto.algorithm.id"),
            nullable=False,
        ),
        sa.Column("vault_path", sa.String(255), nullable=False),
        sa.Column("pkcs11_label", sa.String(120)),
        sa.Column("current_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("min_decryption_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("auto_rotate_days", sa.Integer(), nullable=False, server_default="90"),
        sa.Column(
            "last_rotated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "status",
            sa.String(30),
            nullable=False,
            server_default="ACTIVE",
            comment="ACTIVE / SUSPENDED / MARKED_FOR_DESTRUCTION / DESTROYED",
        ),
        sa.Column("destruction_scheduled_at", sa.DateTime(timezone=True)),
        sa.Column("destruction_marked_by", sa.String(30)),
        sa.Column("destruction_marked_reason", sa.Text()),
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
        sa.Column("created_by", sa.String(30)),
        schema="crypto",
    )
    op.create_unique_constraint(
        "uq_kek_tenant_label", "kek", ["tenant_id", "label"], schema="crypto",
    )
    op.create_index("kek_tenant_idx", "kek", ["tenant_id"], schema="crypto")
    op.execute(
        "CREATE INDEX kek_status_idx ON crypto.kek (status) WHERE status != 'ACTIVE'"
    )

    # ----------------------------------------------------- kek_history
    op.create_table(
        "kek_history",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(30), nullable=False),
        sa.Column("kek_id", sa.String(60), nullable=False),
        sa.Column(
            "changed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("changed_by", sa.String(30), nullable=False),
        sa.Column(
            "transition",
            sa.String(60),
            nullable=False,
            comment="CREATED / ROTATED / SUSPENDED / RESUMED / MARKED_FOR_DESTRUCTION / DESTRUCTION_ABORTED / DESTROYED",
        ),
        sa.Column("from_status", sa.String(30)),
        sa.Column("to_status", sa.String(30)),
        sa.Column("reason", sa.Text()),
        sa.Column("approver_user_id", sa.String(30)),
        sa.Column("audit_event_id", sa.String(30)),
        schema="crypto",
    )
    op.create_index(
        "kekh_kek_time_idx", "kek_history", ["kek_id", "changed_at"], schema="crypto",
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
        schema="crypto",
    )
    op.create_index(
        "ix_crypto_outbox_unpublished", "outbox", ["published_at", "created_at"], schema="crypto",
    )

    # ----------------------------------------------------- RLS
    for tbl in _TENANT_TABLES:
        op.execute(f'ALTER TABLE crypto."{tbl}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE crypto."{tbl}" FORCE ROW LEVEL SECURITY')
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
                f'CREATE POLICY {policy_name} ON crypto."{tbl}" '
                f"FOR {cmd} TO app_user, app_admin {clauses}"
            )
        op.execute(
            f'CREATE POLICY admin_all ON crypto."{tbl}" '
            f"FOR ALL TO app_admin "
            f"USING (current_setting('app.actor', true) = 'ADMIN') "
            f"WITH CHECK (current_setting('app.actor', true) = 'ADMIN')"
        )

    # algorithm: no RLS (global catalogue)
    op.execute("GRANT SELECT ON crypto.algorithm TO app_user, app_admin, app_observability")

    # outbox RLS
    op.execute("ALTER TABLE crypto.outbox ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE crypto.outbox FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY outbox_tenant_insert ON crypto.outbox "
        "FOR INSERT TO app_user, app_admin "
        "WITH CHECK ("
        "  tenant_id IS NULL OR tenant_id = current_setting('app.tenant_id', true)"
        ")"
    )
    op.execute(
        "CREATE POLICY outbox_tenant_select ON crypto.outbox "
        "FOR SELECT TO app_user, app_admin "
        "USING (tenant_id = current_setting('app.tenant_id', true))"
    )
    op.execute(
        "CREATE POLICY outbox_system_all ON crypto.outbox "
        "FOR ALL TO app_observability, app_admin "
        "USING (current_setting('app.actor', true) = 'SYSTEM') "
        "WITH CHECK (current_setting('app.actor', true) = 'SYSTEM')"
    )

    # ----------------------------------------------------- grants
    op.execute("GRANT USAGE ON SCHEMA crypto TO app_user, app_admin, app_observability")
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA crypto "
        "TO app_user, app_admin"
    )
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA crypto TO app_observability")
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA crypto "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user, app_admin"
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA crypto "
        "GRANT SELECT ON TABLES TO app_observability"
    )
    # Sequences (e.g. kek_history.id is BIGSERIAL)
    op.execute(
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA crypto TO app_user, app_admin"
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA crypto "
        "GRANT USAGE, SELECT ON SEQUENCES TO app_user, app_admin"
    )


def downgrade() -> None:
    op.execute("DROP SCHEMA IF EXISTS crypto CASCADE")
