"""default model refactor — move 'default' from provider to tenant/user level

Revision ID: 0002_default_model_refactor
Revises: 0001_llm_gateway_init
Create Date: 2026-06-09 00:00:00 UTC
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_default_model_refactor"
down_revision: str | None = "0001_llm_gateway_init"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_NEW_TABLES = ("tenant_default_model", "user_model_preference")


def _enable_tenant_rls(table: str) -> None:
    op.execute(f'ALTER TABLE llm_gateway."{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE llm_gateway."{table}" FORCE ROW LEVEL SECURITY')
    tenant_match = "tenant_id = current_setting('app.tenant_id', true)"
    for cmd in ("SELECT", "INSERT", "UPDATE", "DELETE"):
        policy_name = f"tenant_{cmd.lower()}"
        if cmd == "INSERT":
            clauses = f"WITH CHECK ({tenant_match})"
        elif cmd == "UPDATE":
            clauses = f"USING ({tenant_match}) WITH CHECK ({tenant_match})"
        else:
            clauses = f"USING ({tenant_match})"
        op.execute(
            f'CREATE POLICY {policy_name} ON llm_gateway."{table}" '
            f"FOR {cmd} TO app_user, app_admin {clauses}"
        )
    op.execute(
        f'CREATE POLICY admin_all ON llm_gateway."{table}" '
        f"FOR ALL TO app_admin "
        f"USING (current_setting('app.actor', true) = 'ADMIN') "
        f"WITH CHECK (current_setting('app.actor', true) = 'ADMIN')"
    )


def upgrade() -> None:
    op.create_table(
        "tenant_default_model",
        sa.Column("id", sa.String(40), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(30),
            sa.ForeignKey("tenant.tenant.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "purpose",
            sa.String(30),
            nullable=False,
            comment="llm | embedding | rerank | tts | stt",
        ),
        sa.Column("model_id", sa.String(100), nullable=False),
        sa.Column("provider_id", sa.String(40), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("created_by", sa.String(30), nullable=True),
        sa.UniqueConstraint(
            "tenant_id", "purpose", name="uq_tenant_default_purpose"
        ),
        schema="llm_gateway",
    )
    op.create_index(
        "ttdm_tenant_idx", "tenant_default_model", ["tenant_id"], schema="llm_gateway"
    )

    op.create_table(
        "user_model_preference",
        sa.Column("id", sa.String(40), primary_key=True),
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
        sa.Column("purpose", sa.String(30), nullable=False),
        sa.Column("model_id", sa.String(100), nullable=False),
        sa.Column("provider_id", sa.String(40), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "tenant_id", "user_id", "purpose", name="uq_user_pref_purpose"
        ),
        schema="llm_gateway",
    )
    op.create_index(
        "ump_tenant_user_idx",
        "user_model_preference",
        ["tenant_id", "user_id"],
        schema="llm_gateway",
    )

    for table in _NEW_TABLES:
        _enable_tenant_rls(table)

    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON "
        "llm_gateway.tenant_default_model, llm_gateway.user_model_preference "
        "TO app_user, app_admin"
    )


def downgrade() -> None:
    op.drop_table("user_model_preference", schema="llm_gateway")
    op.drop_table("tenant_default_model", schema="llm_gateway")
