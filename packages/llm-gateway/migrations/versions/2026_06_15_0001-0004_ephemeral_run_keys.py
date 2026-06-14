"""add run-scoped ephemeral-key columns to llm_tenant_key

Security hardening: a sandbox now receives a short-lived, run-scoped virtual
key instead of the long-lived tenant key. The resolver rejects a key once
``expires_at`` is in the past, so a leaked key only bills the tenant for ~one
run's lifetime.

Backwards compatible: all three columns are nullable / defaulted, and a NULL
``expires_at`` means a perpetual key — every pre-existing tenant key keeps
working unchanged. RLS already covers ``llm_tenant_key`` at the table level, so
the new columns inherit the existing tenant policies without further changes.

Revision ID: 0004_ephemeral_run_keys
Revises: 0003_usage_cache_tokens
Create Date: 2026-06-15 00:00:00 UTC
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_ephemeral_run_keys"
down_revision: str | None = "0003_usage_cache_tokens"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "llm_tenant_key",
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        schema="llm_gateway",
    )
    op.add_column(
        "llm_tenant_key",
        sa.Column("run_id", sa.String(length=64), nullable=True),
        schema="llm_gateway",
    )
    op.add_column(
        "llm_tenant_key",
        sa.Column(
            "ephemeral",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        schema="llm_gateway",
    )


def downgrade() -> None:
    op.drop_column("llm_tenant_key", "ephemeral", schema="llm_gateway")
    op.drop_column("llm_tenant_key", "run_id", schema="llm_gateway")
    op.drop_column("llm_tenant_key", "expires_at", schema="llm_gateway")
