"""add DeepSeek prompt-cache hit/miss token columns to llm_usage_record

Observability only: record cache hit/miss tokens reported by upstream
providers (DeepSeek's ``prompt_cache_hit_tokens`` / ``prompt_cache_miss_tokens``).
Does not touch the billing contract (billing only consumes total_tokens).

Revision ID: 0003_usage_cache_tokens
Revises: 0002_default_model_refactor
Create Date: 2026-06-12 00:00:00 UTC
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_usage_cache_tokens"
down_revision: str | None = "0002_default_model_refactor"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "llm_usage_record",
        sa.Column(
            "prompt_cache_hit_tokens",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
        schema="llm_gateway",
    )
    op.add_column(
        "llm_usage_record",
        sa.Column(
            "prompt_cache_miss_tokens",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
        schema="llm_gateway",
    )


def downgrade() -> None:
    op.drop_column("llm_usage_record", "prompt_cache_miss_tokens", schema="llm_gateway")
    op.drop_column("llm_usage_record", "prompt_cache_hit_tokens", schema="llm_gateway")
