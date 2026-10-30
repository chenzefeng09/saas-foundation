"""index ephemeral tenant keys by expiry for the expired-key purge

The gateway's hourly purge job hard-deletes ephemeral keys that expired more
than the grace period ago, oldest first, in batches. A partial index on
``expires_at`` over ``ephemeral IS TRUE`` rows lets each batch read only the
rows it deletes instead of scanning the table; long-lived keys never enter it.

Built without CONCURRENTLY, like the other indexes in these migrations: the
build's SHARE lock holds back only writes (minting, revoking), not key
resolution, and only for as long as one scan of the table takes.

Revision ID: 0005_ephemeral_key_purge_idx
Revises: 0004_ephemeral_run_keys
Create Date: 2026-10-30 00:00:00 UTC
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_ephemeral_key_purge_idx"
down_revision: str | None = "0004_ephemeral_run_keys"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "llmk_ephemeral_expires_idx",
        "llm_tenant_key",
        ["expires_at"],
        schema="llm_gateway",
        postgresql_where=sa.text("ephemeral IS TRUE"),
    )


def downgrade() -> None:
    op.drop_index("llmk_ephemeral_expires_idx", table_name="llm_tenant_key", schema="llm_gateway")
