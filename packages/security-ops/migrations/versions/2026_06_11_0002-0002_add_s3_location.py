"""add s3_location column to scan_run / incident / drill

Storage-v1 Phase 2 §6.2: writes that reference S3 objects must record an
``original_location`` so Phase 4 GC can hard-delete the corresponding objects.
We park the value on the business row (encoded as JSON list of
``{bucket}::{key}``) until soft-delete copies it into recycle_bin.

Revision ID: 0002_security_ops_s3_location
Revises: 0001_security_ops_init
Create Date: 2026-06-11 00:00:00 UTC
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_security_ops_s3_location"
down_revision: str | None = "0001_security_ops_init"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_TABLES = ("scan_run", "incident", "drill")


def upgrade() -> None:
    for table in _TABLES:
        op.add_column(
            table,
            sa.Column("s3_location", sa.Text(), nullable=True),
            schema="security_ops",
        )


def downgrade() -> None:
    for table in _TABLES:
        op.drop_column(table, "s3_location", schema="security_ops")
