"""add unique index on org_unit(tenant_id, parent_id, name)

Revision ID: 0002_org_unit_unique_parent_name
Revises: 0001_org_init
Create Date: 2026-06-10 12:00:00 UTC

Prevents duplicate department names under the same parent within a tenant.
Uses ``postgresql_nulls_not_distinct`` so top-level units (parent_id IS NULL)
are also covered.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0002_org_unit_unique_parent_name"
down_revision: str | None = "0001_org_init"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "uq_org_unit_parent_name",
        "org_unit",
        ["tenant_id", "parent_id", "name"],
        unique=True,
        schema="org",
        postgresql_nulls_not_distinct=True,
    )


def downgrade() -> None:
    op.drop_index(
        "uq_org_unit_parent_name",
        table_name="org_unit",
        schema="org",
    )
