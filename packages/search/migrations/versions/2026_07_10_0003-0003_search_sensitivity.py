"""Add mandatory sensitivity fields to the search source of truth.

Revision ID: 0003_search_sensitivity
Revises: 0002_search_acl_fields
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003_search_sensitivity"
down_revision = "0002_search_acl_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "search_index",
        sa.Column("sensitivity", sa.String(2), nullable=False, server_default="L3"),
        schema="search",
    )
    op.add_column(
        "search_index",
        sa.Column("sensitivity_rank", sa.SmallInteger(), nullable=False, server_default="3"),
        schema="search",
    )
    op.create_check_constraint(
        "ck_search_sensitivity",
        "search_index",
        "sensitivity IN ('L1','L2','L3','L4','L5')",
        schema="search",
    )
    op.create_check_constraint(
        "ck_search_sensitivity_rank",
        "search_index",
        "sensitivity_rank BETWEEN 1 AND 5",
        schema="search",
    )
    op.create_check_constraint(
        "ck_search_sensitivity_rank_match",
        "search_index",
        "sensitivity_rank = CASE sensitivity "
        "WHEN 'L1' THEN 1 WHEN 'L2' THEN 2 WHEN 'L3' THEN 3 "
        "WHEN 'L4' THEN 4 WHEN 'L5' THEN 5 END",
        schema="search",
    )
    op.create_index(
        "si_tenant_sensitivity_idx",
        "search_index",
        ["tenant_id", "sensitivity_rank"],
        schema="search",
    )


def downgrade() -> None:
    op.drop_index("si_tenant_sensitivity_idx", table_name="search_index", schema="search")
    op.drop_constraint("ck_search_sensitivity_rank_match", "search_index", schema="search")
    op.drop_constraint("ck_search_sensitivity_rank", "search_index", schema="search")
    op.drop_constraint("ck_search_sensitivity", "search_index", schema="search")
    op.drop_column("search_index", "sensitivity_rank", schema="search")
    op.drop_column("search_index", "sensitivity", schema="search")
