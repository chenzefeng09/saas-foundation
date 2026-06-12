"""large-attachment permission catalog

Revision ID: 0004_large_attachment_permission
Revises: 0003_app_registry_permissions
Create Date: 2026-06-12 00:00:00 UTC

Inserts the large-attachment permission definition into
authz.permission_definition (global catalog; no RLS).

Actions catalogued
------------------
session.attachment.large: create
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_large_attachment_permission"
down_revision: str | None = "0003_app_registry_permissions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# ---------------------------------------------------------------------------
# Canonical permission list
# id convention: "<service>.<resource_type>.<action>" or "<service>.<action>"
# service = first dot-segment of the full action string.
# ---------------------------------------------------------------------------
_PERMISSIONS = [
    # ── session.attachment.large ─────────────────────────────────────────────
    {
        "id": "session.attachment.large.create",
        "service": "session",
        "resource_type": "session.attachment.large",
        "action": "create",
        "description": (
            "Upload a large file attachment "
            "(triggers large-memory sandbox)."
        ),
    },
]


def upgrade() -> None:
    perm_table = sa.table(
        "permission_definition",
        sa.column("id", sa.String),
        sa.column("service", sa.String),
        sa.column("resource_type", sa.String),
        sa.column("action", sa.String),
        sa.column("description", sa.Text),
        sa.column("risk_level", sa.String),
        sa.column("requires_mfa", sa.Boolean),
        sa.column("requires_4eyes", sa.Boolean),
        sa.column("requires_pam_jit", sa.Boolean),
        sa.column("requires_business_hours", sa.Boolean),
        sa.column("is_system", sa.Boolean),
        schema="authz",
    )

    rows = [
        {
            "id": p["id"],
            "service": p["service"],
            "resource_type": p["resource_type"],
            "action": p["action"],
            "description": p["description"],
            "risk_level": "LOW",
            "requires_mfa": False,
            "requires_4eyes": False,
            "requires_pam_jit": False,
            "requires_business_hours": False,
            "is_system": True,
        }
        for p in _PERMISSIONS
    ]

    # Idempotent: skip rows whose id is already present.
    op.execute(
        perm_table.insert().prefix_with("OR IGNORE")
        if _is_sqlite()
        else sa.text(  # nosemgrep: avoid-sqlalchemy-text  # DDL migration; all values are module-level constants, no user input
            "INSERT INTO authz.permission_definition "
            "(id, service, resource_type, action, description, risk_level, "
            " requires_mfa, requires_4eyes, requires_pam_jit, requires_business_hours, is_system) "
            "VALUES "
            + ", ".join(
                f"('{r['id']}', '{r['service']}', '{r['resource_type']}', '{r['action']}', "
                f"'{r['description']}', 'LOW', false, false, false, false, true)"
                for r in rows
            )
            + " ON CONFLICT (id) DO NOTHING"
        )
    )


def _is_sqlite() -> bool:
    """Detect SQLite (used in unit tests) to switch to OR IGNORE syntax."""
    try:
        bind = op.get_bind()
        return bind.dialect.name == "sqlite"
    except Exception:  # noqa: BLE001
        return False


def downgrade() -> None:
    ids = ", ".join(f"'{p['id']}'" for p in _PERMISSIONS)
    op.execute(
        sa.text(f"DELETE FROM authz.permission_definition WHERE id IN ({ids})")  # nosemgrep: avoid-sqlalchemy-text  # DDL migration; ids are module-level permission id constants, no user input
    )
