"""workspace permission catalog

Revision ID: 0009_workspace_perms
Revises: 0008_model_perms
Create Date: 2026-07-16 00:00:00 UTC

Adds the ``workspace`` resource-type permissions to authz.permission_definition
(global catalog; no RLS) and back-fills the grants onto every existing role so
already-provisioned tenants gain the capability:

  • member       → ``workspace.read`` + ``workspace.manage`` (explicit tokens,
                   same tier as session.read / run.create — a standard member
                   who can create/use sessions can also use workspaces).
  • tenant_admin → ``workspace.*`` wildcard (matches the existing session.* /
                   run.* / app.* pattern).
  • super_admin  → already covered by the bare ``*`` wildcard; no change.

These back the new session-orchestrator workspace endpoints:
  • require_permission("workspace.read",   "workspace")  — GET lanes
  • require_permission("workspace.manage", "workspace")  — POST/PATCH/DELETE +
    file upload/delete lanes

Actions catalogued
------------------
workspace.read:   list or retrieve workspaces and their files
workspace.manage: create/update/delete a workspace and manage its files

As in 0005-0008: id == granted token == /check action.  authz ``/check`` resolves
the permission by id (``session.get(PermissionDefinition, action)``) and
``_rbac_match`` does ``action in permissions`` (or wildcard), so the bare dotted
ids ``workspace.read`` / ``workspace.manage`` must equal the /check action string
(a composite id would make /check raise PERMISSION_UNKNOWN).  The ``action``
column stores the bare verb.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009_workspace_perms"
down_revision: str | None = "0008_model_perms"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# ---------------------------------------------------------------------------
# Canonical permission list
# id is the PK authz ``/check`` resolves by AND the exact token a role must hold.
# ``action`` column stores the bare verb.  ``service`` == resource team, here the
# session-orchestrator workspace surface, so service="workspace".
# ---------------------------------------------------------------------------
_PERMISSIONS = [
    {
        "id": "workspace.read",
        "service": "workspace",
        "resource_type": "workspace",
        "action": "read",
        "description": "List or retrieve workspaces and their files.",
    },
    {
        "id": "workspace.manage",
        "service": "workspace",
        "resource_type": "workspace",
        "action": "manage",
        "description": (
            "Create, update, or delete a workspace and manage its files "
            "(upload / delete)."
        ),
    },
]

# Tokens back-filled onto existing roles, keyed by role name.
_ROLE_TOKENS = {
    "member": ["workspace.read", "workspace.manage"],
    "tenant_admin": ["workspace.*"],
}


def _is_sqlite() -> bool:
    """Detect SQLite (used in unit tests) to switch syntax / skip PG-only DML."""
    try:
        bind = op.get_bind()
        return bind.dialect.name == "sqlite"
    except Exception:  # noqa: BLE001
        return False


def upgrade() -> None:
    is_sqlite = _is_sqlite()

    if is_sqlite:
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
        op.bulk_insert(
            perm_table,
            [
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
            ],
        )
        # SQLite path is unit-test only; no role back-fill needed there.
        return

    # ── Postgres: insert permission definitions (idempotent) ────────────────
    op.execute(
        sa.text(  # nosemgrep: avoid-sqlalchemy-text  # DDL migration; all values module-level constants, no user input
            "INSERT INTO authz.permission_definition "
            "(id, service, resource_type, action, description, risk_level, "
            " requires_mfa, requires_4eyes, requires_pam_jit, requires_business_hours, is_system) "
            "VALUES "
            + ", ".join(
                f"('{r['id']}', '{r['service']}', '{r['resource_type']}', '{r['action']}', "
                f"'{r['description']}', 'LOW', false, false, false, false, true)"
                for r in _PERMISSIONS
            )
            + " ON CONFLICT (id) DO NOTHING"
        )
    )

    # ── Postgres: back-fill tokens onto existing roles ──────────────────────
    # Append only the tokens not already present (dedup), preserving idempotency.
    # ``permissions`` is text[]; COALESCE handles a NULL array.  Append-only:
    # never removes or rewrites existing tokens.
    for role_name, tokens in _ROLE_TOKENS.items():
        for token in tokens:
            op.execute(
                sa.text(  # nosemgrep: avoid-sqlalchemy-text  # DDL migration; role_name/token are module-level constants, no user input
                    "UPDATE authz.role "
                    "SET permissions = array_append(COALESCE(permissions, ARRAY[]::text[]), "
                    f"'{token}') "
                    f"WHERE name = '{role_name}' "
                    f"AND NOT ('{token}' = ANY(COALESCE(permissions, ARRAY[]::text[])))"
                )
            )


def downgrade() -> None:
    if _is_sqlite():
        ids = ", ".join(f"'{p['id']}'" for p in _PERMISSIONS)
        op.execute(
            sa.text(f"DELETE FROM authz.permission_definition WHERE id IN ({ids})")  # nosemgrep: avoid-sqlalchemy-text  # DDL migration; ids are module-level constants
        )
        return

    # Remove the back-filled tokens from their roles.
    for role_name, tokens in _ROLE_TOKENS.items():
        for token in tokens:
            op.execute(
                sa.text(  # nosemgrep: avoid-sqlalchemy-text  # DDL migration; role_name/token are module-level constants, no user input
                    "UPDATE authz.role "
                    f"SET permissions = array_remove(permissions, '{token}') "
                    f"WHERE name = '{role_name}'"
                )
            )

    ids = ", ".join(f"'{p['id']}'" for p in _PERMISSIONS)
    op.execute(
        sa.text(f"DELETE FROM authz.permission_definition WHERE id IN ({ids})")  # nosemgrep: avoid-sqlalchemy-text  # DDL migration; ids are module-level constants
    )
