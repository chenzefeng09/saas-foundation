"""org management permission catalog

Revision ID: 0006_org_management_perms
Revises: 0005_authz_self_manage_perms
Create Date: 2026-06-14 00:00:00 UTC

Adds the two organisation-structure management permissions to
authz.permission_definition (global catalog; no RLS) and back-fills the
``org.read`` / ``org.manage`` tokens onto every existing tenant_admin role so
already-provisioned tenants gain the capability.

Actions catalogued
------------------
org.read:    view org units / teams / members
org.manage:  create / update / delete org units, teams, members

These are deliberately granted to tenant_admin as *specific* tokens (not
``org.*``).  foundation-org has no per-user authorization of its own (it only
verifies an actor is present), so the BFF guard is the authoritative
enforcement point: a tenant_admin holding these tokens may manage org structure
within its own tenant; a cross-tenant operation still requires platform.admin.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_org_management_perms"
down_revision: str | None = "0005_authz_self_manage_perms"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# ---------------------------------------------------------------------------
# Canonical permission list
# id convention: "<service>.<resource_type>.<action>"
# service = first dot-segment of the full action string.
# ---------------------------------------------------------------------------
_PERMISSIONS = [
    {
        # id is the PK that authz ``/check`` resolves by (session.get) AND the
        # exact token a role must hold (_rbac_match does ``action in
        # permissions``).  The BFF guard sends ``action="org.read"`` so id must
        # equal that string — see 0005 where id==token==/check action.
        "id": "org.read",
        "service": "org",
        "resource_type": "org_unit",
        "action": "read",
        "description": (
            "View organisation structure (org units / teams / members). "
            "查看组织架构(组织单元/团队/成员)。"
        ),
    },
    {
        "id": "org.manage",
        "service": "org",
        "resource_type": "org_unit",
        "action": "manage",
        "description": (
            "Manage organisation structure (create / update / delete org "
            "units, teams, members). 管理组织架构(创建/修改/删除组织单元、团队、成员)。"
        ),
    },
]

# Tokens back-filled onto existing tenant_admin roles.
_TENANT_ADMIN_TOKENS = ["org.read", "org.manage"]


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
                    "risk_level": "MEDIUM",
                    "requires_mfa": False,
                    "requires_4eyes": False,
                    "requires_pam_jit": False,
                    "requires_business_hours": False,
                    "is_system": True,
                }
                for p in _PERMISSIONS
            ],
        )
        # SQLite path is unit-test only; no tenant_admin back-fill needed there.
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
                f"'{r['description']}', 'MEDIUM', false, false, false, false, true)"
                for r in _PERMISSIONS
            )
            + " ON CONFLICT (id) DO NOTHING"
        )
    )

    # ── Postgres: back-fill tokens onto existing tenant_admin roles ─────────
    # Append only the tokens not already present (dedup), preserving idempotency.
    # ``permissions`` is text[]; COALESCE handles a NULL array.
    for token in _TENANT_ADMIN_TOKENS:
        op.execute(
            sa.text(  # nosemgrep: avoid-sqlalchemy-text  # DDL migration; token is a module-level constant, no user input
                "UPDATE authz.role "
                "SET permissions = array_append(COALESCE(permissions, ARRAY[]::text[]), "
                f"'{token}') "
                f"WHERE name = 'tenant_admin' AND NOT ('{token}' = ANY(COALESCE(permissions, ARRAY[]::text[])))"
            )
        )


def downgrade() -> None:
    if _is_sqlite():
        ids = ", ".join(f"'{p['id']}'" for p in _PERMISSIONS)
        op.execute(
            sa.text(f"DELETE FROM authz.permission_definition WHERE id IN ({ids})")  # nosemgrep: avoid-sqlalchemy-text  # DDL migration; ids are module-level constants
        )
        return

    # Remove the back-filled tokens from tenant_admin roles.
    for token in _TENANT_ADMIN_TOKENS:
        op.execute(
            sa.text(  # nosemgrep: avoid-sqlalchemy-text  # DDL migration; token is a module-level constant, no user input
                "UPDATE authz.role "
                f"SET permissions = array_remove(permissions, '{token}') "
                "WHERE name = 'tenant_admin'"
            )
        )

    ids = ", ".join(f"'{p['id']}'" for p in _PERMISSIONS)
    op.execute(
        sa.text(f"DELETE FROM authz.permission_definition WHERE id IN ({ids})")  # nosemgrep: avoid-sqlalchemy-text  # DDL migration; ids are module-level constants
    )
