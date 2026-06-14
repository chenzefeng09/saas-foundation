"""quota read permission catalog

Revision ID: 0007_quota_read_perm
Revises: 0006_org_management_perms
Create Date: 2026-06-14 00:00:00 UTC

Adds the read-only subscription/quota permission to
authz.permission_definition (global catalog; no RLS) and back-fills the
``quota.read`` token onto every existing tenant_admin role so already-provisioned
tenants gain the capability.

Actions catalogued
------------------
quota.read:  view the tenant's own subscription, plan limits and usage

This is deliberately granted to tenant_admin as a *specific* token (not
``quota.*`` and NOT ``quota.manage``).  This round delegates only read-only
visibility: a tenant_admin may inspect their own subscription / quota / usage,
while subscription mutations (change-plan / cancel / create) and the plan
catalogue definition remain super_admin-only (contract-bound, no self-service).
foundation-billing performs no per-user authorization of its own, so the BFF
guard is the authoritative enforcement point: it sends action="quota.read" to
authz /check, which resolves the permission by id (==token) — hence the id is
the bare dotted token ``quota.read`` (not a composite like
``quota.subscription.read`` which would make /check 404 PERMISSION_UNKNOWN).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007_quota_read_perm"
down_revision: str | None = "0006_org_management_perms"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# ---------------------------------------------------------------------------
# Canonical permission list
# id is the PK that authz ``/check`` resolves by (session.get) AND the exact
# token a role must hold (_rbac_match does ``action in permissions``).  The BFF
# guard sends ``action="quota.read"`` so id must equal that string — see 0006
# where id==token==/check action.  ``action`` column stores the bare verb.
# ---------------------------------------------------------------------------
_PERMISSIONS = [
    {
        "id": "quota.read",
        "service": "billing",
        "resource_type": "subscription",
        "action": "read",
        "description": (
            "View the tenant own subscription, plan limits and usage. "
            "查看本租户订阅配额与用量。"
        ),
    },
]

# Tokens back-filled onto existing tenant_admin roles.
_TENANT_ADMIN_TOKENS = ["quota.read"]


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
