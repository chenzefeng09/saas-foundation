"""model default-preference permission catalog

Revision ID: 0008_model_perms
Revises: 0007_quota_read_perm
Create Date: 2026-06-14 00:00:00 UTC

Adds the tenant-scoped default-model preference permissions to
authz.permission_definition (global catalog; no RLS) and back-fills the
``model.read`` + ``model.admin`` tokens onto every existing tenant_admin role so
already-provisioned tenants gain the capability.

Actions catalogued
------------------
model.read:   view the tenant's own default-model preferences (tenant-defaults)
model.admin:  manage the tenant's own default-model preferences (tenant-defaults)

This is the first model-management round that splits the surface by *scope*:

  • Tenant-level (delegated to tenant_admin) — read/write the tenant's own
    default-model preferences.  ``model.read`` for the GET/resolve lanes,
    ``model.admin`` for the PUT.  These are granted as *specific* tokens (NOT
    ``model.*``) so a tenant_admin can pick their tenant's defaults but never
    touches the platform provider directory.
  • Platform-level (stays super_admin only) — the shared LLM provider/endpoint
    directory (providers CRUD) and the probe diagnostic.  These remain gated by
    ``platform.admin``; no token is granted to tenant_admin for them (provider
    POST/PATCH/DELETE and probe).

The provider *read* lane (GET /providers) is downgraded to ``model.read`` at the
BFF so a tenant_admin can enumerate the model catalogue needed to choose their
defaults, while provider mutations stay super_admin-only.

llm-gateway authorizes ``PUT /tenant-defaults`` by ``ctx.actor in {ADMIN,
SERVICE}`` and scopes the write to ``ctx.tenant_id`` (the caller's own tenant),
so an ADMIN actor merely unlocks the "may write tenant defaults" capability — it
is NOT an RLS cross-tenant bypass.  The authoritative cross-tenant gate is the
BFF guard (``require_tenant_rbac_bff`` rejects a foreign ``?tenant_id=`` without
``platform.admin``), so a tenant_admin is confined to their own tenant.

As in 0006/0007: id == granted token == /check action — hence the bare dotted
ids ``model.read`` / ``model.admin`` (not composites, which would make /check
404 PERMISSION_UNKNOWN).  The ``action`` column stores the bare verb.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008_model_perms"
down_revision: str | None = "0007_quota_read_perm"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# ---------------------------------------------------------------------------
# Canonical permission list
# id is the PK that authz ``/check`` resolves by (session.get) AND the exact
# token a role must hold (_rbac_match does ``action in permissions``).  The BFF
# guard sends ``action="model.read"`` / ``"model.admin"`` so id must equal that
# string — see 0007 where id==token==/check action.  ``action`` column stores
# the bare verb.  ``service`` follows 0007's resource-team convention (billing
# there); here the surface is the LLM gateway, so service="llm_gateway".
# ---------------------------------------------------------------------------
_PERMISSIONS = [
    {
        "id": "model.read",
        "service": "llm_gateway",
        "resource_type": "model",
        "action": "read",
        "description": (
            "View the tenant own default-model preferences and provider catalogue. "
            "查看本租户默认模型偏好。"
        ),
    },
    {
        "id": "model.admin",
        "service": "llm_gateway",
        "resource_type": "model",
        "action": "admin",
        "description": (
            "Manage the tenant own default-model preferences. "
            "管理本租户默认模型偏好。"
        ),
    },
]

# Tokens back-filled onto existing tenant_admin roles.
_TENANT_ADMIN_TOKENS = ["model.read", "model.admin"]


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
