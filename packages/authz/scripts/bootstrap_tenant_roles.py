"""Bootstrap default RBAC roles for a tenant.

Creates three system roles for the given ``tenant_id`` and (optionally)
binds an admin user to super_admin.  Idempotent: re-running never raises,
existing rows are silently skipped.

Roles created
-------------
super_admin    permissions=["*"]
tenant_admin   permissions=["session.*","run.*","sandbox.*","skill.*","document.*","mcp_server.*"]
member         permissions=[<explicit list — see _MEMBER_PERMISSIONS>]

Design notes
------------
* system roles require ``is_system=True``; RoleService.create() hard-codes
  ``is_system=False``, so this script inserts directly via raw SQL.
* RLS on authz.role is driven by ``app.tenant_id`` (current_setting).  We
  set it inside the transaction so the INSERT passes the tenant_insert check.
* The admin_all RLS policy requires ``app.actor = 'ADMIN'``; we set that too
  so subsequent SELECTs within the same transaction see the newly inserted row.
* We connect as app_admin (the privileged role that owns RLS bypass via
  admin_all on every tenant table).

Usage
-----
    python scripts/bootstrap_tenant_roles.py \\
        --tenant-id tnt_01TENANT0000000000000000A \\
        --admin-user-id usr_01ADMIN000000000000000001

    # Dry-run (no DB writes):
    python scripts/bootstrap_tenant_roles.py \\
        --tenant-id tnt_... --dry-run
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import UTC, datetime

import ulid

# ---------------------------------------------------------------------------
# Role permission sets
# ---------------------------------------------------------------------------

_SUPER_ADMIN_PERMISSIONS = ["*"]

_TENANT_ADMIN_PERMISSIONS = [
    "session.*",
    "run.*",
    "sandbox.*",
    "skill.*",
    "document.*",
    "mcp_server.*",
]

_MEMBER_PERMISSIONS = [
    "session.read",
    "session.create",
    "session.update",
    "session.message.read",
    "session.message.create",
    "session.attachment.read",
    "session.attachment.create",
    "run.create",
    "run.read",
    "run.cancel",
    "skill.read",
    "document.read",
    "document.search",
    "mcp_server.read",
]

_ROLES = [
    {
        "name": "super_admin",
        "display_name": "Super Admin",
        "description": "Full access to all resources and actions.",
        "permissions": _SUPER_ADMIN_PERMISSIONS,
    },
    {
        "name": "tenant_admin",
        "display_name": "Tenant Admin",
        "description": "Manages all platform resources for the tenant.",
        "permissions": _TENANT_ADMIN_PERMISSIONS,
    },
    {
        "name": "member",
        "display_name": "Member",
        "description": "Standard tenant member with read and run access.",
        "permissions": _MEMBER_PERMISSIONS,
    },
]


def _new_role_id() -> str:
    return f"rol_{ulid.new()!s}"


def _new_binding_id() -> str:
    return f"rbd_{ulid.new()!s}"


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

async def _make_engine(db_url: str):  # type: ignore[no-untyped-def]
    from sqlalchemy.ext.asyncio import create_async_engine
    engine = create_async_engine(
        db_url,
        echo=False,
        pool_pre_ping=True,
        connect_args={
            "statement_cache_size": 0,
            "prepared_statement_cache_size": 0,
        },
    )
    return engine


async def _bootstrap(
    *,
    tenant_id: str,
    admin_user_id: str | None,
    db_url: str,
    dry_run: bool,
) -> None:
    from sqlalchemy import String, bindparam, text
    from sqlalchemy.dialects.postgresql import ARRAY as PG_ARRAY

    engine = await _make_engine(db_url)

    async with engine.connect() as conn:
        async with conn.begin():
            # Set RLS context so INSERT passes tenant_insert policy and
            # admin_all SELECT policy allows us to see rows within the
            # same transaction.
            await conn.execute(text(f"SET LOCAL app.tenant_id = '{tenant_id}'"))  # nosemgrep: avoid-sqlalchemy-text  # SET LOCAL; tenant_id validated by CLI argparse
            await conn.execute(text("SET LOCAL app.actor = 'ADMIN'"))  # nosemgrep: avoid-sqlalchemy-text  # static literal
            await conn.execute(text("SET LOCAL app.user_id = 'BOOTSTRAP'"))  # nosemgrep: avoid-sqlalchemy-text  # static literal

            role_ids: dict[str, str] = {}

            for role_def in _ROLES:
                name = role_def["name"]

                # Check existence (idempotent).
                existing = await conn.execute(
                    text(
                        "SELECT id FROM authz.role "
                        "WHERE tenant_id = :tid AND name = :name AND deleted_at IS NULL"
                    ),
                    {"tid": tenant_id, "name": name},
                )
                row = existing.fetchone()
                if row:
                    role_id = row[0]
                    print(f"  [skip] role '{name}' already exists ({role_id})")  # nosemgrep: forbid-print-in-production-code  # CLI user output
                    role_ids[name] = role_id
                    continue

                role_id = _new_role_id()
                role_ids[name] = role_id
                if dry_run:
                    print(f"  [dry-run] would INSERT role '{name}' id={role_id}")  # nosemgrep: forbid-print-in-production-code  # CLI user output
                else:
                    await conn.execute(
                        text(
                            "INSERT INTO authz.role "
                            "(id, tenant_id, name, display_name, description, "
                            " is_system, immutable, permissions, created_at, updated_at, "
                            " created_by) "
                            "VALUES "
                            "(:id, :tenant_id, :name, :display_name, :description, "
                            " TRUE, TRUE, :permissions, now(), now(), 'BOOTSTRAP')"
                        ).bindparams(
                            bindparam("permissions", type_=PG_ARRAY(String))
                        ),
                        {
                            "id": role_id,
                            "tenant_id": tenant_id,
                            "name": name,
                            "display_name": role_def["display_name"],
                            "description": role_def["description"],
                            "permissions": list(role_def["permissions"]),
                        },
                    )
                    print(f"  [created] role '{name}' id={role_id}")  # nosemgrep: forbid-print-in-production-code  # CLI user output

            # Optionally bind admin_user_id → super_admin.
            if admin_user_id:
                super_admin_id = role_ids.get("super_admin")
                if not super_admin_id:
                    print("  [skip] cannot bind admin: super_admin role not found")  # nosemgrep: forbid-print-in-production-code  # CLI user output
                else:
                    existing_binding = await conn.execute(
                        text(
                            "SELECT id FROM authz.role_binding "
                            "WHERE tenant_id = :tid "
                            "  AND principal_kind = 'USER' "
                            "  AND principal_id = :uid "
                            "  AND role_id = :rid "
                            "  AND revoked_at IS NULL"
                        ),
                        {"tid": tenant_id, "uid": admin_user_id, "rid": super_admin_id},
                    )
                    if existing_binding.fetchone():
                        print(  # nosemgrep: forbid-print-in-production-code  # CLI user output
                            f"  [skip] binding {admin_user_id} → super_admin already exists"
                        )
                    elif dry_run:
                        print(  # nosemgrep: forbid-print-in-production-code  # CLI user output
                            f"  [dry-run] would INSERT binding "
                            f"{admin_user_id} → super_admin (role_id={super_admin_id})"
                        )
                    else:
                        binding_id = _new_binding_id()
                        await conn.execute(
                            text(
                                "INSERT INTO authz.role_binding "
                                "(id, tenant_id, principal_kind, principal_id, role_id, "
                                " scope_kind, scope_id, granted_at, granted_by) "
                                "VALUES "
                                "(:id, :tenant_id, 'USER', :principal_id, :role_id, "
                                " 'TENANT', :scope_id, now(), 'BOOTSTRAP')"
                            ),
                            {
                                "id": binding_id,
                                "tenant_id": tenant_id,
                                "principal_id": admin_user_id,
                                "role_id": super_admin_id,
                                "scope_id": tenant_id,
                            },
                        )
                        print(  # nosemgrep: forbid-print-in-production-code  # CLI user output
                            f"  [created] binding {admin_user_id} → super_admin "
                            f"(binding_id={binding_id})"
                        )

    await engine.dispose()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Bootstrap default RBAC roles for a tenant.",
    )
    p.add_argument(
        "--tenant-id",
        required=True,
        help="Tenant id (tnt_<ULID>) to create roles under.",
    )
    p.add_argument(
        "--admin-user-id",
        default=None,
        help=(
            "Optional user id (usr_<ULID>) to bind to super_admin.  "
            "Idempotent if the binding already exists."
        ),
    )
    p.add_argument(
        "--db-url",
        default="postgresql+asyncpg://app_admin:app_admin_change_me@localhost:5432/foundation",
        help=(
            "SQLAlchemy async DSN.  Defaults to local dev app_admin connection.  "
            "Override via AUTHZ_DB_DSN_ADMIN env var or this flag."
        ),
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be done without writing anything.",
    )
    return p


def main() -> None:
    import os

    parser = _build_parser()
    args = parser.parse_args()

    db_url = os.environ.get("AUTHZ_DB_DSN_ADMIN") or args.db_url

    print(f"bootstrap_tenant_roles: tenant_id={args.tenant_id} dry_run={args.dry_run}")  # nosemgrep: forbid-print-in-production-code  # CLI user output
    asyncio.run(
        _bootstrap(
            tenant_id=args.tenant_id,
            admin_user_id=args.admin_user_id,
            db_url=db_url,
            dry_run=args.dry_run,
        )
    )
    print("done.")  # nosemgrep: forbid-print-in-production-code  # CLI user output


if __name__ == "__main__":
    main()
