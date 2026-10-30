"""Bootstrap default RBAC roles (and seed role bindings) for a tenant.

Creates three system roles for the given ``tenant_id`` and binds the given
users to them.  Idempotent: re-running never raises and never duplicates rows.

Roles created
-------------
super_admin    permissions=["*"]
tenant_admin   permissions=[<explicit list — see _TENANT_ADMIN_PERMISSIONS>]
member         permissions=[<explicit list — see _MEMBER_PERMISSIONS>]

Seed bindings and revocation
----------------------------
``--bind-user USER_ID=ROLE`` (repeatable), ``--admin-user-id USER_ID`` (same as
``=super_admin``) and ``--service-account-id USER_ID`` (same as ``=member``)
each ask for one TENANT-scoped binding of that user to that role.  For every
such (tenant, user, role) the script looks at *all* existing TENANT-scoped
binding rows, whatever their state:

* an ACTIVE binding exists          → left alone (no duplicate, no update);
* only REVOKED / EXPIRED rows exist → left alone too: someone took that grant
  away on purpose, and re-seeding must not silently hand it back;
* no row at all                     → a new binding is created.

So re-running (dev stacks do on every ``up``) only fills in bindings that never
existed.  To deliberately give a revoked grant back, create a new binding via
the RBAC admin API, or re-run this script once with ``--restore-revoked``.
Either way a *new* binding row is written and the revoked row stays as audit
history.  Bindings to roles that are not seeded are never read or modified.

Design notes
------------
* system roles require ``is_system=True``; RoleService.create() hard-codes
  ``is_system=False``, so this script inserts directly via SQL.
* RLS on authz.role / role_binding is driven by ``app.tenant_id`` and
  ``app.actor``.  We set both (transaction-local) so the INSERTs pass the
  tenant_insert check and the ``admin_all`` policy lets the existence checks
  see every row — revoked ones included.
* We connect as app_admin (the privileged role that owns RLS bypass via
  admin_all on every tenant table).

Usage
-----
    python scripts/bootstrap_tenant_roles.py \\
        --tenant-id tnt_01TENANT0000000000000000A \\
        --admin-user-id usr_01ADMIN000000000000000001 \\
        --bind-user usr_01MEMBER00000000000000001=member

    # Dry-run (no DB writes):
    python scripts/bootstrap_tenant_roles.py \\
        --tenant-id tnt_... --dry-run
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal

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
    "app.*",
    "workspace.*",
    # Self-service RBAC management within the tenant.  Granted as specific tokens
    # (NOT "authz.*") so a tenant_admin can manage roles/bindings but cannot
    # delegate authz management itself — see is_grantable() non-delegation rule.
    "authz.role.manage",
    "authz.binding.manage",
    # Organisation-structure management within the tenant.  foundation-org has no
    # per-user authorization of its own, so the BFF guard is the authoritative
    # enforcement point: it sends action="org.read"/"org.manage" to authz /check,
    # which resolves the permission by id (==token) — hence specific tokens here.
    "org.read",
    "org.manage",
    # Read-only subscription / quota visibility within the tenant.  Granted as a
    # specific token (NOT "quota.*" and NOT "quota.manage"): a tenant_admin may
    # inspect their own subscription / quota / usage, but plan changes and the
    # plan catalogue stay super_admin-only (contract-bound).  foundation-billing
    # has no per-user authorization, so the BFF guard is authoritative: it sends
    # action="quota.read" to authz /check, resolved by id (==token).
    "quota.read",
    # Tenant-scoped default-model preferences (tenant-defaults).  Granted as
    # specific tokens (NOT "model.*"): a tenant_admin may read/write their own
    # tenant's default models, but the shared LLM provider directory (providers
    # CRUD) and the probe diagnostic stay super_admin-only.  llm-gateway scopes
    # the tenant-defaults write to the caller's own tenant, so the BFF guard is
    # authoritative for cross-tenant confinement: it sends action="model.read"/
    # "model.admin" to authz /check, resolved by id (==token).
    "model.read",
    "model.admin",
]

_MEMBER_PERMISSIONS = [
    "session.read",
    "session.create",
    "session.update",
    "session.message.read",
    "session.message.create",
    "session.message.delete",
    "session.attachment.read",
    "session.attachment.create",
    "run.create",
    "run.read",
    "run.cancel",
    "workspace.read",
    "workspace.manage",
    "skill.read",
    "document.read",
    "document.search",
    "mcp_server.read",
    "app.read",
    "app.create",
    "app.update",
    "app.run",
]

_ROLES: list[dict[str, Any]] = [
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
_ROLE_NAMES: tuple[str, ...] = tuple(r["name"] for r in _ROLES)

_TENANT_ID_RE = re.compile(r"^tnt_[0-9A-Z]{26}$")
_USER_ID_RE = re.compile(r"^usr_[0-9A-Z]{26}$")

_SEED_GRANT_REASON = "seed binding (bootstrap_tenant_roles)"
_SERVICE_ACCOUNT_GRANT_REASON = "service account: scheduled App runs"
_RESTORED_SUFFIX = " — restored via --restore-revoked"


def _new_role_id() -> str:
    return f"rol_{ulid.new()!s}"


def _new_binding_id() -> str:
    return f"rbd_{ulid.new()!s}"


def _say(msg: str) -> None:
    print(msg)  # nosemgrep: forbid-print-in-production-code  # CLI user output


# ---------------------------------------------------------------------------
# Seed-binding decision (pure; unit-tested)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SeedBinding:
    """One requested TENANT-scoped binding: ``user_id`` → system role ``role``."""

    user_id: str
    role: str
    grant_reason: str


@dataclass(frozen=True)
class ExistingBindings:
    """How many TENANT-scoped bindings a (tenant, user, role) has, by state.

    States follow CheckService: REVOKED wins, then a past ``expires_at`` is
    EXPIRED, everything else is ACTIVE.
    """

    active: int = 0
    revoked: int = 0
    expired: int = 0


SeedAction = Literal["create", "skip-active", "skip-revoked", "skip-expired"]


def seed_action(existing: ExistingBindings, *, restore_revoked: bool = False) -> SeedAction:
    """Decide what seeding does for one (tenant, user, role).

    Only a pair that has *never* had a binding gets one — unless the operator
    explicitly passes ``restore_revoked``.  A revoked or expired grant was
    taken away on purpose; silently re-creating it on the next ``up`` would
    undo that decision.
    """
    if existing.active:
        return "skip-active"
    if restore_revoked:
        return "create"
    if existing.revoked:
        return "skip-revoked"
    if existing.expired:
        return "skip-expired"
    return "create"


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

# Transaction-local RLS context (same effect as SET LOCAL, but bind-parameterised).
_RLS_CONTEXT_SQL = (
    "SELECT set_config('app.tenant_id', :tid, true), "
    "set_config('app.actor', 'ADMIN', true), "
    "set_config('app.user_id', 'BOOTSTRAP', true)"
)

_FIND_ROLE_SQL = (
    "SELECT id FROM authz.role WHERE tenant_id = :tid AND name = :name AND deleted_at IS NULL"
)

_INSERT_ROLE_SQL = (
    "INSERT INTO authz.role "
    "(id, tenant_id, name, display_name, description, "
    " is_system, immutable, permissions, created_at, updated_at, created_by) "
    "VALUES "
    "(:id, :tenant_id, :name, :display_name, :description, "
    " TRUE, TRUE, :permissions, now(), now(), 'BOOTSTRAP')"
)

# Every TENANT-scoped row for the pair, in any state — revoked rows included.
_EXISTING_BINDINGS_SQL = (
    "SELECT "
    "  count(*) FILTER (WHERE revoked_at IS NULL "
    "                   AND (expires_at IS NULL OR expires_at >= now())), "
    "  count(*) FILTER (WHERE revoked_at IS NOT NULL), "
    "  count(*) FILTER (WHERE revoked_at IS NULL AND expires_at < now()), "
    "  max(revoked_at), "
    "  (array_agg(revoked_by ORDER BY revoked_at DESC) "
    "     FILTER (WHERE revoked_at IS NOT NULL))[1] "
    "FROM authz.role_binding "
    "WHERE tenant_id = :tid AND principal_kind = 'USER' AND principal_id = :uid "
    "  AND role_id = :rid AND scope_kind = 'TENANT'"
)

_INSERT_BINDING_SQL = (
    "INSERT INTO authz.role_binding "
    "(id, tenant_id, principal_kind, principal_id, role_id, "
    " scope_kind, scope_id, granted_at, granted_by, grant_reason) "
    "VALUES "
    "(:id, :tenant_id, 'USER', :principal_id, :role_id, "
    " 'TENANT', :scope_id, now(), 'BOOTSTRAP', :grant_reason)"
)


async def _make_engine(db_url: str) -> Any:
    from sqlalchemy.ext.asyncio import create_async_engine

    return create_async_engine(
        db_url,
        echo=False,
        pool_pre_ping=True,
        connect_args={
            "statement_cache_size": 0,
            "prepared_statement_cache_size": 0,
        },
    )


async def _ensure_roles(conn: Any, *, tenant_id: str, dry_run: bool) -> dict[str, str]:
    from sqlalchemy import String, bindparam, text
    from sqlalchemy.dialects.postgresql import ARRAY as PG_ARRAY

    role_ids: dict[str, str] = {}
    for role_def in _ROLES:
        name = role_def["name"]
        row = (
            await conn.execute(text(_FIND_ROLE_SQL), {"tid": tenant_id, "name": name})
        ).fetchone()
        if row:
            role_ids[name] = row[0]
            _say(f"  [skip] role '{name}' already exists ({row[0]})")
            continue

        role_id = _new_role_id()
        role_ids[name] = role_id
        if dry_run:
            _say(f"  [dry-run] would INSERT role '{name}' id={role_id}")
            continue
        await conn.execute(
            text(_INSERT_ROLE_SQL).bindparams(bindparam("permissions", type_=PG_ARRAY(String))),
            {
                "id": role_id,
                "tenant_id": tenant_id,
                "name": name,
                "display_name": role_def["display_name"],
                "description": role_def["description"],
                "permissions": list(role_def["permissions"]),
            },
        )
        _say(f"  [created] role '{name}' id={role_id}")
    return role_ids


async def _ensure_binding(
    conn: Any,
    *,
    tenant_id: str,
    seed: SeedBinding,
    role_id: str,
    dry_run: bool,
    restore_revoked: bool,
) -> None:
    from sqlalchemy import text

    row = (
        await conn.execute(
            text(_EXISTING_BINDINGS_SQL),
            {"tid": tenant_id, "uid": seed.user_id, "rid": role_id},
        )
    ).one()
    existing = ExistingBindings(active=row[0], revoked=row[1], expired=row[2])
    label = f"{seed.user_id} → {seed.role}"

    action = seed_action(existing, restore_revoked=restore_revoked)
    if action == "skip-active":
        _say(f"  [skip] binding {label} already active")
        return
    if action == "skip-revoked":
        _say(
            f"  [skip] binding {label} was revoked (last at {row[3]:%Y-%m-%d %H:%M} UTC "
            f"by {row[4]}); not re-granting (see --restore-revoked)"
        )
        return
    if action == "skip-expired":
        _say(f"  [skip] binding {label} has expired; not re-granting (see --restore-revoked)")
        return

    restoring = bool(existing.revoked or existing.expired)
    grant_reason = seed.grant_reason + (_RESTORED_SUFFIX if restoring else "")
    if dry_run:
        _say(f"  [dry-run] would INSERT binding {label} (role_id={role_id})")
        return
    binding_id = _new_binding_id()
    await conn.execute(
        text(_INSERT_BINDING_SQL),
        {
            "id": binding_id,
            "tenant_id": tenant_id,
            "principal_id": seed.user_id,
            "role_id": role_id,
            "scope_id": tenant_id,
            "grant_reason": grant_reason,
        },
    )
    verb = "restored" if restoring else "created"
    _say(f"  [{verb}] binding {label} (binding_id={binding_id})")


async def _bootstrap(
    *,
    tenant_id: str,
    seeds: Sequence[SeedBinding],
    db_url: str,
    dry_run: bool,
    restore_revoked: bool,
) -> None:
    from sqlalchemy import text

    engine = await _make_engine(db_url)
    try:
        async with engine.connect() as conn, conn.begin():
            await conn.execute(text(_RLS_CONTEXT_SQL), {"tid": tenant_id})
            role_ids = await _ensure_roles(conn, tenant_id=tenant_id, dry_run=dry_run)
            for seed in seeds:
                await _ensure_binding(
                    conn,
                    tenant_id=tenant_id,
                    seed=seed,
                    role_id=role_ids[seed.role],
                    dry_run=dry_run,
                    restore_revoked=restore_revoked,
                )
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _tenant_id_arg(value: str) -> str:
    if not _TENANT_ID_RE.match(value):
        raise argparse.ArgumentTypeError(f"not a tenant id (tnt_<26 chars>): {value!r}")
    return value


def _user_id_arg(value: str) -> str:
    if not _USER_ID_RE.match(value):
        raise argparse.ArgumentTypeError(f"not a user id (usr_<26 chars>): {value!r}")
    return value


def _bind_user_arg(value: str) -> tuple[str, str]:
    user_id, sep, role = value.partition("=")
    if not sep:
        raise argparse.ArgumentTypeError(f"expected USER_ID=ROLE, got {value!r}")
    if role not in _ROLE_NAMES:
        raise argparse.ArgumentTypeError(
            f"unknown role {role!r} in {value!r}; expected one of {', '.join(_ROLE_NAMES)}"
        )
    return _user_id_arg(user_id), role


def collect_seeds(args: argparse.Namespace) -> list[SeedBinding]:
    """Flatten the binding flags into SeedBindings, first occurrence wins."""
    requested: list[SeedBinding] = []
    if args.admin_user_id:
        requested.append(SeedBinding(args.admin_user_id, "super_admin", _SEED_GRANT_REASON))
    for user_id, role in args.bind_users or []:
        requested.append(SeedBinding(user_id, role, _SEED_GRANT_REASON))
    for svc_user_id in args.service_account_ids or []:
        # Downstream RBAC guards require ``usr_[0-9A-Z]{26}`` and 403 anything
        # else before even consulting authz, so warn (not fail) on mismatch.
        if not _USER_ID_RE.match(svc_user_id):
            _say(
                f"  [warn] service account id '{svc_user_id}' does not "
                "match usr_[0-9A-Z]{26}; downstream guards will 403 it"
            )
        requested.append(SeedBinding(svc_user_id, "member", _SERVICE_ACCOUNT_GRANT_REASON))

    seen: set[tuple[str, str]] = set()
    seeds: list[SeedBinding] = []
    for seed in requested:
        if (seed.user_id, seed.role) not in seen:
            seen.add((seed.user_id, seed.role))
            seeds.append(seed)
    return seeds


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Bootstrap default RBAC roles and seed role bindings for a tenant.",
    )
    p.add_argument(
        "--tenant-id",
        required=True,
        type=_tenant_id_arg,
        help="Tenant id (tnt_<ULID>) to create roles under.",
    )
    p.add_argument(
        "--admin-user-id",
        default=None,
        type=_user_id_arg,
        help="User id (usr_<ULID>) to bind to super_admin.  Same as --bind-user ID=super_admin.",
    )
    p.add_argument(
        "--bind-user",
        action="append",
        default=None,
        dest="bind_users",
        type=_bind_user_arg,
        metavar="USER_ID=ROLE",
        help=(
            f"Bind a user to one of the system roles ({', '.join(_ROLE_NAMES)}); "
            "repeatable.  Never re-creates a binding that was revoked or expired."
        ),
    )
    p.add_argument(
        "--service-account-id",
        action="append",
        default=None,
        dest="service_account_ids",
        help=(
            "Machine-principal user id (usr_<26 chars>) to bind to the member role "
            "(repeatable).  Used for service accounts like cron-runner's "
            "scheduled-App-run identity."
        ),
    )
    p.add_argument(
        "--restore-revoked",
        action="store_true",
        help=(
            "Also create a fresh binding where the requested one was revoked or has "
            "expired (the old row is kept as history).  Off by default: seeding never "
            "undoes a revocation on its own."
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


def main(argv: Sequence[str] | None = None) -> None:
    args = _build_parser().parse_args(argv)
    db_url = os.environ.get("AUTHZ_DB_DSN_ADMIN") or args.db_url
    seeds = collect_seeds(args)

    _say(
        f"bootstrap_tenant_roles: tenant_id={args.tenant_id} dry_run={args.dry_run} "
        f"restore_revoked={args.restore_revoked}"
    )
    asyncio.run(
        _bootstrap(
            tenant_id=args.tenant_id,
            seeds=seeds,
            db_url=db_url,
            dry_run=args.dry_run,
            restore_revoked=args.restore_revoked,
        )
    )
    _say("done.")


if __name__ == "__main__":
    main()
