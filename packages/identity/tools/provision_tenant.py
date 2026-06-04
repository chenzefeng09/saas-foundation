"""CLI tool: provision a new tenant.

Usage
-----
    python tools/provision_tenant.py \\
        --name "ACME Corp" \\
        --tier PRO \\
        --admin-email admin@acme.example \\
        [--admin-display-name "ACME Admin"] \\
        [--tenant-id tnt_01EXISTING00000000000000A]  # idempotent re-run

Environment
-----------
All IDENTITY_* env vars must be set (see config.py).  Use a .env file in
the identity package root for local dev.

The tool connects as app_admin (via IDENTITY_DB_DSN_ADMIN or falls back to
IDENTITY_DB_DSN) and runs the same saga as the HTTP endpoint.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

# Allow running from the tools/ directory without installing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


async def _run(args: argparse.Namespace) -> None:
    # Load settings (picks up .env from CWD or IDENTITY_* env vars)
    from foundation_identity.config import get_settings
    settings = get_settings()

    from foundation_identity.adapters.keycloak_admin import get_keycloak_admin
    from foundation_identity.adapters.audit_publisher import get_audit_publisher

    svc_kwargs = {
        "keycloak": get_keycloak_admin(),
        "audit": get_audit_publisher(),
        "org_url": settings.org_url,
        "billing_url": settings.billing_url,
        "authz_url": settings.authz_url,
    }

    from foundation_identity.services.tenant_provisioning_service import TenantProvisioningService
    svc = TenantProvisioningService(**svc_kwargs)

    print(f"Provisioning tenant: name={args.name!r} tier={args.tier}")
    if args.dry_run:
        print("[dry-run] skipping actual provisioning")
        return

    result = await svc.provision(
        name=args.name,
        tier=args.tier,
        admin_email=args.admin_email,
        admin_display_name=args.admin_display_name,
        tenant_id=args.tenant_id,
    )
    print(json.dumps(result, indent=2))


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Provision a new tenant.")
    p.add_argument("--name", required=True, help="Human-readable tenant name.")
    p.add_argument(
        "--tier", default="FREE",
        choices=["FREE", "STARTER", "PRO", "ENTERPRISE"],
    )
    p.add_argument("--admin-email", required=True, help="First admin's email.")
    p.add_argument("--admin-display-name", default=None)
    p.add_argument(
        "--tenant-id", default=None,
        help="Re-run provisioning for an existing tenant_id (idempotent).",
    )
    p.add_argument("--dry-run", action="store_true")
    return p


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    asyncio.run(_run(args))


if __name__ == "__main__":
    main()
