"""scripts/bootstrap_tenant_roles.py — seed-binding decisions and CLI parsing.

The SQL side runs against a real Postgres (dev stack ``authz-init``); here we pin
the pure rules: re-seeding never duplicates an active binding and never
resurrects a revoked or expired one unless explicitly told to.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "bootstrap_tenant_roles.py"

TENANT = "tnt_01J5DEVXX00000000000000001"
ADMIN = "usr_01KT7TZ70AM2RK8P0C01KMBPRR"
ALICE = "usr_01KT7TZ70AM2RK8P0C0ALICE01"
SVC = "usr_01SVCCRON00000000000000000"


@pytest.fixture(scope="module")
def script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("bootstrap_tenant_roles", _SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve annotations via sys.modules
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("active", "revoked", "expired", "restore", "expected"),
    [
        (0, 0, 0, False, "create"),  # never bound → seed it
        (1, 0, 0, False, "skip-active"),  # already bound → leave alone
        (1, 2, 1, False, "skip-active"),  # active wins over history
        (0, 1, 0, False, "skip-revoked"),  # admin revoked it → do not resurrect
        (0, 1, 1, False, "skip-revoked"),
        (0, 0, 1, False, "skip-expired"),  # time-boxed grant ran out → do not extend
        (0, 1, 0, True, "create"),  # explicit --restore-revoked
        (0, 0, 1, True, "create"),
        (1, 1, 0, True, "skip-active"),  # restore never duplicates an active one
    ],
)
def test_seed_action(
    script: ModuleType, active: int, revoked: int, expired: int, restore: bool, expected: str
) -> None:
    existing = script.ExistingBindings(active=active, revoked=revoked, expired=expired)
    assert script.seed_action(existing, restore_revoked=restore) == expected


def test_collect_seeds_maps_flags_to_roles_and_dedupes(script: ModuleType) -> None:
    argv = ["--tenant-id", TENANT, "--admin-user-id", ADMIN]
    argv += ["--bind-user", f"{ADMIN}=super_admin"]  # duplicate of --admin-user-id
    argv += ["--bind-user", f"{ALICE}=member", "--service-account-id", SVC]
    args = script._build_parser().parse_args(argv)
    seeds = script.collect_seeds(args)

    assert [(s.user_id, s.role) for s in seeds] == [
        (ADMIN, "super_admin"),
        (ALICE, "member"),
        (SVC, "member"),
    ]
    assert seeds[2].grant_reason == "service account: scheduled App runs"
    assert args.restore_revoked is False


@pytest.mark.parametrize(
    "argv",
    [
        ["--tenant-id", "tnt_bad"],
        ["--tenant-id", "tnt_01J5DEVXX00000000000000001'; DROP TABLE x; --"],
        ["--tenant-id", TENANT, "--bind-user", ALICE],  # missing =ROLE
        ["--tenant-id", TENANT, "--bind-user", f"{ALICE}=owner"],  # unknown role
        ["--tenant-id", TENANT, "--bind-user", "alice=member"],  # not a usr_ id
        ["--tenant-id", TENANT, "--admin-user-id", "admin@foundation.local"],
    ],
)
def test_cli_rejects_malformed_ids_and_roles(script: ModuleType, argv: list[str]) -> None:
    with pytest.raises(SystemExit) as ei:
        script._build_parser().parse_args(argv)
    assert ei.value.code == 2
