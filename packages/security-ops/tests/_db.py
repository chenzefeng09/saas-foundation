"""Connection settings shared by the integration and security tiers.

Both tiers run against a real, migrated Postgres as an RLS-bound role and read the
connection from the FOUNDATION_DB_* variables that service-ci.yml sets.  A missing
variable is an error, never a skip: these tiers exist to prove the database contract.
"""

from __future__ import annotations

import os

from sqlalchemy.engine import URL


def _require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"{name} is not set; tests/integration and tests/security need a real "
            "Postgres (see .github/workflows/service-ci.yml)"
        )
    return value


def foundation_db_url() -> URL:
    return URL.create(
        "postgresql+asyncpg",
        username=_require("FOUNDATION_DB_USER"),
        password=_require("FOUNDATION_DB_PASSWORD"),
        host=_require("FOUNDATION_DB_HOST"),
        port=int(os.environ.get("FOUNDATION_DB_PORT", "5432")),
        database=os.environ.get("FOUNDATION_DB_NAME", "foundation"),
    )
