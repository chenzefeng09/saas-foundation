"""Integration tier: the real app over HTTP against a migrated Postgres.

No dependency overrides: requests go through the middleware, the DI session
(SET LOCAL via set_config) and RLS, connected as the runtime role CI configures.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import httpx
import pytest
from sqlalchemy import delete

from tests._db import foundation_db_url

# Before the test modules import the app: main.py builds it at import time and
# get_settings() caches the first Settings it reads.
os.environ["SECURITY_OPS_DB_DSN"] = foundation_db_url().render_as_string(hide_password=False)
# CI starts only postgres + redis, so the feature-flag client stays on its local
# presets instead of polling an Unleash server that is not there.
os.environ["FEATURE_FLAG_UNLEASH_ENABLED"] = "false"

from foundation_security_ops.domain.db import dispose_engine
from foundation_security_ops.main import app
from tests.integration._support import API, MODELS, as_actor


@pytest.fixture(autouse=True)
async def _clean_db() -> AsyncIterator[None]:
    # Every test starts from empty security_ops tables. The engine is bound to the
    # test's event loop, so it is disposed with it.
    async with as_actor("SERVICE") as session:
        for model in MODELS:
            await session.execute(delete(model))
    yield
    await dispose_engine()


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    # raise_app_exceptions=False: an unhandled error comes back as the 500 the
    # exception handler renders, as it would over the wire.
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(
        transport=transport,
        base_url=f"http://security-ops{API}",
        headers={"X-Actor": "SERVICE"},
    ) as c:
        yield c
