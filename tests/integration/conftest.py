"""Shared fixtures for integration tests.

These tests run against the full docker-compose stack and expect the following
environment variables to be set (injected by docker-compose):

  FOUNDATION_IDENTITY_URL  = http://identity:8001/api/identity/v1
  FOUNDATION_AUTHZ_URL     = http://authz:8002/api/authz/v1
  FOUNDATION_ORG_URL       = http://org:8003/api/org/v1
  FOUNDATION_CRYPTO_URL    = http://crypto:8004/api/crypto/v1
  FOUNDATION_TENANT_ID     = tnt_01J5DEVXX00000000000000001
  FOUNDATION_USER_ID       = usr_01J5INT000000000000TEST1
  FOUNDATION_ACTOR         = SERVICE
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass

import httpx
import pytest


# ---------------------------------------------------------------------------
# Service URLs
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class ServiceEndpoints:
    identity: str
    authz: str
    org: str
    crypto: str

    @classmethod
    def from_env(cls) -> ServiceEndpoints:
        return cls(
            identity=os.environ["FOUNDATION_IDENTITY_URL"],
            authz=os.environ["FOUNDATION_AUTHZ_URL"],
            org=os.environ["FOUNDATION_ORG_URL"],
            crypto=os.environ["FOUNDATION_CRYPTO_URL"],
        )


@pytest.fixture(scope="session")
def endpoints() -> ServiceEndpoints:
    return ServiceEndpoints.from_env()


# ---------------------------------------------------------------------------
# Tenant / actor context (passed as HTTP headers)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class TenantContext:
    tenant_id: str
    user_id: str
    actor: str

    @property
    def headers(self) -> dict[str, str]:
        return {
            "X-Tenant-Id": self.tenant_id,
            "X-User-Id": self.user_id,
            "X-Actor": self.actor,
            "Content-Type": "application/json",
        }

    @classmethod
    def from_env(cls) -> TenantContext:
        return cls(
            tenant_id=os.environ.get("FOUNDATION_TENANT_ID", "tnt_01J5DEVXX00000000000000001"),
            user_id=os.environ.get("FOUNDATION_USER_ID", "usr_01J5INT000000000000TEST1"),
            actor=os.environ.get("FOUNDATION_ACTOR", "SERVICE"),
        )


@pytest.fixture(scope="session")
def tenant() -> TenantContext:
    return TenantContext.from_env()


# ---------------------------------------------------------------------------
# HTTP clients
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def client() -> Iterator[httpx.AsyncClient]:
    """Session-scoped async HTTP client."""
    async with httpx.AsyncClient(timeout=30.0) as c:
        yield c


@pytest.fixture
def anon_client() -> Iterator[httpx.AsyncClient]:
    """Client without tenant headers (for testing auth rejection)."""
    async with httpx.AsyncClient(timeout=10.0, headers={"Content-Type": "application/json"}) as c:
        yield c


# ---------------------------------------------------------------------------
# Health check helper
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
async def _wait_for_services(endpoints: ServiceEndpoints) -> None:
    """Block until all 4 services respond to /healthz."""
    import asyncio

    urls = [
        f"{endpoints.crypto}/healthz",
        f"{endpoints.identity}/healthz",
        f"{endpoints.authz}/healthz",
        f"{endpoints.org}/healthz",
    ]
    async with httpx.AsyncClient(timeout=5.0) as c:
        for url in urls:
            for attempt in range(30):
                try:
                    r = await c.get(url)
                    if r.status_code == 200:
                        break
                except Exception:
                    pass
                await asyncio.sleep(1)
            else:
                pytest.exit(f"Service at {url} did not become healthy after 30s")
