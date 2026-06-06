"""E2E test suite — conftest.

目的
----
这个 conftest 为 e2e 测试提供连接真实底座栈的 fixture。
所有 e2e 测试都标注 @pytest.mark.e2e，且在 FOUNDATION_API_URL 未设置时 skip。

运行前提
--------
必须先启动完整的底座栈：

    cd /path/to/saas-foundation
    cp deploy/docker-compose/.env.example deploy/docker-compose/.env
    # 编辑 .env 设置密码
    docker compose -f deploy/docker-compose/dev.yml \\
                   -f deploy/docker-compose/integration.yml up -d
    # 等待 healthcheck 全绿（约 30-60s）
    docker compose -f deploy/docker-compose/integration.yml ps

然后运行：

    FOUNDATION_API_URL=http://localhost:8000 \\
    FOUNDATION_API_TOKEN=<dev-token> \\
    pytest tests/e2e/ -v -m e2e

或通过 Makefile（如果已配置）：

    make test-e2e

环境变量
--------
FOUNDATION_API_URL   底座 API 网关地址（e.g. http://localhost:8000）
FOUNDATION_API_TOKEN 调用底座的 Bearer token（dev 环境可用 seed 脚本生成的临时 token）
FOUNDATION_TENANT_A  主测试租户 ID（默认 tnt_01J5DEVXX00000000000000001）
FOUNDATION_TENANT_B  第二租户 ID（用于跨租户隔离测试）
FOUNDATION_DB_DSN    直连 DB 的 DSN（RLS fuzz 场景用；可选）
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import httpx
import pytest


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_TENANT_A = "tnt_01J5DEVXX00000000000000001"
_DEFAULT_TENANT_B = "tnt_01J5DEVXX00000000000000002"


# ---------------------------------------------------------------------------
# Skip guard
# ---------------------------------------------------------------------------

def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "e2e: end-to-end tests — require a running foundation stack",
    )


def _require_stack() -> str:
    """Return FOUNDATION_API_URL or skip."""
    url = os.environ.get("FOUNDATION_API_URL")
    if not url:
        pytest.skip(
            "E2E tests require a running foundation stack. "
            "Set FOUNDATION_API_URL (and FOUNDATION_API_TOKEN) and re-run. "
            "See tests/e2e/conftest.py for startup instructions."
        )
    return url


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@dataclass
class E2EConfig:
    api_url: str
    api_token: str
    tenant_a: str
    tenant_b: str


@pytest.fixture(scope="session")
def e2e_config() -> E2EConfig:
    """Session-level config parsed from env. Skips if stack not available."""
    api_url = _require_stack()
    return E2EConfig(
        api_url=api_url,
        api_token=os.environ.get("FOUNDATION_API_TOKEN", "dev-token"),
        tenant_a=os.environ.get("FOUNDATION_TENANT_A", _DEFAULT_TENANT_A),
        tenant_b=os.environ.get("FOUNDATION_TENANT_B", _DEFAULT_TENANT_B),
    )


@pytest.fixture(scope="session")
def http_client(e2e_config: E2EConfig) -> httpx.Client:
    """Synchronous httpx client pointing at the foundation stack."""
    with httpx.Client(
        base_url=e2e_config.api_url,
        timeout=30.0,
        headers={
            "Authorization": f"Bearer {e2e_config.api_token}",
            "Content-Type": "application/json",
        },
    ) as client:
        yield client


@pytest.fixture(scope="session", autouse=True)
def wait_for_stack(e2e_config: E2EConfig) -> None:
    """Ensure the foundation stack is healthy before any e2e test runs.

    Checks /healthz on the primary API gateway. Retries up to 30s.
    """
    import time

    deadline = time.time() + 30
    last_exc: Exception | None = None
    while time.time() < deadline:
        try:
            r = httpx.get(
                f"{e2e_config.api_url}/healthz",
                timeout=3.0,
                headers={"Authorization": f"Bearer {e2e_config.api_token}"},
            )
            if r.status_code == 200:
                return
        except Exception as exc:
            last_exc = exc
        time.sleep(2)

    pytest.fail(
        f"Foundation stack at {e2e_config.api_url} not healthy after 30s. "
        f"Last error: {last_exc}. "
        "Run: docker compose -f deploy/docker-compose/dev.yml -f deploy/docker-compose/integration.yml up -d"
    )
