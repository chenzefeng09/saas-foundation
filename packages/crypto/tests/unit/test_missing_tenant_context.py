"""A request without tenant context gets RFC 9457 problem+json, not FastAPI's {"detail": ...}.

``current_context`` raises ``TENANT_CONTEXT_MISSING``; the FoundationError handler
renders it as the contract's ``Unauthorized`` response (docs/errors.md §2).
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from foundation_crypto.config import get_settings
from foundation_crypto.main import create_app

# docs/errors.md §3.1, as contracts/openapi/_common.yaml's Error.code pattern.
CODE_FORMAT = re.compile(r"FOUNDATION\.[A-Z_]+\.[A-Z_]+\.[A-Z_]+")
PATH = "/api/crypto/v1/keks"


def test_a_request_without_tenant_context_gets_a_problem_json_401(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Settings were cached with tracing on when main.py built its module-level app,
    # before conftest's CRYPTO_OTEL_ENABLED=false; a traced request would leave spans
    # for an OTLP exporter with no collector, and pytest would wait out its retries.
    monkeypatch.setattr(get_settings(), "otel_enabled", False)

    resp = TestClient(create_app()).get(PATH)

    assert resp.status_code == 401
    assert resp.headers["content-type"].startswith("application/problem+json")
    body = resp.json()
    assert body["code"] == "FOUNDATION.CRYPTO.AUTH.TENANT_CONTEXT_MISSING"
    assert CODE_FORMAT.fullmatch(body["code"])
    assert body["status"] == 401
    assert body["instance"] == PATH
    assert body["request_id"] == resp.headers["X-Request-Id"]
