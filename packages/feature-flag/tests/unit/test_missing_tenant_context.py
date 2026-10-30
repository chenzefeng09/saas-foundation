"""User overrides need a tenant and a user; without either the answer is RFC 9457 problem+json.

``_identity`` raises ``TENANT_CONTEXT_MISSING`` / ``USER_CONTEXT_MISSING``; the
FoundationError handler renders them as 401 problem+json (docs/errors.md §2),
not FastAPI's ``{"detail": ...}``.
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from foundation_feature_flag.main import create_app

# docs/errors.md §3.1, as contracts/openapi/_common.yaml's Error.code pattern.
CODE_FORMAT = re.compile(r"FOUNDATION\.[A-Z_]+\.[A-Z_]+\.[A-Z_]+")
PATH = "/api/feature-flag/v1/user-overrides"
TENANT_ID = "tnt_01J0000000000000000000TNT1"


@pytest.mark.parametrize(
    ("headers", "code"),
    [
        pytest.param(
            {},
            "FOUNDATION.FEATURE_FLAG.AUTH.TENANT_CONTEXT_MISSING",
            id="no-tenant",
        ),
        pytest.param(
            {"X-Tenant-Id": TENANT_ID},
            "FOUNDATION.FEATURE_FLAG.AUTH.USER_CONTEXT_MISSING",
            id="no-user",
        ),
    ],
)
def test_user_overrides_without_identity_get_a_problem_json_401(
    headers: dict[str, str], code: str
) -> None:
    resp = TestClient(create_app()).get(PATH, headers=headers)

    assert resp.status_code == 401
    assert resp.headers["content-type"].startswith("application/problem+json")
    body = resp.json()
    assert body["code"] == code
    assert CODE_FORMAT.fullmatch(body["code"])
    assert body["status"] == 401
    assert body["instance"] == PATH
    assert body["request_id"] == resp.headers["X-Request-Id"]
