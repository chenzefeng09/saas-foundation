"""A request without tenant context gets RFC 9457 problem+json, not FastAPI's {"detail": ...}.

``current_context`` raises ``TENANT_CONTEXT_MISSING``; the FoundationError handler
renders it as the contract's ``Unauthorized`` response (docs/errors.md §2).
compliance's test dependencies have no httpx, so no TestClient: the request goes to
the ASGI app directly, through its middleware and handlers.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

from foundation_compliance.main import create_app

# docs/errors.md §3.1, as contracts/openapi/_common.yaml's Error.code pattern.
CODE_FORMAT = re.compile(r"FOUNDATION\.[A-Z_]+\.[A-Z_]+\.[A-Z_]+")
PATH = "/api/compliance/v1/ropa"


async def _get(path: str) -> tuple[int, dict[str, str], dict[str, Any]]:
    """GET ``path`` from a fresh app; return the status, headers and JSON body."""
    sent: list[dict[str, Any]] = []
    responded = asyncio.Event()
    requested = False

    async def receive() -> dict[str, Any]:
        nonlocal requested
        if not requested:
            requested = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await responded.wait()
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)
        if message["type"] == "http.response.body" and not message.get("more_body"):
            responded.set()

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "root_path": "",
        "query_string": b"",
        "headers": [(b"host", b"testserver")],
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
    }
    await create_app()(scope, receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    headers = {k.decode(): v.decode() for k, v in start["headers"]}
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return start["status"], headers, json.loads(body)


async def test_a_request_without_tenant_context_gets_a_problem_json_401() -> None:
    status, headers, body = await _get(PATH)

    assert status == 401
    assert headers["content-type"].startswith("application/problem+json")
    assert body["code"] == "FOUNDATION.COMPLIANCE.AUTH.TENANT_CONTEXT_MISSING"
    assert CODE_FORMAT.fullmatch(body["code"])
    assert body["status"] == 401
    assert body["instance"] == PATH
    assert body["request_id"] == headers["x-request-id"]
