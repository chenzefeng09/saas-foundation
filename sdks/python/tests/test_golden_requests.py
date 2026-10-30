"""Every SDK method sends exactly the request pinned in ``contracts/sdk/<service>.json``.

Each service's ``tests/unit/test_sdk_requests.py`` checks the same requests
against its routes and its OpenAPI contract, so a path, parameter or field that
changes on one side only fails one of the two suites. When a method changes on
purpose, change its cases with it (see ``contracts/sdk/README.md``).
"""

from __future__ import annotations

import asyncio
import inspect
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl

import httpx
import pytest
import respx
from foundation_sdk import FoundationClient, tenant_context

GOLDEN = Path(__file__).resolve().parents[3] / "contracts" / "sdk"
FILES = [json.loads(path.read_text()) for path in sorted(GOLDEN.glob("*.json"))]
BASE_URL = "http://sdk.test"


def _calls() -> Iterator[Any]:
    for file in FILES:
        for case in file["cases"]:
            for call in case["python"]:
                yield pytest.param(
                    file,
                    call,
                    case["request"],
                    id=f"{file['service']}/{case['id']}/{call['method']}",
                )


def _wire(request: httpx.Request) -> dict[str, Any]:
    """``request`` written down the way the golden files write it."""
    path, _, raw_query = request.url.raw_path.decode().partition("?")
    wire: dict[str, Any] = {"method": request.method, "path": path}
    query: dict[str, list[str]] = {}
    for name, value in parse_qsl(raw_query, keep_blank_values=True):
        query.setdefault(name, []).append(value)
    if query:
        wire["query"] = {name: v[0] if len(v) == 1 else v for name, v in query.items()}
    if request.content:
        wire["json"] = json.loads(request.content)
    return wire


@pytest.mark.parametrize(("file", "call", "expected"), _calls())
def test_the_method_sends_the_golden_request(
    file: dict[str, Any], call: dict[str, Any], expected: dict[str, Any]
) -> None:
    resource = getattr(FoundationClient(BASE_URL, "tok"), file["service"].replace("-", "_"))
    context = file["context"]

    with respx.mock(base_url=BASE_URL, assert_all_called=False) as router:
        route = router.route().respond(200, json={})
        with tenant_context(context["tenant_id"], user_id=context["user_id"]):
            result = getattr(resource, call["method"])(*call["args"], **call["kwargs"])
            if inspect.iscoroutine(result):
                asyncio.run(result)

    assert [_wire(sent.request) for sent in route.calls] == [expected]


def test_every_public_method_has_a_golden_request() -> None:
    pinned = {
        (file["service"], call["method"])
        for file in FILES
        for case in file["cases"]
        for call in case["python"]
    }
    methods = {
        (name.replace("_", "-"), method)
        for name, resource in vars(FoundationClient(BASE_URL, "tok")).items()
        if type(resource).__module__.startswith("foundation_sdk.resources.")
        for method, _ in inspect.getmembers(type(resource), inspect.isfunction)
        if not method.startswith("_")
    }

    assert sorted(methods - pinned) == [], "methods without a case in contracts/sdk/"
    assert sorted(pinned - methods) == [], "cases for methods the SDK does not have"
