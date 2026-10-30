"""Lifecycle SDK request-shape regression tests."""

from __future__ import annotations

from typing import Any

from foundation_sdk.resources.lifecycle import LifecycleResource


class _RecordingTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        self.calls.append((method, path, kwargs))
        return {"items": [], "next_cursor": None}


def test_list_legal_holds_filters_with_the_contract_param() -> None:
    transport = _RecordingTransport()
    resource = LifecycleResource(transport)  # type: ignore[arg-type]

    resource.list_legal_holds(resource_id="res_123")

    # A bare ``resource_id`` is not a parameter of GET /legal-holds: the service
    # would ignore it and return every active hold of the tenant.
    assert transport.calls == [
        (
            "GET",
            "/api/lifecycle/v1/legal-holds",
            {"params": {"filter.resource_id": "res_123"}},
        )
    ]


def test_list_legal_holds_without_a_resource_sends_no_filter() -> None:
    transport = _RecordingTransport()
    resource = LifecycleResource(transport)  # type: ignore[arg-type]

    resource.list_legal_holds()

    assert transport.calls == [("GET", "/api/lifecycle/v1/legal-holds", {"params": {}})]


def test_list_legal_holds_keeps_an_empty_resource_id_as_a_filter() -> None:
    transport = _RecordingTransport()
    resource = LifecycleResource(transport)  # type: ignore[arg-type]

    # Dropping it would turn "holds on resource ''" (none) into every hold of the tenant.
    resource.list_legal_holds(resource_id="")

    assert transport.calls[0][2] == {"params": {"filter.resource_id": ""}}
