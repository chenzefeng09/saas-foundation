"""Error code registry + FoundationError behaviour."""

from __future__ import annotations

import pytest

from foundation_authz.errors import (
    OPA_TIMEOUT,
    PERMISSION_DENIED,
    PERMISSION_UNKNOWN,
    REGISTRY,
    ROLE_NOT_FOUND,
    FoundationError,
)


pytestmark = pytest.mark.unit


class TestErrorCodeRegistry:
    def test_no_duplicate_codes(self) -> None:
        # _Registry.build raised at import time if duplicates exist; this asserts
        # the build product is non-empty and unique.
        codes = [c.code for c in REGISTRY.codes]
        assert len(codes) == len(set(codes))
        assert len(codes) > 0

    def test_all_codes_prefixed_correctly(self) -> None:
        for c in REGISTRY.codes:
            assert c.code.startswith("FOUNDATION.AUTHZ.")
            parts = c.code.split(".")
            assert len(parts) == 4, f"bad code: {c.code}"
            assert parts[0] == "FOUNDATION"
            assert parts[1] == "AUTHZ"
            assert parts[2] in {
                "POLICY", "INPUT", "RESOURCE", "STATE", "DEPENDENCY", "INTERNAL"
            }, f"unknown category in {c.code}"

    def test_http_status_consistent_with_category(self) -> None:
        category_to_allowed_status = {
            "POLICY": {403},
            "INPUT": {400, 422},
            "RESOURCE": {404, 409},
            "STATE": {409},
            "DEPENDENCY": {502, 503, 504},
            "INTERNAL": {500},
        }
        for c in REGISTRY.codes:
            category = c.code.split(".")[2]
            assert c.http_status in category_to_allowed_status[category], (
                f"{c.code}: {c.http_status} not allowed in {category}"
            )


class TestFoundationError:
    def test_carries_error_code(self) -> None:
        err = FoundationError(ROLE_NOT_FOUND)
        assert err.error_code is ROLE_NOT_FOUND
        assert err.detail == ROLE_NOT_FOUND.default_detail
        assert err.user_message == ROLE_NOT_FOUND.default_user_message

    def test_custom_detail_overrides(self) -> None:
        err = FoundationError(PERMISSION_DENIED, detail="custom detail")
        assert err.detail == "custom detail"
        assert err.user_message == PERMISSION_DENIED.default_user_message

    def test_extra_recorded(self) -> None:
        err = FoundationError(PERMISSION_UNKNOWN, extra={"action": "x.y.z"})
        assert err.extra == {"action": "x.y.z"}

    def test_str_contains_code(self) -> None:
        err = FoundationError(OPA_TIMEOUT)
        assert "FOUNDATION.AUTHZ.DEPENDENCY.OPA_TIMEOUT" in str(err)

    def test_extra_default_is_empty_dict(self) -> None:
        err = FoundationError(ROLE_NOT_FOUND)
        assert err.extra == {}
