"""Error registry invariants."""

from __future__ import annotations

import re

import pytest

from foundation_identity.errors import REGISTRY


CODE_RE = re.compile(r"^FOUNDATION\.IDENTITY\.[A-Z_]+\.[A-Z_]+$")


@pytest.mark.unit
def test_all_codes_match_4_segment_pattern() -> None:
    for ec in REGISTRY.codes:
        assert CODE_RE.match(ec.code), f"bad code: {ec.code}"


@pytest.mark.unit
def test_no_duplicate_codes() -> None:
    codes = [ec.code for ec in REGISTRY.codes]
    assert len(codes) == len(set(codes))


@pytest.mark.unit
def test_http_status_in_allowed_range() -> None:
    allowed = {400, 401, 403, 404, 409, 410, 412, 413, 422, 429, 500, 502, 503, 504}
    for ec in REGISTRY.codes:
        assert ec.http_status in allowed, f"{ec.code} → {ec.http_status}"


@pytest.mark.unit
def test_essential_codes_present() -> None:
    must_have = {
        "FOUNDATION.IDENTITY.AUTH.INVALID_CREDENTIALS",
        "FOUNDATION.IDENTITY.AUTH.TOKEN_EXPIRED",
        "FOUNDATION.IDENTITY.AUTH.MFA_REQUIRED",
        "FOUNDATION.IDENTITY.POLICY.PERMISSION_DENIED",
        "FOUNDATION.IDENTITY.RESOURCE.USER_NOT_FOUND",
        "FOUNDATION.IDENTITY.RESOURCE.USER_ALREADY_EXISTS",
        "FOUNDATION.IDENTITY.INPUT.PASSWORD_TOO_WEAK",
    }
    actual = {ec.code for ec in REGISTRY.codes}
    assert must_have.issubset(actual)
