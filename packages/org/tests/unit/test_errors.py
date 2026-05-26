"""Error registry validation tests for org module."""

from foundation_org.errors import REGISTRY, FoundationError


class TestErrorRegistry:
    def test_all_codes_are_unique(self) -> None:
        codes = [c.code for c in REGISTRY.codes]
        assert len(codes) == len(set(codes)), f"Duplicate codes: {codes}"

    def test_all_have_valid_http_status(self) -> None:
        for ec in REGISTRY.codes:
            assert 200 <= ec.http_status < 600

    def test_essential_codes_exist(self) -> None:
        code_set = {c.code for c in REGISTRY.codes}
        essential = [
            "FOUNDATION.ORG.RESOURCE.ORG_UNIT_NOT_FOUND",
            "FOUNDATION.ORG.RESOURCE.TEAM_NOT_FOUND",
            "FOUNDATION.ORG.RESOURCE.MEMBERSHIP_NOT_FOUND",
            "FOUNDATION.ORG.RESOURCE.ORG_UNIT_CODE_CONFLICT",
            "FOUNDATION.ORG.RESOURCE.TEAM_CODE_CONFLICT",
            "FOUNDATION.ORG.STATE.NOT_EMPTY",
            "FOUNDATION.ORG.STATE.ORG_UNIT_ARCHIVED",
            "FOUNDATION.ORG.STATE.ORG_UNIT_CYCLE",
            "FOUNDATION.ORG.STATE.DEPTH_EXCEEDED",
            "FOUNDATION.ORG.STATE.IMMUTABLE_CODE",
            "FOUNDATION.ORG.STATE.MEMBER_ALREADY_IN_TEAM",
            "FOUNDATION.ORG.STATE.MEMBER_NOT_IN_TEAM",
            "FOUNDATION.ORG.INTERNAL.UNEXPECTED",
        ]
        for e in essential:
            assert e in code_set, f"Missing: {e}"


class TestFoundationError:
    def test_extra_fields(self) -> None:
        from foundation_org.errors import ORG_UNIT_NOT_FOUND

        exc = FoundationError(ORG_UNIT_NOT_FOUND, extra={"ou_id": "ou_123"})
        assert exc.extra["ou_id"] == "ou_123"
