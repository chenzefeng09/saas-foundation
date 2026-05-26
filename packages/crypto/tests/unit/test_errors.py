"""Error registry validation tests."""

from foundation_crypto.errors import REGISTRY, FoundationError


class TestErrorRegistry:
    def test_all_codes_are_unique(self) -> None:
        codes = [c.code for c in REGISTRY.codes]
        assert len(codes) == len(set(codes)), f"Duplicate codes found: {codes}"

    def test_all_have_valid_http_status(self) -> None:
        for ec in REGISTRY.codes:
            assert 200 <= ec.http_status < 600, f"Invalid HTTP status for {ec.code}: {ec.http_status}"

    def test_essential_codes_exist(self) -> None:
        code_set = {c.code for c in REGISTRY.codes}
        essential = [
            "FOUNDATION.CRYPTO.POLICY.PERMISSION_DENIED",
            "FOUNDATION.CRYPTO.INPUT.VALIDATION_FAILED",
            "FOUNDATION.CRYPTO.INPUT.ALGORITHM_UNSUPPORTED",
            "FOUNDATION.CRYPTO.RESOURCE.KEK_NOT_FOUND",
            "FOUNDATION.CRYPTO.RESOURCE.KEK_LABEL_CONFLICT",
            "FOUNDATION.CRYPTO.STATE.KEK_NOT_ACTIVE",
            "FOUNDATION.CRYPTO.STATE.KEK_NOT_DESTRUCTIBLE",
            "FOUNDATION.CRYPTO.STATE.KEK_DESTROYED",
            "FOUNDATION.CRYPTO.STATE.ENVELOPE_TAMPERED",
            "FOUNDATION.CRYPTO.DEPENDENCY.VAULT_UNAVAILABLE",
            "FOUNDATION.CRYPTO.INTERNAL.UNEXPECTED",
        ]
        for e in essential:
            assert e in code_set, f"Missing essential error code: {e}"


class TestFoundationError:
    def test_raises_with_extra(self) -> None:
        from foundation_crypto.errors import KEK_NOT_FOUND

        exc = FoundationError(KEK_NOT_FOUND, detail="test detail", extra={"kek_id": "kek_123"})
        assert exc.error_code is KEK_NOT_FOUND
        assert exc.detail == "test detail"
        assert exc.extra["kek_id"] == "kek_123"

    def test_default_detail_and_message(self) -> None:
        from foundation_crypto.errors import VAULT_UNAVAILABLE

        exc = FoundationError(VAULT_UNAVAILABLE)
        assert exc.detail == VAULT_UNAVAILABLE.default_detail
        assert exc.user_message == VAULT_UNAVAILABLE.default_user_message
