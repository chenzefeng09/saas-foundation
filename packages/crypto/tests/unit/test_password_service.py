"""Unit tests for password_service."""

import pytest

from foundation_crypto.schemas.password import PasswordHashRequest, PasswordVerifyRequest
from foundation_crypto.services.password_service import PasswordService


@pytest.fixture
def svc() -> PasswordService:
    return PasswordService()


class TestHash:
    def test_hash_returns_phc_format(self, svc: PasswordService) -> None:
        result = svc.hash(PasswordHashRequest(password="mySecureP@ssw0rd"))
        assert result.algorithm == "argon2id"
        assert result.encoded.startswith("$argon2id$")

    def test_hash_different_passwords_produce_different_outputs(self, svc: PasswordService) -> None:
        r1 = svc.hash(PasswordHashRequest(password="password1"))
        r2 = svc.hash(PasswordHashRequest(password="password2"))
        assert r1.encoded != r2.encoded


class TestVerify:
    def test_verify_correct_password(self, svc: PasswordService) -> None:
        encoded = svc.hash(PasswordHashRequest(password="correct")).encoded
        result = svc.verify(PasswordVerifyRequest(password="correct", encoded=encoded))
        assert result.valid is True

    def test_verify_wrong_password(self, svc: PasswordService) -> None:
        encoded = svc.hash(PasswordHashRequest(password="correct")).encoded
        result = svc.verify(PasswordVerifyRequest(password="wrong", encoded=encoded))
        assert result.valid is False

    def test_verify_invalid_hash_format(self, svc: PasswordService) -> None:
        result = svc.verify(PasswordVerifyRequest(password="anything", encoded="not-a-valid-hash"))
        assert result.valid is False
