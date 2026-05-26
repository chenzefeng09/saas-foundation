"""Schema validation unit tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from foundation_crypto.schemas.algorithm import AlgorithmRead, TenantAlgorithmPolicyRead
from foundation_crypto.schemas.envelope import Envelope, EncryptRequest
from foundation_crypto.schemas.kek import CreateKEKRequest, KEKRead, MarkForDestructionRequest
from foundation_crypto.schemas.password import PasswordHashRequest, PasswordVerifyRequest
from foundation_crypto.schemas.sign import SignRequest, VerifyRequest


class TestAlgorithmSchema:
    def test_valid_algorithm_read(self) -> None:
        a = AlgorithmRead(
            id="AES-256-GCM",
            kind="SYMMETRIC",
            family="AES",
            provider="openssl",
            key_size_bits=256,
            fips_140=True,
        )
        assert a.id == "AES-256-GCM"

    def test_invalid_algorithm_kind(self) -> None:
        with pytest.raises(ValidationError):
            AlgorithmRead(id="AES-256-GCM", kind="INVALID", family="AES", provider="openssl")


class TestKEKSchema:
    def test_valid_create_kek_request(self) -> None:
        req = CreateKEKRequest(label="pii.phone", purpose="FIELD_ENCRYPT", algorithm_id="AES-256-GCM")
        assert req.label == "pii.phone"

    def test_invalid_label_pattern(self) -> None:
        with pytest.raises(ValidationError):
            CreateKEKRequest(label="PII.PHONE", purpose="FIELD_ENCRYPT", algorithm_id="AES-256-GCM")

    def test_invalid_purpose(self) -> None:
        with pytest.raises(ValidationError):
            CreateKEKRequest(label="pii.phone", purpose="INVALID", algorithm_id="AES-256-GCM")

    def test_mark_for_destruction_requires_reason(self) -> None:
        with pytest.raises(ValidationError):
            MarkForDestructionRequest(reason="")  # empty string < min_length

    def test_reason_is_required(self) -> None:
        """Reason field accepts any non-empty string (min_length=1)."""
        req = MarkForDestructionRequest(reason="Compliance requirement met")
        assert len(req.reason) >= 1


class TestEnvelopeSchema:
    def test_valid_envelope(self) -> None:
        env = Envelope(
            schema_version=1,
            algorithm="AES-256-GCM",
            kek_id="kek_01J00000000000000000000001",
            kek_version=1,
            wrapped_dek_b64="YWJj",
            nonce_b64="MTIzNDU2Nzg5MDEy",
            ciphertext_b64="eHl6",
            aad={"user_id": "usr_1"},
        )
        assert env.schema_version == 1

    def test_encrypt_request_min_plaintext(self) -> None:
        with pytest.raises(ValidationError):
            EncryptRequest(key_label="pii.phone", plaintext_b64="")


class TestPasswordSchema:
    def test_valid_hash_request(self) -> None:
        req = PasswordHashRequest(password="test123")
        assert req.password == "test123"

    def test_empty_password_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PasswordHashRequest(password="")


class TestSignSchema:
    def test_valid_sign_request(self) -> None:
        req = SignRequest(key_label="audit.hashchain", data_b64="dGVzdA==")
        assert req.key_label == "audit.hashchain"
        assert req.detached is True

    def test_valid_verify_request(self) -> None:
        req = VerifyRequest(
            key_label="audit.hashchain",
            data_b64="dGVzdA==",
            signature_b64="c2ln",
        )
        assert req.key_label == "audit.hashchain"
