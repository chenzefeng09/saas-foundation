"""Unit tests for foundation_storage.errors."""

from __future__ import annotations

import pytest

from foundation_storage.errors import (
    KEY_INVALID,
    OBJECT_LOCKED,
    OBJECT_NOT_FOUND,
    QUOTA_EXCEEDED,
    REGISTRY,
    KeyValidationError,
    ObjectLockedError,
    ObjectNotFoundError,
    QuotaExceededError,
    StorageError,
)


class TestErrorCodes:
    def test_quota_exceeded_code_and_status(self) -> None:
        assert QUOTA_EXCEEDED.code == "FOUNDATION.STORAGE.QUOTA.EXCEEDED"
        assert QUOTA_EXCEEDED.http_status == 429

    def test_object_not_found(self) -> None:
        assert OBJECT_NOT_FOUND.code == "FOUNDATION.STORAGE.OBJECT.NOT_FOUND"
        assert OBJECT_NOT_FOUND.http_status == 404

    def test_key_invalid(self) -> None:
        assert KEY_INVALID.code == "FOUNDATION.STORAGE.KEY.INVALID"
        assert KEY_INVALID.http_status == 400

    def test_object_locked(self) -> None:
        assert OBJECT_LOCKED.code == "FOUNDATION.STORAGE.OBJECT.LOCKED"
        assert OBJECT_LOCKED.http_status == 409

    def test_registry_has_codes_and_no_dupes(self) -> None:
        codes = [c.code for c in REGISTRY.codes]
        assert "FOUNDATION.STORAGE.QUOTA.EXCEEDED" in codes
        assert len(codes) == len(set(codes))


class TestExceptions:
    def test_quota_exceeded_extends_storage_error(self) -> None:
        e = QuotaExceededError(QUOTA_EXCEEDED, detail="too big")
        assert isinstance(e, StorageError)
        assert "FOUNDATION.STORAGE.QUOTA.EXCEEDED" in str(e)
        assert e.detail == "too big"

    def test_default_messages(self) -> None:
        e = ObjectNotFoundError(OBJECT_NOT_FOUND)
        assert e.detail == OBJECT_NOT_FOUND.default_detail
        assert e.user_message == OBJECT_NOT_FOUND.default_user_message

    def test_user_message_override(self) -> None:
        e = KeyValidationError(KEY_INVALID, user_message="客户提示")
        assert e.user_message == "客户提示"

    def test_object_locked_extra(self) -> None:
        e = ObjectLockedError(OBJECT_LOCKED, extra={"key": "k1"})
        assert e.extra == {"key": "k1"}

    def test_raise_and_catch(self) -> None:
        with pytest.raises(StorageError):
            raise QuotaExceededError(QUOTA_EXCEEDED)
