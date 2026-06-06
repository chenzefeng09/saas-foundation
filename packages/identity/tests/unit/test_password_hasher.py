"""Tests for Argon2 password hashing adapter."""

from __future__ import annotations

import pytest

from foundation_identity.adapters import password_hasher as module
from foundation_identity.adapters.password_hasher import PasswordHasher, get_password_hasher


@pytest.mark.unit
def test_password_hasher_hashes_and_verifies_password() -> None:
    hasher = PasswordHasher()

    hashed = hasher.hash("CorrectHorseBatteryStaple!1")

    assert hashed.startswith("$argon2")
    assert hasher.verify(hashed, "CorrectHorseBatteryStaple!1") is True
    assert hasher.verify(hashed, "wrong-password") is False
    assert hasher.verify("not-a-valid-hash", "CorrectHorseBatteryStaple!1") is False
    assert hasher.needs_rehash(hashed) is False


@pytest.mark.unit
def test_get_password_hasher_returns_singleton(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(module, "_singleton", None)

    first = get_password_hasher()
    second = get_password_hasher()

    assert first is second
