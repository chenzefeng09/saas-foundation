"""Password hashing — Argon2id via argon2-cffi.

Identity service stores hashes in Keycloak (not in our DB), so this adapter
is used only for:
  * password-strength check before sending to Keycloak
  * out-of-band password reset flows
"""

from __future__ import annotations

from argon2 import PasswordHasher as _Argon2
from argon2.exceptions import InvalidHash, VerifyMismatchError


class PasswordHasher:
    """Thin Argon2id wrapper with policy-aligned defaults.

    Parameters chosen per OWASP recommendations (2024):
      * time_cost   = 3
      * memory_cost = 64 MiB
      * parallelism = 4
      * hash_len    = 32 bytes
      * salt_len    = 16 bytes
    """

    def __init__(self) -> None:
        self._h = _Argon2(time_cost=3, memory_cost=64 * 1024, parallelism=4, hash_len=32)

    def hash(self, password: str) -> str:
        return self._h.hash(password)

    def verify(self, hashed: str, password: str) -> bool:
        try:
            return self._h.verify(hashed, password)
        except (VerifyMismatchError, InvalidHash):
            return False

    def needs_rehash(self, hashed: str) -> bool:
        return self._h.check_needs_rehash(hashed)


_singleton: PasswordHasher | None = None


def get_password_hasher() -> PasswordHasher:
    global _singleton
    if _singleton is None:
        _singleton = PasswordHasher()
    return _singleton
