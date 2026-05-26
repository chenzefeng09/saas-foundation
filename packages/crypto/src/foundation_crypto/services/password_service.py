"""Password hashing service (crypto-v1 §9).

Uses Argon2id (OWASP recommended parameters).
  - Default: memory=64MiB, time_cost=3, parallelism=4, hash_len=32, salt_len=16.
  - Output: PHC string format ($argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>).
  - verify: auto-detects parameters from the PHC string.
  - needs_rehash: when the stored hash uses weaker params than current policy,
    the caller should re-hash the password on next successful login.

SM3 pre-hash for 国密 mode is deferred to v1.1 (Tongsuo integration).
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError

from foundation_crypto.config import get_settings
from foundation_crypto.observability import get_logger
from foundation_crypto.schemas.password import (
    PasswordHashRequest,
    PasswordHashResponse,
    PasswordVerifyRequest,
    PasswordVerifyResponse,
)

log = get_logger(__name__)


class PasswordService:
    """Stateless password hashing via Argon2id."""

    def hash(self, request: PasswordHashRequest) -> PasswordHashResponse:
        settings = get_settings()
        ph = PasswordHasher(
            memory_cost=request.memory_kib or settings.argon2_memory_kib,
            time_cost=request.time_cost or settings.argon2_time_cost,
            parallelism=request.parallelism or settings.argon2_parallelism,
            hash_len=settings.argon2_hash_len,
            salt_len=settings.argon2_salt_len,
        )
        encoded = ph.hash(request.password)
        return PasswordHashResponse(encoded=encoded, algorithm="argon2id")

    def verify(self, request: PasswordVerifyRequest) -> PasswordVerifyResponse:
        settings = get_settings()
        ph = PasswordHasher()

        try:
            valid = ph.verify(request.encoded, request.password)
        except (VerificationError, InvalidHashError):
            return PasswordVerifyResponse(valid=False)

        if not valid:
            return PasswordVerifyResponse(valid=False)

        # Check if rehash needed (stored hash params weaker than current policy)
        needs_rehash = ph.check_needs_rehash(
            request.encoded,
        ) or self._params_weaker_than_policy(request.encoded, settings)

        return PasswordVerifyResponse(valid=True, needs_rehash=needs_rehash)

    @staticmethod
    def _params_weaker_than_policy(encoded: str, settings) -> bool:  # type: ignore[no-untyped-def]
        """Heuristic: rehash if stored memory/time/parallelism is lower than current."""
        try:
            ph = PasswordHasher()
            params = ph.extract_parameters(encoded)
            return (
                params.memory_cost < settings.argon2_memory_kib
                or params.time_cost < settings.argon2_time_cost
                or params.parallelism < settings.argon2_parallelism
            )
        except Exception:
            # Can't parse → rehash to be safe
            return True
