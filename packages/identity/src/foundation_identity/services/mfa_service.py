"""MFA (Multi-Factor Authentication) service.

Supported method: TOTP (RFC 6238) — implemented with stdlib hmac/hashlib/base64
so no extra dependency (pyotp) is required.

Flow:
  1. enroll()       → generates a TOTP secret + QR URL; stores an un-confirmed MfaMethod row
  2. confirm()      → verifies first code; marks method confirmed (disabled_at=None)
  3. list_methods() → returns all non-disabled methods for a user
  4. delete()       → removes a specific method (audit-logged)
  5. begin_challenge()  → creates an in-memory (or short-lived Redis-like key) challenge
  6. verify_challenge() → checks the supplied TOTP code

In M2 the "challenge" state is held in-process (dict). For production, replace with
Redis TTL keys or a `mfa_challenge` DB table.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time
import urllib.parse
from datetime import UTC, datetime
from typing import Any

import ulid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_identity.adapters.audit_publisher import AuditPublisher
from foundation_identity.adapters.keycloak_admin import KeycloakAdminAdapter
from foundation_identity.domain.models import MfaMethod, User
from foundation_identity.errors import (
    MFA_CODE_INVALID,
    MFA_REQUIRED,
    USER_NOT_FOUND,
    FoundationError,
)
from foundation_identity.observability import get_logger
from foundation_identity.schemas.mfa import (
    MfaChallengeResponse,
    MfaEnrollResponse,
    MfaMethodRead,
)

log = get_logger(__name__)

# ── In-process challenge store (replace with Redis in production) ──────────── #
# key: challenge_id → {"user_id": str, "tenant_id": str, "secret": str, "exp": float}
_challenges: dict[str, dict[str, Any]] = {}
_CHALLENGE_TTL_SECONDS = 300  # 5 minutes


def _new_id(prefix: str) -> str:
    return f"{prefix}_{ulid.new()!s}"


# ── TOTP helpers (RFC 6238 / RFC 4226) ───────────────────────────────────────#

def _hotp(secret_b32: str, counter: int, digits: int = 6) -> str:
    """Compute one HMAC-OTP value for the given counter."""
    key = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10**digits)).zfill(digits)


def _totp(secret_b32: str, t: float | None = None, step: int = 30, digits: int = 6) -> str:
    """Compute the current TOTP value."""
    counter = int((t if t is not None else time.time()) // step)
    return _hotp(secret_b32, counter, digits)


def _verify_totp(secret_b32: str, code: str, window: int = 1) -> bool:
    """Accept current + ±window steps to handle clock skew."""
    now = time.time()
    step = 30
    for delta in range(-window, window + 1):
        expected = _totp(secret_b32, t=now + delta * step, step=step)
        if hmac.compare_digest(expected, code):
            return True
    return False


def _new_totp_secret() -> str:
    """Generate a 20-byte random secret encoded as base32 (no padding)."""
    raw = os.urandom(20)
    return base64.b32encode(raw).decode().rstrip("=")


def _totp_qr_url(secret: str, user_email: str, issuer: str = "SaaS Foundation") -> str:
    label = urllib.parse.quote(f"{issuer}:{user_email}")
    params = urllib.parse.urlencode(
        {
            "secret": secret,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": "6",
            "period": "30",
        }
    )
    return f"otpauth://totp/{label}?{params}"


# ── Service class ─────────────────────────────────────────────────────────────#


class MfaService:
    """MFA lifecycle — TOTP enrol/verify; Keycloak credential sync optional."""

    def __init__(
        self,
        keycloak: KeycloakAdminAdapter,
        audit: AuditPublisher,
    ) -> None:
        self._kc = keycloak
        self._audit = audit

    # ── list ─────────────────────────────────────────────────────────────── #

    async def list_methods(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        user_id: str,
    ) -> list[MfaMethodRead]:
        """Return all active (non-disabled) MFA methods for the user."""
        result = await session.execute(
            select(MfaMethod).where(
                MfaMethod.tenant_id == tenant_id,
                MfaMethod.user_id == user_id,
                MfaMethod.disabled_at.is_(None),
            )
        )
        methods = result.scalars().all()
        return [
            MfaMethodRead(
                id=m.id,
                kind=m.kind,  # type: ignore[arg-type]
                label=m.label,
                enrolled_at=m.enrolled_at,
                last_used_at=m.last_used_at,
            )
            for m in methods
        ]

    # ── enroll ───────────────────────────────────────────────────────────── #

    async def enroll(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        user_id: str,
        request_id: str,
        label: str | None = None,
    ) -> MfaEnrollResponse:
        """Begin TOTP enrollment: create an un-confirmed MfaMethod, return secret + QR URL."""
        # Ensure the user exists
        user_row = await session.execute(
            select(User).where(User.tenant_id == tenant_id, User.id == user_id)
        )
        user = user_row.scalar_one_or_none()
        if user is None:
            raise FoundationError(USER_NOT_FOUND)

        secret = _new_totp_secret()
        method_id = _new_id("mfa")
        now = datetime.now(UTC)

        method = MfaMethod(
            id=method_id,
            tenant_id=tenant_id,
            user_id=user_id,
            kind="TOTP",
            label=label or "Authenticator App",
            secret_ref=secret,  # In production: write to Vault; store Vault path here
            enrolled_at=now,
            disabled_at=now,  # Disabled until confirmed
        )
        session.add(method)
        await session.flush()

        log.info(
            "mfa.enroll.started",
            tenant_id=tenant_id,
            user_id=user_id,
            method_id=method_id,
            request_id=request_id,
        )

        email = user.email
        qr_url = _totp_qr_url(secret, email)

        return MfaEnrollResponse(
            enrollment_id=method_id,
            secret=secret,
            qr_url=qr_url,
        )

    # ── confirm enrollment ────────────────────────────────────────────────── #

    async def confirm_enrollment(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        user_id: str,
        request_id: str,
        enrollment_id: str,
        code: str,
    ) -> MfaMethodRead:
        """Verify the first TOTP code and activate the method."""
        result = await session.execute(
            select(MfaMethod).where(
                MfaMethod.tenant_id == tenant_id,
                MfaMethod.user_id == user_id,
                MfaMethod.id == enrollment_id,
            )
        )
        method = result.scalar_one_or_none()
        if method is None:
            raise FoundationError(MFA_CODE_INVALID, detail="Enrollment not found")

        if method.secret_ref is None:
            raise FoundationError(MFA_CODE_INVALID, detail="Method has no secret")

        if not _verify_totp(method.secret_ref, code):
            raise FoundationError(MFA_CODE_INVALID)

        # Activate
        method.disabled_at = None
        method.last_used_at = datetime.now(UTC)
        await session.flush()

        # Mark user as mfa_enabled
        user_row = await session.execute(
            select(User).where(User.tenant_id == tenant_id, User.id == user_id)
        )
        user = user_row.scalar_one_or_none()
        if user is not None:
            user.mfa_enabled = True
            await session.flush()

        await self._audit.publish(
            session,
            event_type="foundation.identity.mfa.enrolled",
            tenant_id=tenant_id,
            aggregate_id=user_id,
            payload={"method_id": enrollment_id, "kind": "TOTP"},
            request_id=request_id,
        )

        log.info(
            "mfa.enroll.confirmed",
            tenant_id=tenant_id,
            user_id=user_id,
            method_id=enrollment_id,
            request_id=request_id,
        )

        return MfaMethodRead(
            id=method.id,
            kind="TOTP",
            label=method.label,
            enrolled_at=method.enrolled_at,
            last_used_at=method.last_used_at,
        )

    # ── delete ───────────────────────────────────────────────────────────── #

    async def delete_method(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        user_id: str,
        request_id: str,
        method_id: str,
    ) -> None:
        """Soft-delete a MFA method (sets disabled_at)."""
        result = await session.execute(
            select(MfaMethod).where(
                MfaMethod.tenant_id == tenant_id,
                MfaMethod.user_id == user_id,
                MfaMethod.id == method_id,
                MfaMethod.disabled_at.is_(None),
            )
        )
        method = result.scalar_one_or_none()
        if method is None:
            raise FoundationError(MFA_CODE_INVALID, detail="MFA method not found")

        method.disabled_at = datetime.now(UTC)
        await session.flush()

        await self._audit.publish(
            session,
            event_type="foundation.identity.mfa.deleted",
            tenant_id=tenant_id,
            aggregate_id=user_id,
            payload={"method_id": method_id},
            request_id=request_id,
        )

    # ── challenge / verify ───────────────────────────────────────────────── #

    async def begin_challenge(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        user_id: str,
    ) -> MfaChallengeResponse:
        """Issue a challenge; client must call verify_challenge() with the TOTP code."""
        result = await session.execute(
            select(MfaMethod).where(
                MfaMethod.tenant_id == tenant_id,
                MfaMethod.user_id == user_id,
                MfaMethod.disabled_at.is_(None),
            )
        )
        methods = result.scalars().all()
        if not methods:
            raise FoundationError(MFA_REQUIRED, detail="No active MFA method found")

        kinds = list({m.kind for m in methods})  # type: ignore[misc]
        challenge_id = _new_id("chal")
        exp = time.time() + _CHALLENGE_TTL_SECONDS

        # Store secrets keyed by challenge; first TOTP method wins for verify
        totp_method = next((m for m in methods if m.kind == "TOTP"), None)
        _challenges[challenge_id] = {
            "user_id": user_id,
            "tenant_id": tenant_id,
            "secret": totp_method.secret_ref if totp_method else None,
            "exp": exp,
        }

        from datetime import timedelta

        return MfaChallengeResponse(
            challenge_id=challenge_id,
            methods=kinds,  # type: ignore[arg-type]
            expires_at=datetime.now(UTC) + timedelta(seconds=_CHALLENGE_TTL_SECONDS),
        )

    async def verify_challenge(
        self,
        *,
        challenge_id: str,
        code: str,
    ) -> str:
        """Verify a TOTP code against a challenge; returns user_id on success."""
        entry = _challenges.get(challenge_id)
        if entry is None or entry["exp"] < time.time():
            _challenges.pop(challenge_id, None)
            raise FoundationError(MFA_CODE_INVALID, detail="Challenge expired or not found")

        secret = entry.get("secret")
        if secret is None:
            raise FoundationError(MFA_CODE_INVALID, detail="No TOTP secret for challenge")

        if not _verify_totp(secret, code):
            raise FoundationError(MFA_CODE_INVALID)

        _challenges.pop(challenge_id, None)
        return entry["user_id"]
