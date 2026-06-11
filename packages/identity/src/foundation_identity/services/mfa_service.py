"""MFA (Multi-Factor Authentication) service.

Supported method: TOTP (RFC 6238) — implemented with stdlib hmac/hashlib/base64
so no extra dependency (pyotp) is required.

Flow:
  1. enroll()       → generates a TOTP secret + QR URL; stores an un-confirmed MfaMethod row
  2. confirm()      → verifies first code; marks method confirmed (disabled_at=None)
  3. list_methods() → returns all non-disabled methods for a user
  4. delete()       → removes a specific method (audit-logged)
  5. begin_challenge()  → creates a short-lived Redis challenge key
  6. verify_challenge() → checks the supplied TOTP code

Challenge state lives in Redis (TTL keys, ``mfa:challenge:{id}``) so it works
across multiple service replicas and self-expires.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import time
import urllib.parse
from datetime import UTC, datetime

import ulid
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_identity.adapters.audit_publisher import AuditPublisher
from foundation_identity.adapters.keycloak_admin import KeycloakAdminAdapter
from foundation_identity.adapters.notification_gateway import NotificationGateway
from foundation_identity.adapters.redis_cache import RedisCacheAdapter
from foundation_identity.config import get_settings
from foundation_identity.domain.models import MfaMethod, RecoveryCode, User
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

# Challenge state is stored in Redis under this key prefix with a TTL.
_CHALLENGE_KEY_PREFIX = "mfa:challenge:"
_SMS_CHALLENGE_KEY_PREFIX = "mfa:sms_challenge:"
_CHALLENGE_TTL_SECONDS = 300  # 5 minutes
_SMS_CODE_LENGTH = 6


def _new_id(prefix: str) -> str:
    return f"{prefix}_{ulid.new()!s}"


# ── secret-at-rest encryption (Fernet) ───────────────────────────────────────#

def _fernet() -> Fernet:
    """Fernet built from the configured MFA encryption key."""
    key = get_settings().mfa_secret_encryption_key.get_secret_value()
    return Fernet(key.encode())


def _encrypt_secret(plaintext: str) -> str:
    """Encrypt a TOTP secret for storage in ``mfa_method.secret_ref``."""
    return _fernet().encrypt(plaintext.encode()).decode()


def _decrypt_secret(stored: str) -> str:
    """Decrypt a stored TOTP secret.

    Tolerates legacy plaintext rows: if the value is not a valid Fernet token
    (rows written before encryption was introduced), it is returned as-is so
    existing enrolments keep working until they re-enrol.
    """
    try:
        return _fernet().decrypt(stored.encode()).decode()
    except InvalidToken:
        return stored


# ── recovery codes ───────────────────────────────────────────────────────────#

def _hash_recovery_code(code: str) -> str:
    """SHA-256 hex of a recovery code (codes are high-entropy, no salt needed)."""
    return hashlib.sha256(code.encode()).hexdigest()


def _generate_recovery_code() -> str:
    """A human-friendly one-time code, e.g. ``abcd-efgh-ijkl`` (lowercase a-z0-9)."""
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    raw = "".join(secrets.choice(alphabet) for _ in range(12))
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"


def _mask_phone(phone: str) -> str:
    """Show only the last four digits of a phone number (for labels / logs)."""
    suffix = phone[-4:] if len(phone) >= 4 else phone
    return f"***{suffix}"


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
        cache: RedisCacheAdapter,
        notification: NotificationGateway | None = None,
    ) -> None:
        self._kc = keycloak
        self._audit = audit
        self._cache = cache
        self._notification = notification or NotificationGateway()

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
                kind=m.kind,
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
            # Encrypted at rest (Fernet); plaintext is only shown to the user
            # below for QR provisioning, never persisted.
            secret_ref=_encrypt_secret(secret),
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

        if not _verify_totp(_decrypt_secret(method.secret_ref), code):
            raise FoundationError(MFA_CODE_INVALID)

        # Activate
        method.disabled_at = None
        method.last_used_at = datetime.now(UTC)
        await session.flush()

        # Mark user as mfa_enabled; first-time enablement also mints recovery
        # codes (returned in plaintext exactly once).
        user_row = await session.execute(
            select(User).where(User.tenant_id == tenant_id, User.id == user_id)
        )
        user = user_row.scalar_one_or_none()
        first_enablement = user is not None and not user.mfa_enabled
        recovery_codes: list[str] | None = None
        if user is not None:
            user.mfa_enabled = True
            await session.flush()
        if first_enablement:
            recovery_codes = await self._mint_recovery_codes(
                session, tenant_id=tenant_id, user_id=user_id
            )

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
            recovery_codes=recovery_codes,
        )

    # ── recovery codes ───────────────────────────────────────────────────── #

    async def _mint_recovery_codes(
        self, session: AsyncSession, *, tenant_id: str, user_id: str
    ) -> list[str]:
        """Generate, store (hashed), and return a fresh batch of recovery codes.

        Any existing unused codes for the user are dropped first so a re-mint
        invalidates the old set.  Returns the plaintext codes for one-time
        display; only their SHA-256 hashes are persisted.
        """
        # Invalidate prior unused codes (re-mint supersedes them).
        existing = await session.execute(
            select(RecoveryCode).where(
                RecoveryCode.tenant_id == tenant_id,
                RecoveryCode.user_id == user_id,
                RecoveryCode.used_at.is_(None),
            )
        )
        now = datetime.now(UTC)
        for row in existing.scalars().all():
            row.used_at = now

        count = get_settings().mfa_recovery_code_count
        plaintext: list[str] = []
        for _ in range(count):
            code = _generate_recovery_code()
            plaintext.append(code)
            session.add(
                RecoveryCode(
                    id=_new_id("rec"),
                    tenant_id=tenant_id,
                    user_id=user_id,
                    code_hash=_hash_recovery_code(code),
                )
            )
        await session.flush()
        return plaintext

    # ── step-up gating ───────────────────────────────────────────────────── #

    async def require_recent_mfa(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        user_id: str,
    ) -> None:
        """Gate a sensitive action on a recent MFA-satisfied session.

        If the actor has MFA enabled, the most recent active session for them
        MUST carry ``mfa_satisfied=True``.  Users without MFA enabled are
        passed through unchanged (there is no second factor to gate on).

        Raises ``MFA_REQUIRED`` when the gate would fail.
        """
        from foundation_identity.domain.models import Session as SessionModel

        user_row = await session.execute(
            select(User).where(User.tenant_id == tenant_id, User.id == user_id)
        )
        user = user_row.scalar_one_or_none()
        if user is None or not user.mfa_enabled:
            return
        now = datetime.now(UTC)
        rows = await session.execute(
            select(SessionModel)
            .where(
                SessionModel.tenant_id == tenant_id,
                SessionModel.user_id == user_id,
                SessionModel.revoked_at.is_(None),
                SessionModel.expires_at > now,
            )
            .order_by(SessionModel.issued_at.desc())
            .limit(1)
        )
        latest = rows.scalar_one_or_none()
        if latest is None or not latest.mfa_satisfied:
            raise FoundationError(
                MFA_REQUIRED,
                detail="This action requires a recent MFA-verified session",
            )

    # ── admin reset (privileged) ─────────────────────────────────────────── #

    async def admin_reset_user_mfa(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        actor_id: str,
        user_id: str,
        request_id: str,
    ) -> None:
        """Wipe all MFA state for a user (admin recovery path).

        Soft-deletes every active MfaMethod, voids any unused recovery codes,
        clears ``user.mfa_enabled`` so the password-only login path is
        re-enabled, and removes the user's WebAuthn + OTP credentials at
        Keycloak.  Audited as a SECURITY-class event.

        Caller is responsible for the authz check (only platform / tenant
        admins should be able to invoke this).
        """
        now = datetime.now(UTC)

        # 1) Soft-delete active MFA methods.
        methods = await session.execute(
            select(MfaMethod).where(
                MfaMethod.tenant_id == tenant_id,
                MfaMethod.user_id == user_id,
                MfaMethod.disabled_at.is_(None),
            )
        )
        for m in methods.scalars().all():
            m.disabled_at = now

        # 2) Void unused recovery codes.
        recs = await session.execute(
            select(RecoveryCode).where(
                RecoveryCode.tenant_id == tenant_id,
                RecoveryCode.user_id == user_id,
                RecoveryCode.used_at.is_(None),
            )
        )
        for r in recs.scalars().all():
            r.used_at = now

        # 3) Flip the user-level flag back to "no MFA".
        user_row = await session.execute(
            select(User).where(User.tenant_id == tenant_id, User.id == user_id)
        )
        user = user_row.scalar_one_or_none()
        if user is None:
            raise FoundationError(USER_NOT_FOUND)
        user.mfa_enabled = False
        await session.flush()

        # 4) Best-effort: clear KC-side OTP + WebAuthn credentials.
        if user.keycloak_user_id:
            try:
                kc_creds = await self._kc.list_credentials(user.keycloak_user_id)
                for c in kc_creds:
                    if c.get("type", "") in (
                        "otp", "webauthn", "webauthn-passwordless",
                    ):
                        try:
                            await self._kc.delete_credential(
                                user.keycloak_user_id, c.get("id", "")
                            )
                        except FoundationError:
                            log.warning(
                                "mfa.admin_reset.kc_delete_failed",
                                user_id=user_id,
                                credential_id=c.get("id"),
                            )
            except FoundationError:
                log.warning("mfa.admin_reset.kc_list_failed", user_id=user_id)

        await self._audit.publish(
            session,
            event_type="foundation.identity.mfa.admin_reset",
            tenant_id=tenant_id,
            aggregate_id=user_id,
            payload={
                "user_id": user_id,
                "actor_id": actor_id,
                "severity": "SECURITY",
            },
            request_id=request_id,
        )

    # ── SMS OTP ─────────────────────────────────────────────────────────── #

    async def enroll_sms(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        user_id: str,
        request_id: str,
        phone: str,
        label: str | None = None,
    ) -> MfaMethodRead:
        """Register a phone number for SMS-OTP delivery.

        The phone number is stored encrypted (same Fernet key as TOTP secrets);
        SMS codes themselves are short-lived Redis entries, never persisted.
        Method is enabled immediately — there's no separate confirm step for
        SMS in this flow (admin can require one via a separate confirm path
        if desired).
        """
        user_row = await session.execute(
            select(User).where(User.tenant_id == tenant_id, User.id == user_id)
        )
        user = user_row.scalar_one_or_none()
        if user is None:
            raise FoundationError(USER_NOT_FOUND)

        method_id = _new_id("mfa")
        now = datetime.now(UTC)
        method = MfaMethod(
            id=method_id,
            tenant_id=tenant_id,
            user_id=user_id,
            kind="SMS_OTP",
            label=label or f"SMS to {_mask_phone(phone)}",
            secret_ref=_encrypt_secret(phone),
            enrolled_at=now,
        )
        session.add(method)
        await session.flush()

        await self._audit.publish(
            session,
            event_type="foundation.identity.mfa.sms_enrolled",
            tenant_id=tenant_id,
            aggregate_id=user_id,
            payload={"method_id": method_id, "phone_suffix": phone[-4:]},
            request_id=request_id,
        )
        return MfaMethodRead(
            id=method_id,
            kind="SMS_OTP",
            label=method.label,
            enrolled_at=now,
            last_used_at=None,
        )

    async def send_sms_challenge(
        self,
        *,
        challenge_id: str,
        phone: str,
    ) -> None:
        """Generate a 6-digit code, stash it in Redis, dispatch the SMS.

        Code is single-use: ``verify_sms_challenge`` deletes the entry on
        success.  Fail-secure: if Redis write fails, the SMS is NOT sent and
        the failure propagates so the caller can refuse the challenge.
        """
        code = "".join(secrets.choice("0123456789") for _ in range(_SMS_CODE_LENGTH))
        await self._cache.set(
            _SMS_CHALLENGE_KEY_PREFIX + challenge_id,
            code,
            ttl_seconds=_CHALLENGE_TTL_SECONDS,
        )
        await self._notification.send_sms(
            phone=phone,
            body=f"Your verification code is {code} (valid for 5 minutes).",
        )

    async def verify_sms_challenge(
        self, *, challenge_id: str, code: str
    ) -> bool:
        """Match a submitted SMS code against the stashed one; single-use."""
        key = _SMS_CHALLENGE_KEY_PREFIX + challenge_id
        expected = await self._cache.get(key)
        if expected is None:
            return False
        if not hmac.compare_digest(expected, code):
            return False
        await self._cache.delete(key)
        return True

    # ── WebAuthn (delegated to Keycloak) ─────────────────────────────────── #

    async def list_webauthn_credentials(
        self, session: AsyncSession, *, tenant_id: str, user_id: str
    ) -> list[dict[str, str]]:
        """Return the user's WebAuthn keys registered at Keycloak.

        Resolves ``keycloak_user_id`` from the local user row, lists all KC
        credentials, and projects only the WebAuthn entries (``webauthn`` and
        ``webauthn-passwordless``) into a UI-friendly shape.
        """
        sub = await self._resolve_kc_sub(session, tenant_id=tenant_id, user_id=user_id)
        creds = await self._kc.list_credentials(sub)
        out: list[dict[str, str]] = []
        for c in creds:
            kind = c.get("type", "")
            if not kind.startswith("webauthn"):
                continue
            out.append(
                {
                    "id": str(c.get("id", "")),
                    "type": kind,
                    "label": str(c.get("userLabel") or ""),
                    "created_at": str(c.get("createdDate") or ""),
                }
            )
        return out

    async def trigger_webauthn_register(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        user_id: str,
        request_id: str,
        passwordless: bool = False,
    ) -> None:
        """Email the user a Keycloak required-action link to register a key.

        Keycloak handles the WebAuthn ceremony in its self-service pages
        (``navigator.credentials.create`` runs there).  We just trigger the
        required action; on next interactive login the user completes
        enrolment and a credential of type ``webauthn`` (or
        ``webauthn-passwordless``) appears at KC.
        """
        sub = await self._resolve_kc_sub(session, tenant_id=tenant_id, user_id=user_id)
        action = "webauthn-register-passwordless" if passwordless else "webauthn-register"
        await self._kc.trigger_required_action(sub, action=action)
        await self._audit.publish(
            session,
            event_type="foundation.identity.mfa.webauthn_register_triggered",
            tenant_id=tenant_id,
            aggregate_id=user_id,
            payload={"action": action},
            request_id=request_id,
        )

    async def delete_webauthn_credential(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        user_id: str,
        request_id: str,
        credential_id: str,
    ) -> None:
        """Remove a single WebAuthn key at Keycloak (revokes that authenticator)."""
        sub = await self._resolve_kc_sub(session, tenant_id=tenant_id, user_id=user_id)
        await self._kc.delete_credential(sub, credential_id)
        await self._audit.publish(
            session,
            event_type="foundation.identity.mfa.webauthn_credential_deleted",
            tenant_id=tenant_id,
            aggregate_id=user_id,
            payload={"credential_id": credential_id},
            request_id=request_id,
        )

    async def _resolve_kc_sub(
        self, session: AsyncSession, *, tenant_id: str, user_id: str
    ) -> str:
        """Look up the foundation user's Keycloak subject (``keycloak_user_id``)."""
        result = await session.execute(
            select(User).where(
                User.tenant_id == tenant_id,
                User.id == user_id,
                User.deleted_at.is_(None),
            )
        )
        user = result.scalar_one_or_none()
        if user is None or not user.keycloak_user_id:
            raise FoundationError(
                USER_NOT_FOUND, detail="User has no linked Keycloak subject"
            )
        return user.keycloak_user_id

    async def verify_recovery_code(
        self, session: AsyncSession, *, tenant_id: str, user_id: str, code: str
    ) -> bool:
        """Redeem a one-time recovery code; returns True on success.

        The matched code is marked used (single-use).  A non-matching or
        already-used code returns False without side effects.
        """
        code_hash = _hash_recovery_code(code.strip().lower())
        result = await session.execute(
            select(RecoveryCode).where(
                RecoveryCode.tenant_id == tenant_id,
                RecoveryCode.user_id == user_id,
                RecoveryCode.code_hash == code_hash,
                RecoveryCode.used_at.is_(None),
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            return False
        row.used_at = datetime.now(UTC)
        await session.flush()
        return True

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

        kinds = list({m.kind for m in methods})
        challenge_id = _new_id("chal")

        # Store secrets keyed by challenge; first TOTP method wins for verify.
        # The secret_ref is encrypted at rest — decrypt once here so the short-
        # lived challenge entry carries the plaintext the TOTP check needs.
        # Redis TTL handles expiry — no manual exp bookkeeping needed.
        totp_method = next((m for m in methods if m.kind == "TOTP"), None)
        challenge_secret = (
            _decrypt_secret(totp_method.secret_ref)
            if totp_method and totp_method.secret_ref
            else None
        )
        await self._cache.set(
            _CHALLENGE_KEY_PREFIX + challenge_id,
            json.dumps(
                {
                    "user_id": user_id,
                    "tenant_id": tenant_id,
                    "secret": challenge_secret,
                }
            ),
            ttl_seconds=_CHALLENGE_TTL_SECONDS,
        )

        from datetime import timedelta

        return MfaChallengeResponse(
            challenge_id=challenge_id,
            methods=kinds,
            expires_at=datetime.now(UTC) + timedelta(seconds=_CHALLENGE_TTL_SECONDS),
        )

    async def verify_challenge(
        self,
        *,
        challenge_id: str,
        code: str,
    ) -> str:
        """Verify a TOTP code against a challenge; returns user_id on success."""
        key = _CHALLENGE_KEY_PREFIX + challenge_id
        raw = await self._cache.get(key)
        if raw is None:
            # Absent → expired (TTL) or never existed.
            raise FoundationError(MFA_CODE_INVALID, detail="Challenge expired or not found")
        entry = json.loads(raw)

        secret = entry.get("secret")
        if secret is None:
            raise FoundationError(MFA_CODE_INVALID, detail="No TOTP secret for challenge")

        if not _verify_totp(secret, code):
            raise FoundationError(MFA_CODE_INVALID)

        # Single-use: consume the challenge on success.
        await self._cache.delete(key)
        user_id: str = entry["user_id"]
        return user_id
