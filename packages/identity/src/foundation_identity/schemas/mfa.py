"""MFA schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

MfaKind = Literal["TOTP", "SMS_OTP", "WEBAUTHN", "PUSH"]


class MfaMethodRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    kind: MfaKind
    label: str | None = None
    enrolled_at: datetime
    last_used_at: datetime | None = None
    recovery_codes: list[str] | None = Field(
        default=None,
        description=(
            "One-time recovery codes, returned ONLY on the first MFA enrolment "
            "(plaintext shown once; only hashes are stored). Null on subsequent "
            "confirmations."
        ),
    )


class MfaEnrollResponse(BaseModel):
    enrollment_id: str
    secret: str
    qr_url: str


class MfaConfirmRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enrollment_id: str
    code: str = Field(pattern=r"^[0-9]{6}$")


class MfaChallengeResponse(BaseModel):
    challenge_id: str
    methods: list[MfaKind]
    expires_at: datetime


class MfaVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge_id: str
    method: MfaKind
    code: str


class WebAuthnCredentialRead(BaseModel):
    """A WebAuthn key registered at Keycloak."""

    id: str
    type: str  # "webauthn" or "webauthn-passwordless"
    label: str
    created_at: str


class WebAuthnRegisterRequest(BaseModel):
    """Trigger a Keycloak required-action email to enrol a new key."""

    model_config = ConfigDict(extra="forbid")

    passwordless: bool = False


class SmsEnrollRequest(BaseModel):
    """Register a phone number for SMS-OTP delivery."""

    model_config = ConfigDict(extra="forbid")

    phone: str = Field(min_length=4, max_length=32)
    label: str | None = None
