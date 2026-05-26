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
