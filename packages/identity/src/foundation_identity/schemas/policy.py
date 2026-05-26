"""Password policy schemas."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class PasswordPolicyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    min_length: int = Field(ge=8, le=128)
    require_upper: bool
    require_lower: bool
    require_digit: bool
    require_symbol: bool
    max_age_days: int = Field(ge=1, le=365)
    history_size: int = Field(ge=1, le=24)
    max_failed_attempts: int = Field(ge=3, le=10)
    lockout_minutes: int = Field(ge=5, le=1440)
    breach_check_enabled: bool = False


class PasswordPolicyUpdate(BaseModel):
    """Server enforces 'only tighten, never relax' against compliance-mode floor."""

    model_config = ConfigDict(extra="forbid")

    min_length: int = Field(ge=8, le=128)
    require_upper: bool
    require_lower: bool
    require_digit: bool
    require_symbol: bool
    max_age_days: int = Field(ge=1, le=365)
    history_size: int = Field(ge=1, le=24)
    max_failed_attempts: int = Field(ge=3, le=10)
    lockout_minutes: int = Field(ge=5, le=1440)
    breach_check_enabled: bool = False
