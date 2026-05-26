"""Permission definition schemas."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class PermissionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str = Field(min_length=3, max_length=120)
    service: str
    resource_type: str
    action: str
    description: str
    risk_level: RiskLevel
    requires_mfa: bool = False
    requires_4eyes: bool = False
    requires_pam_jit: bool = False
    requires_business_hours: bool = False
    is_system: bool = True
