"""Password-hash schemas."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class PasswordHashRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    password: str = Field(min_length=1, max_length=1024)
    # Optional overrides; default to settings.
    memory_kib: int | None = Field(default=None, ge=8192, le=1_048_576)
    time_cost: int | None = Field(default=None, ge=1, le=20)
    parallelism: int | None = Field(default=None, ge=1, le=16)


class PasswordHashResponse(BaseModel):
    # PHC string: $argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>
    encoded: str
    algorithm: str = "argon2id"


class PasswordVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    password: str = Field(min_length=1, max_length=1024)
    encoded: str = Field(min_length=1, max_length=512)


class PasswordVerifyResponse(BaseModel):
    valid: bool
    # When True, params have drifted from current policy; caller should re-hash.
    needs_rehash: bool = False
