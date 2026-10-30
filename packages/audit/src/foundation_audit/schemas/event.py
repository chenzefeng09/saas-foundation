"""Audit service — event schema (audit-v1 §3.1).

This is the canonical event shape that all services push. It mirrors
the ClickHouse `audit.events` table structure but lives as a Pydantic
model for validation + serialisation in the SDK.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["DEBUG", "INFO", "NOTICE", "WARN", "ERROR", "SECURITY", "CRITICAL"]
Outcome = Literal["SUCCESS", "FAILURE", "DENIED", "PARTIAL"]
ActorKind = Literal["USER", "SYSTEM", "ADMIN", "MIGRATOR", "SERVICE_ACCOUNT", "API_KEY"]

EVENT_ID_PATTERN = r"^evt_[0-9A-Z]{26}$"
REQUEST_ID_PATTERN = r"^req_[0-9A-Z]{26}$"


class AuditEvent(BaseModel):
    """Single audit event pushed by any service.

    The `payload` field holds the domain-specific detail JSON.
    `sensitive_fields` lists keys inside `payload` that should be
    masked before storage — the audit service delegates masking to
    data-protection-service.
    """

    model_config = ConfigDict(extra="forbid")

    # -- identifiers
    event_id: str = Field(pattern=EVENT_ID_PATTERN)
    schema_version: int = Field(default=1, ge=1)

    # -- time
    occurred_at: datetime

    # -- tenant
    tenant_id: str

    # -- source
    service: str
    service_version: str | None = None

    # -- event classification
    event_type: str = Field(min_length=1, max_length=200)
    severity: Severity = "INFO"
    outcome: Outcome = "SUCCESS"

    # -- actor
    actor_kind: ActorKind
    actor_user_id: str | None = None
    actor_api_key_id: str | None = None

    # -- target / resource
    resource_type: str | None = None
    resource_id: str | None = None
    resource_path: str | None = None

    # -- tracing
    request_id: str | None = Field(default=None, pattern=REQUEST_ID_PATTERN)
    trace_id: str | None = None
    span_id: str | None = None
    session_id: str | None = None
    parent_event_id: str | None = None

    # -- context
    ip: str | None = None
    user_agent: str | None = None
    country: str | None = None

    # -- payload (domain-specific detail; masked before storage)
    payload: dict[str, Any] = Field(default_factory=dict)
    sensitive_fields: list[str] = Field(default_factory=list)


class AuditEventStored(AuditEvent):
    """Event as stored in ClickHouse — with server-added fields."""

    ingested_at: datetime
    tsa_timestamp: datetime | None = None

    prev_hash: str | None = None
    curr_hash: str | None = None
    merkle_batch_id: str | None = None
    merkle_leaf_idx: int | None = None
    batch_signature: str | None = None

    worm_written: bool = False
    worm_uri: str | None = None


class AuditQuery(BaseModel):
    """Search/filter parameters for the query endpoint."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    service: str | None = None
    event_type: str | None = None
    event_types: list[str] | None = None
    severity: Severity | None = None
    outcome: Outcome | None = None
    actor_user_id: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    session_id: str | None = None
    request_id: str | None = None

    occurred_from: datetime | None = None
    occurred_to: datetime | None = None

    limit: int = Field(default=100, ge=1, le=1000)
    cursor: str | None = None  # next_cursor of the previous page (opaque keyset token)


class AuditQueryResult(BaseModel):
    items: list[AuditEventStored]
    next_cursor: str | None = None
    total_estimate: int | None = None
