"""Schema tests for audit events."""

import pytest
from pydantic import ValidationError

from foundation_audit.schemas.event import AuditEvent, AuditQuery


class TestAuditEvent:
    def test_minimal_event(self) -> None:
        from datetime import UTC, datetime

        event = AuditEvent(
            event_id="evt_01J00000000000000000000001",
            occurred_at=datetime.now(UTC),
            tenant_id="tnt_01J0000000000000000000TNT1",
            service="identity",
            event_type="foundation.identity.user.login_success",
            actor_kind="USER",
            actor_user_id="usr_01J0000000000000000000USR1",
        )
        assert event.event_id.startswith("evt_")
        assert event.schema_version == 1
        assert event.severity == "INFO"
        assert event.outcome == "SUCCESS"

    def test_invalid_event_id(self) -> None:
        from datetime import UTC, datetime
        with pytest.raises(ValidationError):
            AuditEvent(
                event_id="invalid-id",
                occurred_at=datetime.now(UTC),
                tenant_id="tnt_01J0000000000000000000TNT1",
                service="identity",
                event_type="test",
                actor_kind="USER",
            )

    def test_severity(self) -> None:
        from datetime import UTC, datetime
        event = AuditEvent(
            event_id="evt_01J00000000000000000000001",
            occurred_at=datetime.now(UTC),
            tenant_id="tnt_01J0000000000000000000TNT1",
            service="identity",
            event_type="test",
            severity="CRITICAL",
            actor_kind="SYSTEM",
        )
        assert event.severity == "CRITICAL"

    def test_invalid_severity(self) -> None:
        from datetime import UTC, datetime
        with pytest.raises(ValidationError):
            AuditEvent(
                event_id="evt_01J00000000000000000000001",
                occurred_at=datetime.now(UTC),
                tenant_id="tnt_01J0000000000000000000TNT1",
                service="identity",
                event_type="test",
                severity="INVALID",  # type: ignore[arg-type]
                actor_kind="USER",
            )

    def test_payload_with_sensitive_fields(self) -> None:
        from datetime import UTC, datetime
        event = AuditEvent(
            event_id="evt_01J00000000000000000000001",
            occurred_at=datetime.now(UTC),
            tenant_id="tnt_01J0000000000000000000TNT1",
            service="identity",
            event_type="test",
            actor_kind="USER",
            payload={"email": "user@example.com", "phone": "13800138000"},
            sensitive_fields=["email", "phone"],
        )
        assert len(event.sensitive_fields) == 2


class TestAuditQuery:
    def test_minimal_query(self) -> None:
        q = AuditQuery(tenant_id="tnt_01J0000000000000000000TNT1")
        assert q.limit == 100

    def test_query_with_filters(self) -> None:
        q = AuditQuery(
            tenant_id="tnt_01J0000000000000000000TNT1",
            service="identity",
            severity="ERROR",
            limit=50,
        )
        assert q.service == "identity"
        assert q.limit == 50
