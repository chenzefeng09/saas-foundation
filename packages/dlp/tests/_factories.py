"""Factory helpers for DLP tests."""

from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Any

from foundation_dlp.domain.models import Classification, DLPEvent, DLPRule
from foundation_dlp.services.pagination import decode_cursor


def make_classification(*, cls_id: str = "cls_test1", tenant_id: str = "tnt_01J0000000000000000000TNT1",
                        resource_type: str = "document", resource_id: str = "doc_1",
                        sensitivity: str = "L3", tags: list[str] | None = None,
                        downgradable: bool = True,
                        updated_at: datetime | None = None) -> Classification:
    return Classification(id=cls_id, tenant_id=tenant_id, resource_type=resource_type,
        resource_id=resource_id, sensitivity=sensitivity, tags=tags or [],
        downgradable=downgradable, tagged_at=datetime.now(UTC), updated_at=updated_at)

def make_dlp_event(*, event_id: int, occurred_at: datetime,
                   tenant_id: str = "tnt_01J0000000000000000000TNT1",
                   check_type: str = "SCAN", decision: str = "QUARANTINE") -> DLPEvent:
    return DLPEvent(id=event_id, tenant_id=tenant_id, check_type=check_type, decision=decision,
        resource_type="document", resource_id=f"doc_{event_id}", occurred_at=occurred_at)

def make_dlp_rule(*, rule_id: str = "dlpr_test1", tenant_id: str = "tnt_01J0000000000000000000TNT1",
                  name: str = "Test Rule", rule_type: str = "REGEX", pattern: str = r"\d{18}",
                  min_sensitivity: str = "L3") -> DLPRule:
    return DLPRule(id=rule_id, tenant_id=tenant_id, name=name, rule_type=rule_type,
        pattern=pattern, min_sensitivity=min_sensitivity, enabled=True)

def newest_first_answer(rows: Sequence[Any], cursor: str | None, limit: int, *,
                        ts: Callable[[Any], datetime], parse_id: Callable[[str], Any]) -> list[Any]:
    """What a governance list query returns from ``rows``.

    (ts, id) descending, only the rows after ``cursor``, limit + 1 of them.
    """
    ordered = sorted(rows, key=lambda r: (ts(r), r.id), reverse=True)
    if cursor is not None:
        after = decode_cursor(cursor, parse_id=parse_id)
        ordered = [r for r in ordered if (ts(r), r.id) < after]
    return ordered[: limit + 1]
