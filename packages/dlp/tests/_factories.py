"""Factory helpers for DLP tests."""

from datetime import UTC, datetime
from foundation_dlp.domain.models import Classification, DLPRule


def make_classification(*, cls_id: str = "cls_test1", tenant_id: str = "tnt_01J0000000000000000000TNT1",
                        resource_type: str = "document", resource_id: str = "doc_1",
                        sensitivity: str = "L3", tags: list[str] | None = None,
                        downgradable: bool = True) -> Classification:
    return Classification(id=cls_id, tenant_id=tenant_id, resource_type=resource_type,
        resource_id=resource_id, sensitivity=sensitivity, tags=tags or [],
        downgradable=downgradable, tagged_at=datetime.now(UTC))

def make_dlp_rule(*, rule_id: str = "dlpr_test1", tenant_id: str = "tnt_01J0000000000000000000TNT1",
                  name: str = "Test Rule", rule_type: str = "REGEX", pattern: str = r"\d{18}",
                  min_sensitivity: str = "L3") -> DLPRule:
    return DLPRule(id=rule_id, tenant_id=tenant_id, name=name, rule_type=rule_type,
        pattern=pattern, min_sensitivity=min_sensitivity, enabled=True)
