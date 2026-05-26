"""ORM-object factory helpers for lifecycle tests."""

from __future__ import annotations
from datetime import UTC, datetime, timedelta

from foundation_lifecycle.domain.models import ResourceType, RecycleBin


def make_resource_type(*, rt_id: str = "user_data", service: str = "identity",
                       kind: str = "user_pii", retention_days: int = 365,
                       recycle_bin_days: int = 30, requires_cert: bool = False) -> ResourceType:
    return ResourceType(id=rt_id, service=service, kind=kind, display_name=f"{service}.{kind}",
        retention_days_default=retention_days, recycle_bin_days=recycle_bin_days,
        requires_destruction_certificate=requires_cert)


def make_recycle_bin_entry(*, bin_id: str = "bin_test1",
                           tenant_id: str = "tnt_01J0000000000000000000TNT1",
                           resource_type_id: str = "user_data",
                           resource_id: str = "res_123",
                           expires_at: datetime | None = None) -> RecycleBin:
    if expires_at is None:
        expires_at = datetime.now(UTC) + timedelta(days=30)
    return RecycleBin(id=bin_id, tenant_id=tenant_id, resource_type_id=resource_type_id,
                      resource_id=resource_id, deleted_by="usr_test",
                      expires_at=expires_at)
