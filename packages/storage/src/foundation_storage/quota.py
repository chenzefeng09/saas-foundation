"""Quota checker interface (Phase 1: protocol + Noop only).

Phase 3 will add a Postgres-backed implementation that consults
``storage_quota`` rows. Until then ``NoopQuotaChecker`` is the default
plugged into ``StorageClient``.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from foundation_storage.keys import BucketPurpose


@runtime_checkable
class QuotaChecker(Protocol):
    """Pluggable quota enforcement strategy.

    ``check_before_upload`` SHOULD raise ``QuotaExceededError`` when the upload
    would exceed the tenant's quota for the given bucket purpose.
    ``increment_used`` is called *after* a successful put to update the
    tenant's used bytes counter.
    """

    async def check_before_upload(
        self,
        tenant_id: str,
        bucket_purpose: BucketPurpose,
        estimated_bytes: int,
    ) -> None: ...

    async def increment_used(
        self,
        tenant_id: str,
        bucket_purpose: BucketPurpose,
        delta_bytes: int,
    ) -> None: ...


class NoopQuotaChecker:
    """No-op implementation: never blocks, never records.  Default for Phase 1."""

    async def check_before_upload(
        self,
        tenant_id: str,
        bucket_purpose: BucketPurpose,
        estimated_bytes: int,
    ) -> None:
        return None

    async def increment_used(
        self,
        tenant_id: str,
        bucket_purpose: BucketPurpose,
        delta_bytes: int,
    ) -> None:
        return None
