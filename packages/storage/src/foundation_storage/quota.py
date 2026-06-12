"""Quota checker interface and implementations.

Phase 1 shipped the ``QuotaChecker`` Protocol and a no-op default plugged
into ``StorageClient``. Phase 3 adds ``PostgresQuotaChecker`` which reads
and atomically updates ``lifecycle.tenant_storage_quota`` rows via a
caller-provided ``AsyncSession`` factory (one short transaction per call —
no shared session state with the request that triggered the upload).

The schema lives in the lifecycle service (see
``packages/lifecycle/migrations/.../0002_add_tenant_storage_quota.py``);
foundation_storage talks to it via raw SQL so we don't pull a lifecycle
import (cyclic) here.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from foundation_storage.errors import QUOTA_EXCEEDED, QuotaExceededError
from foundation_storage.keys import BucketPurpose
from foundation_storage.observability import get_logger, get_meter

if TYPE_CHECKING:
    from contextlib import AbstractAsyncContextManager


log = get_logger(__name__)
_meter = get_meter(__name__)
# Phase 7: surface upload accept/reject ratios as a Prometheus-scrapable
# counter.  ``increment_used`` is intentionally NOT instrumented — the
# ``storage.quota.used_bytes`` gauge that lifecycle publishes during the
# daily reconcile already covers the current-consumption view.
_upload_counter = _meter.create_counter(
    "storage.quota.upload_total",
    unit="1",
    description="Quota upload attempts, partitioned by result (accepted|rejected)",
)


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
    """No-op implementation: never blocks, never records.

    Default when no Postgres-backed checker is wired (tests, bootstrap, or
    services that don't care about quota yet).
    """

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


# ---------------------------------------------------------------------------
# Postgres-backed implementation (storage-v1 §5, §10.1 row-level atomic update).
# ---------------------------------------------------------------------------

# Use plain text SQL via SQLAlchemy ``text()`` so we don't import the lifecycle
# ORM here (would create a packaging cycle).
_SELECT_QUOTA_SQL = (
    "SELECT limit_bytes, used_bytes "
    "FROM lifecycle.tenant_storage_quota "
    "WHERE tenant_id = :tenant_id AND bucket_purpose = :bucket_purpose"
)

_INCREMENT_USED_SQL = (
    "UPDATE lifecycle.tenant_storage_quota "
    "SET used_bytes = used_bytes + :delta, updated_at = now() "
    "WHERE tenant_id = :tenant_id AND bucket_purpose = :bucket_purpose"
)


# AsyncSession is referenced only for type-checking; importing it eagerly would
# force every storage user to install sqlalchemy[asyncio]. Use ``Any`` at
# runtime so the module imports cleanly when SQLAlchemy isn't present.
SessionFactory = Callable[[], "AbstractAsyncContextManager[Any]"]


class PostgresQuotaChecker:
    """Quota enforcement backed by ``lifecycle.tenant_storage_quota``.

    Concurrency model (storage-v1 §10.1): rely on Postgres' per-row atomic
    UPDATE — ``UPDATE ... SET used_bytes = used_bytes + :delta`` — instead of
    Redis or app-level locks. The check-then-put-then-increment sequence
    can over-admit when two uploads race, but the daily reconcile job
    corrects drift and the soft-warn-at-80% gives operators a window before
    a hard ceiling matters.

    Parameters
    ----------
    session_factory:
        Zero-arg callable returning an async-context-manager-yielding
        ``AsyncSession``. Each method call opens its own short transaction
        — we deliberately do NOT share the caller's request session, so
        a quota update isn't rolled back if the surrounding business
        transaction aborts.
    """

    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    async def check_before_upload(
        self,
        tenant_id: str,
        bucket_purpose: BucketPurpose,
        estimated_bytes: int,
    ) -> None:
        from sqlalchemy import text  # late import; sqlalchemy is a soft dep

        params = {"tenant_id": tenant_id, "bucket_purpose": bucket_purpose.value}
        async with self._session_factory() as session:
            result = await session.execute(text(_SELECT_QUOTA_SQL), params)
            row = result.first()
        if row is None:
            # Storage-v1 §5: a tenant with no quota row is unmetered. Log and
            # let the upload proceed so a missing row is observable in metrics
            # without hard-blocking real traffic.
            log.warning(
                "storage.quota.row_missing",
                tenant_id=tenant_id,
                bucket_purpose=bucket_purpose.value,
            )
            _upload_counter.add(
                1,
                {
                    "bucket_purpose": bucket_purpose.value,
                    "result": "accepted",
                },
            )
            return
        limit_bytes = int(row[0])
        used_bytes = int(row[1])
        if used_bytes + estimated_bytes > limit_bytes:
            _upload_counter.add(
                1,
                {
                    "bucket_purpose": bucket_purpose.value,
                    "result": "rejected",
                },
            )
            raise QuotaExceededError(
                QUOTA_EXCEEDED,
                detail=(
                    f"tenant {tenant_id} would exceed quota for "
                    f"{bucket_purpose.value}: "
                    f"{used_bytes} + {estimated_bytes} > {limit_bytes}"
                ),
                extra={
                    "tenant_id": tenant_id,
                    "bucket_purpose": bucket_purpose.value,
                    "limit_bytes": str(limit_bytes),
                    "used_bytes": str(used_bytes),
                },
            )
        _upload_counter.add(
            1,
            {
                "bucket_purpose": bucket_purpose.value,
                "result": "accepted",
            },
        )

    async def increment_used(
        self,
        tenant_id: str,
        bucket_purpose: BucketPurpose,
        delta_bytes: int,
    ) -> None:
        from sqlalchemy import text  # late import

        params = {
            "tenant_id": tenant_id,
            "bucket_purpose": bucket_purpose.value,
            "delta": int(delta_bytes),
        }
        async with self._session_factory() as session:
            result = await session.execute(text(_INCREMENT_USED_SQL), params)
            rowcount = getattr(result, "rowcount", None)
            # Commit only when the session is autocommit=off (the common case).
            commit = getattr(session, "commit", None)
            if commit is not None:
                await commit()
        if rowcount == 0:
            # Mirror check_before_upload's "missing row is observable but not
            # fatal" contract — drift will be corrected on the next reconcile.
            log.warning(
                "storage.quota.increment_no_row",
                tenant_id=tenant_id,
                bucket_purpose=bucket_purpose.value,
                delta_bytes=delta_bytes,
            )
