"""S3 / MinIO WORM (Object Lock) adapter for critical audit events.

Legacy path (default):
  Writes events as individual JSON objects under:
    s3://{worm_bucket}/tenant={tenant_id}/year=YYYY/month=MM/day=DD/hour=HH/{event_id}.json
  using a freshly-built boto3 client per call.

Phase 2 path (behind feature flag ``storage.worm_via_storage_client``):
  Routes the same write through ``foundation_storage.StorageClient`` so that
  retry policy, OTel spans, ENV-driven bucket name, and (later) quota hooks
  live in one place.  The S3 key uses the new ``ObjectKey.for_audit_event``
  layout ``tenants/{tid}/events/YYYY/MM/DD/HH/{event_id}.json`` (storage-v1 §3.2).

Object Lock mode: COMPLIANCE (immutable for ``worm_retention_days`` days).

``worm_enabled`` defaults to False for dev; set ``AUDIT_WORM_ENABLED=true`` in
production.  Failure to write WORM is logged as WARNING and does NOT block the
main audit chain.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from foundation_audit.config import get_settings
from foundation_audit.observability import get_logger

log = get_logger(__name__)

_WORM_SEVERITY = frozenset({"SECURITY", "CRITICAL"})
_FLAG_NAME = "storage.worm_via_storage_client"


def _should_worm(event: dict[str, Any]) -> bool:
    """Return True if the event should be WORM double-written."""
    return event.get("severity", "INFO") in _WORM_SEVERITY


def _parse_occurred_at(event: dict[str, Any]) -> datetime:
    occurred_raw = event.get("occurred_at", datetime.now(UTC).isoformat())
    if isinstance(occurred_raw, str):
        try:
            return datetime.fromisoformat(occurred_raw.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(UTC)
    if isinstance(occurred_raw, datetime):
        return occurred_raw
    return datetime.now(UTC)


def _object_key(event: dict[str, Any]) -> str:
    """Build the legacy S3 object key for an event (Hive-partition layout)."""
    ts = _parse_occurred_at(event)
    tenant = event.get("tenant_id", "unknown")
    event_id = event.get("event_id", "unknown")
    return (
        f"tenant={tenant}/"
        f"year={ts.year}/month={ts.month:02d}/day={ts.day:02d}/"
        f"hour={ts.hour:02d}/{event_id}.json"
    )


def _retention_until() -> datetime:
    """RFC 3339 retention date — N years from today (per config)."""
    s = get_settings()
    now = datetime.now(UTC)
    return datetime(now.year + s.worm_retention_years, now.month, now.day, tzinfo=UTC)


def _is_storage_client_enabled(event: dict[str, Any]) -> bool:
    """Evaluate the Phase 2 routing flag.  Defaults to False on any error
    (fail_open=False, matching the preset registration).
    """
    try:
        from foundation_feature_flag.services.feature_flag_service import (
            FeatureFlagService,
        )
    except ImportError:
        return False
    try:
        svc = FeatureFlagService()
        result = svc.is_enabled(
            _FLAG_NAME,
            tenant_id=event.get("tenant_id"),
        )
        return bool(result)
    except Exception as exc:
        log.warning("worm.flag_lookup.failed", flag=_FLAG_NAME, error=str(exc))
        return False


async def _write_via_storage_client(event: dict[str, Any]) -> str | None:
    """Phase 2 path: write through foundation_storage.StorageClient."""
    try:
        from foundation_storage import (
            ObjectKey,
            StorageClient,
        )
        from foundation_storage import (
            get_settings as get_storage_settings,
        )
    except ImportError:
        log.warning("worm.storage_client.not_installed")
        return None

    ts = _parse_occurred_at(event)
    tenant_id = str(event.get("tenant_id", "unknown"))
    event_id = str(event.get("event_id", "unknown"))

    try:
        key = ObjectKey.for_audit_event(tenant_id, ts, event_id)
    except Exception as exc:
        log.warning(
            "worm.storage_client.key_invalid",
            event_id=event_id,
            tenant_id=tenant_id,
            error=str(exc),
        )
        return None

    settings = get_storage_settings()
    client = StorageClient.as_system(settings)
    body = json.dumps(event, default=str, ensure_ascii=False).encode()
    retain_until = _retention_until()

    try:
        await client.put_object(
            key=key,
            body=body,
            content_type="application/json",
            object_lock_mode="COMPLIANCE",
            object_lock_retain_until=retain_until,
        )
    except Exception as exc:
        log.warning(
            "worm.storage_client.put_failed",
            event_id=event_id,
            error=str(exc),
        )
        return None

    bucket = settings.bucket_audit
    uri = f"s3://{bucket}/{key.key}"
    log.info("worm.written", event_id=event_id, uri=uri, route="storage_client")
    return uri


async def _write_via_boto3_direct(event: dict[str, Any]) -> str | None:
    """Legacy path: build a one-shot boto3 client locally and put_object directly."""
    s = get_settings()
    try:
        import boto3
        from botocore.config import Config

        boto_client = boto3.client(
            "s3",
            endpoint_url=s.s3_endpoint,
            aws_access_key_id=s.s3_access_key,
            aws_secret_access_key=s.s3_secret_key,
            config=Config(signature_version="s3v4"),
        )

        key = _object_key(event)
        body = json.dumps(event, default=str, ensure_ascii=False).encode()
        retain_until = _retention_until()

        import asyncio

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: boto_client.put_object(
                Bucket=s.worm_bucket,
                Key=key,
                Body=body,
                ContentType="application/json",
                ObjectLockMode="COMPLIANCE",
                ObjectLockRetainUntilDate=retain_until,
            ),
        )

        uri = f"s3://{s.worm_bucket}/{key}"
        log.info("worm.written", event_id=event.get("event_id"), uri=uri, route="legacy")
        return uri

    except ImportError:
        log.warning("worm.boto3.not_installed", hint="pip install boto3")
        return None
    except Exception as exc:
        log.warning(
            "worm.write.failed",
            event_id=event.get("event_id"),
            error=str(exc),
        )
        return None


async def write_worm(event: dict[str, Any]) -> str | None:
    """Write an event to S3 WORM bucket with Object Lock.

    Routing:
      - Feature flag ``storage.worm_via_storage_client`` ON  → StorageClient path
      - flag OFF (default) or any flag-lookup failure        → legacy boto3 path

    The legacy path is preserved verbatim so an emergency rollback is just a
    flag flip; see docs/design/storage-migration-v1.md.

    Returns the s3:// URI on success, None on failure or if worm_enabled=False.
    """
    s = get_settings()
    if not s.worm_enabled:
        return None
    if not _should_worm(event):
        return None

    if _is_storage_client_enabled(event):
        return await _write_via_storage_client(event)
    return await _write_via_boto3_direct(event)
