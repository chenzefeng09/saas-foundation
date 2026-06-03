"""S3 / MinIO WORM (Object Lock) adapter for critical audit events.

Writes events as individual JSON objects under:
  s3://{worm_bucket}/tenant={tenant_id}/year=YYYY/month=MM/day=DD/hour=HH/{event_id}.json

Object Lock mode: COMPLIANCE (immutable for `worm_retention_days` days).

worm_enabled defaults to False for dev; set AUDIT_WORM_ENABLED=true in production.
Failure to write WORM is logged as WARNING and does NOT block the main audit chain.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from foundation_audit.config import get_settings
from foundation_audit.observability import get_logger

log = get_logger(__name__)

_WORM_SEVERITY = frozenset({"SECURITY", "CRITICAL"})


def _should_worm(event: dict[str, Any]) -> bool:
    """Return True if the event should be WORM double-written."""
    return event.get("severity", "INFO") in _WORM_SEVERITY


def _object_key(event: dict[str, Any]) -> str:
    """Build the S3 object key for an event."""
    occurred_raw = event.get("occurred_at", datetime.now(UTC).isoformat())
    if isinstance(occurred_raw, str):
        try:
            ts = datetime.fromisoformat(occurred_raw.replace("Z", "+00:00"))
        except ValueError:
            ts = datetime.now(UTC)
    elif isinstance(occurred_raw, datetime):
        ts = occurred_raw
    else:
        ts = datetime.now(UTC)

    tenant = event.get("tenant_id", "unknown")
    event_id = event.get("event_id", "unknown")
    return (
        f"tenant={tenant}/"
        f"year={ts.year}/month={ts.month:02d}/day={ts.day:02d}/"
        f"hour={ts.hour:02d}/{event_id}.json"
    )


async def write_worm(event: dict[str, Any]) -> str | None:
    """Write an event to S3 WORM bucket with Object Lock.

    Returns the s3:// URI on success, None on failure or if worm_enabled=False.
    """
    s = get_settings()
    if not s.worm_enabled:
        return None
    if not _should_worm(event):
        return None

    try:
        import boto3  # type: ignore[import-untyped]
        from botocore.config import Config  # type: ignore[import-untyped]

        boto_client = boto3.client(
            "s3",
            endpoint_url=s.s3_endpoint,
            aws_access_key_id=s.s3_access_key,
            aws_secret_access_key=s.s3_secret_key,
            config=Config(signature_version="s3v4"),
        )

        key = _object_key(event)
        body = json.dumps(event, default=str, ensure_ascii=False).encode()

        # RFC 3339 retention date — 7 years default
        retain_until = datetime(
            datetime.now(UTC).year + s.worm_retention_years,
            datetime.now(UTC).month,
            datetime.now(UTC).day,
            tzinfo=UTC,
        )

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
        log.info("worm.written", event_id=event.get("event_id"), uri=uri)
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
