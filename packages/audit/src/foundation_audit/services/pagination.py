"""Keyset cursor for the audit event query (``POST /events:query``).

ClickHouse returns a tenant's events in the table's sort order, oldest first
(``ORDER BY tenant_id, occurred_at, event_id``).  The next page must hold
exactly the events after the last one returned *in that order*, so the cursor
carries the whole sort key and a page is selected with::

    WHERE (occurred_at, event_id) > (:cursor_ts, :cursor_id)

``event_id`` alone cannot be the cursor: every emitter mints its own
``evt_<ULID>`` and stamps ``occurred_at`` itself, so ids need not sort like
``occurred_at`` (clock skew between services, events stamped before they are
sent), and events of one request can share an ``occurred_at`` millisecond.
``event_id`` only breaks those ties, which makes the order total.

Clients treat the cursor as opaque: URL-safe base64 of ``<iso ts>|<event_id>``,
the timestamp in UTC exactly as stored (milliseconds).
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime

from foundation_audit.errors import VALIDATION_FAILED, FoundationError

_EVENT_ID_PREFIX = "evt_"
_INVALID_CURSOR = "cursor is not a next_cursor this query returned"


def encode_cursor(occurred_at: datetime, event_id: str) -> str:
    """Cursor for the page after the event whose sort key is ``(occurred_at, event_id)``.

    ClickHouse hands ``occurred_at`` back as a naive UTC datetime.
    """
    ts = occurred_at.astimezone(UTC) if occurred_at.tzinfo else occurred_at.replace(tzinfo=UTC)
    raw = f"{ts.isoformat()}|{event_id}".encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, str]:
    """Inverse of :func:`encode_cursor`: ``(occurred_at in UTC, event_id)``.

    A cursor this query did not hand out (garbage, a bare event id from before
    the cursor carried the timestamp) is a 422, not a 500 or a wrong page.
    """
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
        ts_text, event_id = raw.split("|")
        ts = datetime.fromisoformat(ts_text)
    except ValueError as exc:  # binascii.Error and UnicodeDecodeError are ValueErrors
        raise FoundationError(VALIDATION_FAILED, detail=_INVALID_CURSOR) from exc
    if ts.tzinfo is None or not event_id.startswith(_EVENT_ID_PREFIX):
        raise FoundationError(VALIDATION_FAILED, detail=_INVALID_CURSOR)
    return ts.astimezone(UTC), event_id
