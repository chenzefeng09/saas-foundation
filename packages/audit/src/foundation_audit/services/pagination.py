"""Keyset cursors: the audit event query and verify-integrity's windows.

The event query (``POST /events:query``)
----------------------------------------
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

verify-integrity (``POST /events:verify-integrity``)
----------------------------------------------------
A window of verification follows the order the worker chained events in:
batch after batch (``ingested_at``), a batch's events in leaf order.  The next
window holds the events after the last one checked in that order::

    WHERE (ingested_at, merkle_batch_id, merkle_leaf_idx) > (:ts, :batch_id, :leaf_idx)

Neither ``occurred_at`` nor ``event_id`` follows that order.  The cursor is
URL-safe base64 of ``<iso ts>|<merkle_batch_id>|<merkle_leaf_idx>``.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime

from foundation_audit.errors import VALIDATION_FAILED, FoundationError

_EVENT_ID_PREFIX = "evt_"
_INVALID_CURSOR = "cursor is not a next_cursor this query returned"
_BATCH_ID_PREFIX = "mrk_"
_INVALID_CHAIN_CURSOR = "cursor is not a next_cursor verify-integrity returned"
_LEAF_IDX_LIMIT = 2**32  # merkle_leaf_idx is a UInt32


def _utc(ts: datetime) -> datetime:
    """``ts`` in UTC.  ClickHouse hands ``DateTime64(3, 'UTC')`` back as a naive UTC datetime."""
    return ts.astimezone(UTC) if ts.tzinfo else ts.replace(tzinfo=UTC)


def _b64(raw: str) -> str:
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def _unb64(cursor: str) -> str:
    return base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()


def encode_cursor(occurred_at: datetime, event_id: str) -> str:
    """Cursor for the page after the event whose sort key is ``(occurred_at, event_id)``."""
    return _b64(f"{_utc(occurred_at).isoformat()}|{event_id}")


def decode_cursor(cursor: str) -> tuple[datetime, str]:
    """Inverse of :func:`encode_cursor`: ``(occurred_at in UTC, event_id)``.

    A cursor this query did not hand out (garbage, a bare event id from before
    the cursor carried the timestamp) is a 422, not a 500 or a wrong page.
    """
    try:
        ts_text, event_id = _unb64(cursor).split("|")
        ts = datetime.fromisoformat(ts_text)
    except ValueError as exc:  # binascii.Error and UnicodeDecodeError are ValueErrors
        raise FoundationError(VALIDATION_FAILED, detail=_INVALID_CURSOR) from exc
    if ts.tzinfo is None or not event_id.startswith(_EVENT_ID_PREFIX):
        raise FoundationError(VALIDATION_FAILED, detail=_INVALID_CURSOR)
    return ts.astimezone(UTC), event_id


def encode_chain_cursor(ingested_at: datetime, batch_id: str, leaf_idx: int) -> str:
    """Cursor for the window after the event chained at ``(ingested_at, batch_id, leaf_idx)``."""
    return _b64(f"{_utc(ingested_at).isoformat()}|{batch_id}|{leaf_idx}")


def decode_chain_cursor(cursor: str) -> tuple[datetime, str, int]:
    """Inverse of :func:`encode_chain_cursor`: ``(ingested_at in UTC, batch_id, leaf_idx)``.

    Anything else, an event query's cursor among them, is a 422.
    """
    try:
        ts_text, batch_id, leaf_text = _unb64(cursor).split("|")
        ts = datetime.fromisoformat(ts_text)
    except ValueError as exc:  # binascii.Error and UnicodeDecodeError are ValueErrors
        raise FoundationError(VALIDATION_FAILED, detail=_INVALID_CHAIN_CURSOR) from exc
    if (
        ts.tzinfo is None
        or not batch_id.startswith(_BATCH_ID_PREFIX)
        or not (leaf_text.isascii() and leaf_text.isdigit())
        or int(leaf_text) >= _LEAF_IDX_LIMIT
    ):
        raise FoundationError(VALIDATION_FAILED, detail=_INVALID_CHAIN_CURSOR)
    return ts.astimezone(UTC), batch_id, int(leaf_text)
