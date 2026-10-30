"""Keyset cursors for the lists shown newest first (recycle bin, legal holds).

Those lists are ordered by a timestamp the database stamps on insert (``now()``
of the inserting transaction), newest first.  The next page must hold exactly
the rows after the last one returned *in that order*, so the cursor carries the
whole sort key and a page is selected with::

    WHERE (ts, id) < (:cursor_ts, :cursor_id) ORDER BY ts DESC, id DESC

``id`` alone cannot be the cursor: ids are ULIDs minted by the app, which need
not sort like the database's timestamps (concurrent transactions, clock skew),
and rows written in one transaction share a timestamp.  ``id`` only breaks those
ties, which makes the order total.

Clients treat the cursor as opaque: URL-safe base64 of ``<iso ts>|<id>``.
"""

from __future__ import annotations

import base64
from datetime import datetime

from foundation_lifecycle.errors import VALIDATION_FAILED, FoundationError

_INVALID_CURSOR = "cursor is not a next_cursor this list returned"


def encode_cursor(ts: datetime, row_id: str) -> str:
    """Cursor for the page after the row whose sort key is ``(ts, row_id)``."""
    raw = f"{ts.isoformat()}|{row_id}".encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str, *, id_prefix: str) -> tuple[datetime, str]:
    """Inverse of :func:`encode_cursor`.

    A cursor this list did not hand out (garbage, a bare id from before the
    cursor carried the timestamp, another list's cursor) is a 422, not a 500.
    """
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
        ts_text, row_id = raw.split("|")
        ts = datetime.fromisoformat(ts_text)
    except ValueError as exc:  # binascii.Error and UnicodeDecodeError are ValueErrors
        raise FoundationError(VALIDATION_FAILED, detail=_INVALID_CURSOR) from exc
    if not row_id.startswith(id_prefix):
        raise FoundationError(VALIDATION_FAILED, detail=_INVALID_CURSOR)
    return ts, row_id
