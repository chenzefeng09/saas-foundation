"""Keyset cursors for the governance lists shown newest first.

``GET /core/events`` lists dlp_event rows by ``occurred_at`` and
``GET /core/classifications`` lists labels by ``updated_at``, newest first.  The
next page must hold exactly the rows after the last one returned *in that
order*, so the cursor carries the whole sort key and a page is selected with::

    WHERE (ts, id) < (:cursor_ts, :cursor_id) ORDER BY ts DESC, id DESC

The timestamp alone cannot be the cursor: every row written in one transaction
shares its ``now()``, so ``ts < :cursor_ts`` skips the rows tied with the last
one shown.  Nor can the id: a dlp_event id comes from a sequence at insert time
while ``now()`` is the transaction's start, so concurrent transactions number
their rows out of time order.  ``id`` only breaks the ties, which makes the
order total.

Clients treat the cursor as opaque: URL-safe base64 of ``<iso ts>|<id>``.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from datetime import datetime

from foundation_dlp.errors import VALIDATION_FAILED, FoundationError

_INVALID_CURSOR = "cursor is not a next_cursor this list returned"
_BIGINT_MAX = 2**63 - 1


def encode_cursor(ts: datetime, row_id: int | str) -> str:
    """Cursor for the page after the row whose sort key is ``(ts, row_id)``."""
    raw = f"{ts.isoformat()}|{row_id}".encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor[IdT: (int, str)](
    cursor: str, *, parse_id: Callable[[str], IdT]
) -> tuple[datetime, IdT]:
    """Inverse of :func:`encode_cursor`; ``parse_id`` turns the id text back into the key.

    A cursor this list did not hand out (garbage, the bare timestamp the
    deprecated ``before`` used to take, another list's cursor) is a 422, not a
    500 or a wrong page.
    """
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
        ts_text, id_text = raw.split("|")
        ts = datetime.fromisoformat(ts_text)
        row_id = parse_id(id_text)
    except ValueError as exc:  # binascii.Error and UnicodeDecodeError are ValueErrors
        raise FoundationError(VALIDATION_FAILED, detail=_INVALID_CURSOR) from exc
    if ts.tzinfo is None:  # both sort keys are timestamptz: every cursor has an offset
        raise FoundationError(VALIDATION_FAILED, detail=_INVALID_CURSOR)
    return ts, row_id


def parse_event_id(text: str) -> int:
    """A dlp_event id (bigserial) as a cursor carries it."""
    if not (text.isascii() and text.isdigit()) or not 0 < int(text) <= _BIGINT_MAX:
        raise ValueError(f"not a dlp_event id: {text!r}")
    return int(text)


def parse_classification_id(text: str) -> str:
    """A classification id as a cursor carries it."""
    if not text.startswith("cls_"):
        raise ValueError(f"not a classification id: {text!r}")
    return text
