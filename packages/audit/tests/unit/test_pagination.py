"""Unit tests for the keyset cursor of the audit event query (services.pagination)."""

from __future__ import annotations

import base64
import re
from datetime import UTC, datetime, timedelta, timezone

import pytest

from foundation_audit.errors import VALIDATION_FAILED, FoundationError
from foundation_audit.services.pagination import decode_cursor, encode_cursor

_EVT = "evt_01JC0000000000000000000001"
_STORED = datetime(2026, 10, 30, 12, 0, 0, 250000, tzinfo=UTC)


def _b64(raw: str) -> str:
    return base64.urlsafe_b64encode(raw.encode()).decode()


@pytest.mark.usefixtures("local_time_not_utc")
@pytest.mark.parametrize("occurred_at", [
    datetime(2026, 10, 30, 12, 0, 0, 250000),  # naive UTC: what ClickHouse hands back
    _STORED,
    datetime(2026, 10, 30, 20, 0, 0, 250000, tzinfo=timezone(timedelta(hours=8))),
])
def test_cursor_round_trips_the_sort_key_in_utc(occurred_at: datetime) -> None:
    assert decode_cursor(encode_cursor(occurred_at, _EVT)) == (_STORED, _EVT)


def test_cursor_survives_a_query_string_unencoded() -> None:
    # The ISO timestamp holds '+', ':' and '.'; the token itself must not.
    assert re.fullmatch(r"[A-Za-z0-9_-]+", encode_cursor(_STORED, _EVT))


@pytest.mark.parametrize("cursor", [
    _EVT,  # a bare event id: what the query handed out before the cursor carried occurred_at
    _b64(f"2026-10-30T12:00:00.250000|{_EVT}"),  # no offset: not a cursor this query issues
    _b64("2026-10-30T12:00:00.250000+00:00|cls_01J0000000000000000000CLS1"),  # another list's
    _b64(f"2026-10-30T12:00:00+00:00|{_EVT}|extra"),
    _b64(f"yesterday|{_EVT}"),
    _b64(_EVT),  # no timestamp at all
    "%%%",
    "游标",
])
def test_decode_rejects_anything_encode_did_not_produce(cursor: str) -> None:
    with pytest.raises(FoundationError) as exc:
        decode_cursor(cursor)

    assert exc.value.error_code is VALIDATION_FAILED
