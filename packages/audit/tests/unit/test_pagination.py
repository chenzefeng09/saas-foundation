"""Unit tests for the keyset cursors of the event query and verify-integrity."""

from __future__ import annotations

import base64
import re
from datetime import UTC, datetime, timedelta, timezone

import pytest

from foundation_audit.errors import VALIDATION_FAILED, FoundationError
from foundation_audit.services.pagination import (
    decode_chain_cursor,
    decode_cursor,
    encode_chain_cursor,
    encode_cursor,
)

_EVT = "evt_01JC0000000000000000000001"
_MRK = "mrk_0A1B2C3D4E5F60718293A4B5C6"
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


@pytest.mark.usefixtures("local_time_not_utc")
@pytest.mark.parametrize("ingested_at", [
    datetime(2026, 10, 30, 12, 0, 0, 250000),  # naive UTC: what ClickHouse hands back
    _STORED,
    datetime(2026, 10, 30, 20, 0, 0, 250000, tzinfo=timezone(timedelta(hours=8))),
])
@pytest.mark.parametrize("leaf_idx", [0, 7, 2**32 - 1])
def test_chain_cursor_round_trips_the_chain_position_in_utc(
    ingested_at: datetime, leaf_idx: int,
) -> None:
    cursor = encode_chain_cursor(ingested_at, _MRK, leaf_idx)

    assert decode_chain_cursor(cursor) == (_STORED, _MRK, leaf_idx)
    assert re.fullmatch(r"[A-Za-z0-9_-]+", cursor)


@pytest.mark.parametrize("cursor", [
    encode_cursor(_STORED, _EVT),  # the event query's: no batch, no leaf
    _EVT,
    _b64(f"2026-10-30T12:00:00.250000|{_MRK}|0"),  # no offset
    _b64("2026-10-30T12:00:00.250000+00:00|evt_01JC0000000000000000000001|0"),  # not a batch
    _b64(f"2026-10-30T12:00:00.250000+00:00|{_MRK}|-1"),
    _b64(f"2026-10-30T12:00:00.250000+00:00|{_MRK}|{2**32}"),  # past UInt32
    _b64(f"2026-10-30T12:00:00.250000+00:00|{_MRK}|٣"),  # a digit, not ASCII
    _b64(f"2026-10-30T12:00:00.250000+00:00|{_MRK}|"),
    _b64(f"2026-10-30T12:00:00.250000+00:00|{_MRK}|0|extra"),
    _b64(f"yesterday|{_MRK}|0"),
    "%%%",
])
def test_chain_cursor_decode_rejects_anything_encode_did_not_produce(cursor: str) -> None:
    with pytest.raises(FoundationError) as exc:
        decode_chain_cursor(cursor)

    assert exc.value.error_code is VALIDATION_FAILED


def test_a_chain_cursor_is_no_event_query_cursor() -> None:
    with pytest.raises(FoundationError) as exc:
        decode_cursor(encode_chain_cursor(_STORED, _MRK, 0))

    assert exc.value.error_code is VALIDATION_FAILED
