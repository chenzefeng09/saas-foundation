"""Unit tests for the keyset cursor of the newest-first lists (services.pagination)."""

from __future__ import annotations

import base64
import re
from datetime import UTC, datetime, timedelta, timezone

import pytest

from foundation_lifecycle.errors import VALIDATION_FAILED, FoundationError
from foundation_lifecycle.services.pagination import decode_cursor, encode_cursor

_BIN_ID = "bin_01J0000000000000000000BIN1"


def _b64(raw: str) -> str:
    return base64.urlsafe_b64encode(raw.encode()).decode()


@pytest.mark.parametrize("ts", [
    datetime(2026, 10, 30, 12, 0, 1, 123456, tzinfo=UTC),  # Postgres keeps microseconds
    datetime(2026, 10, 30, 20, 0, tzinfo=timezone(timedelta(hours=8))),
])
def test_cursor_round_trips_the_exact_sort_key(ts: datetime) -> None:
    decoded = decode_cursor(encode_cursor(ts, _BIN_ID), id_prefix="bin_")

    assert decoded == (ts, _BIN_ID)
    assert decoded[0].utcoffset() == ts.utcoffset()


def test_cursor_survives_a_query_string_unencoded() -> None:
    # The ISO timestamp holds '+' and ':'; the token itself must not.
    cursor = encode_cursor(datetime(2026, 10, 30, 12, 0, tzinfo=UTC), _BIN_ID)

    assert re.fullmatch(r"[A-Za-z0-9_-]+", cursor)


@pytest.mark.parametrize("cursor", [
    _BIN_ID,  # a bare id, what the list handed out before the cursor carried the timestamp
    _b64("2026-10-30T12:00:00+00:00|lhd_01J0000000000000000000HLD1"),  # another list's id
    _b64(f"2026-10-30T12:00:00+00:00|{_BIN_ID}|extra"),
    _b64(f"yesterday|{_BIN_ID}"),
    _b64(_BIN_ID),  # no timestamp at all
    "%%%",
    "游标",
])
def test_decode_rejects_anything_encode_did_not_produce(cursor: str) -> None:
    with pytest.raises(FoundationError) as exc:
        decode_cursor(cursor, id_prefix="bin_")

    assert exc.value.error_code is VALIDATION_FAILED
