"""Unit tests for the keyset cursor of the governance lists (services.pagination)."""

from __future__ import annotations

import base64
import re
from datetime import UTC, datetime, timedelta, timezone

import pytest

from foundation_dlp.errors import VALIDATION_FAILED, FoundationError
from foundation_dlp.services.pagination import (
    decode_cursor,
    encode_cursor,
    parse_classification_id,
    parse_event_id,
)

_CLS_ID = "cls_01J0000000000000000000CLS1"


def _b64(raw: str) -> str:
    return base64.urlsafe_b64encode(raw.encode()).decode()


@pytest.mark.parametrize("ts", [
    datetime(2026, 10, 30, 12, 0, 1, 123456, tzinfo=UTC),  # Postgres keeps microseconds
    datetime(2026, 10, 30, 20, 0, tzinfo=timezone(timedelta(hours=8))),
])
def test_cursor_round_trips_the_exact_sort_key(ts: datetime) -> None:
    assert decode_cursor(encode_cursor(ts, 42), parse_id=parse_event_id) == (ts, 42)
    assert decode_cursor(encode_cursor(ts, _CLS_ID), parse_id=parse_classification_id) == (
        ts, _CLS_ID,
    )
    assert decode_cursor(encode_cursor(ts, 42), parse_id=parse_event_id)[0].utcoffset() == (
        ts.utcoffset()
    )


def test_cursor_survives_a_query_string_unencoded() -> None:
    # The ISO timestamp holds '+' and ':'; the token itself must not.
    cursor = encode_cursor(datetime(2026, 10, 30, 12, 0, tzinfo=UTC), 2**63 - 1)

    assert re.fullmatch(r"[A-Za-z0-9_-]+", cursor)


@pytest.mark.parametrize("cursor", [
    "2026-10-30T12:00:00+00:00",  # a bare timestamp: what next_before used to hold
    _b64("2026-10-30T12:00:00|42"),  # no offset: not a timestamptz this list hands out
    _b64("2026-10-30T12:00:00+00:00|42|extra"),
    _b64("yesterday|42"),
    _b64("42"),
    "%%%",
    "游标",
])
def test_decode_rejects_anything_encode_did_not_produce(cursor: str) -> None:
    with pytest.raises(FoundationError) as exc:
        decode_cursor(cursor, parse_id=parse_event_id)

    assert exc.value.error_code is VALIDATION_FAILED


@pytest.mark.parametrize("event_id", [
    _CLS_ID,  # the label list's id
    "0", "-1", "+1", " 1", "1.0", "",  # not a bigserial id as str(int) writes it
    chr(0xFF11) + chr(0xFF12),  # fullwidth "12", which int() would accept
    str(2**63),  # past bigint: the driver would raise, a 500 instead of a 422
])
def test_event_cursor_rejects_an_id_dlp_event_never_has(event_id: str) -> None:
    with pytest.raises(FoundationError) as exc:
        decode_cursor(_b64(f"2026-10-30T12:00:00+00:00|{event_id}"), parse_id=parse_event_id)

    assert exc.value.error_code is VALIDATION_FAILED


@pytest.mark.parametrize("cls_id", ["42", "lhd_01J0000000000000000000HLD1", ""])
def test_label_cursor_rejects_an_id_a_label_never_has(cls_id: str) -> None:
    with pytest.raises(FoundationError) as exc:
        decode_cursor(
            _b64(f"2026-10-30T12:00:00+00:00|{cls_id}"), parse_id=parse_classification_id,
        )

    assert exc.value.error_code is VALIDATION_FAILED
