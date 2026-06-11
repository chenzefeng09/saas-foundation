"""Helpers for the ``RecycleBin.original_location`` column (storage-v1 §6.2).

Writers (e.g. security-ops) stash a JSON-encoded ``list[str]`` of
``"{bucket}::{key}"`` entries when soft-deleting; lifecycle GC then has
enough information to delete the underlying S3 objects when the resource
ages out of the recycle bin.

This module isolates the JSON shape so the service code stays focused on
the orchestration.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from foundation_storage import ObjectKey
from foundation_storage import get_settings as get_storage_settings
from foundation_storage.errors import KeyValidationError

from foundation_lifecycle.observability import get_logger

if TYPE_CHECKING:
    from foundation_storage.config import StorageSettings

log = get_logger(__name__)


def encode_locations(locations: list[str] | None) -> str | None:
    """Serialize raw ``["bucket::key", ...]`` for the ``original_location`` column.

    Returns ``None`` when ``locations`` is ``None`` or empty so we don't
    persist meaningless ``"[]"`` rows.
    """
    if not locations:
        return None
    return json.dumps(locations, ensure_ascii=False)


def parse_s3_location(
    raw: str | None,
    *,
    settings: StorageSettings | None = None,
) -> list[ObjectKey]:
    """Parse ``RecycleBin.original_location`` into a list of ``ObjectKey``.

    Returns ``[]`` for ``None``, empty string, or any malformed payload
    (a warning is logged in the malformed case).  Individual entries that
    fail ``ObjectKey.from_string`` are skipped with a warning so one bad
    entry doesn't block GC for the whole resource.
    """
    if raw is None or raw == "":
        return []
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError:
        log.warning("storage.location.invalid_json", raw=raw[:200])
        return []
    if not isinstance(decoded, list):
        log.warning("storage.location.not_a_list", raw=raw[:200])
        return []

    bucket_map = (settings or get_storage_settings()).bucket_to_purpose_map()
    out: list[ObjectKey] = []
    for entry in decoded:
        if not isinstance(entry, str):
            log.warning("storage.location.non_string_entry", entry=str(entry)[:200])
            continue
        try:
            out.append(ObjectKey.from_string(entry, bucket_map))
        except KeyValidationError as exc:
            log.warning(
                "storage.location.parse_failed",
                entry=entry[:200],
                error=str(exc),
            )
    return out
