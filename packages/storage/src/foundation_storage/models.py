"""Plain data containers returned by StorageClient methods."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True, slots=True)
class ObjectMeta:
    """Metadata for an object — returned by ``head_object`` / ``list_prefix``."""

    key: str
    content_length: int
    content_type: str | None = None
    last_modified: datetime | None = None
    metadata: dict[str, str] = field(default_factory=dict)
