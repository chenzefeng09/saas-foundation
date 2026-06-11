"""Tenant-scoped object key layout (storage-v1 §3)."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from foundation_storage.errors import KEY_INVALID, KeyValidationError

TENANT_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


class BucketPurpose(StrEnum):
    """Logical bucket categories.  Map to physical bucket names via StorageSettings."""

    AUDIT = "audit"
    WORKSPACE = "workspace"
    KB_RAW = "kb_raw"
    KB_DERIVED = "kb_derived"


def _validate_tenant(tenant_id: str) -> None:
    if not TENANT_ID_PATTERN.match(tenant_id):
        raise KeyValidationError(
            KEY_INVALID,
            detail=f"tenant_id {tenant_id!r} does not match {TENANT_ID_PATTERN.pattern}",
        )


def _validate_segment(seg: str) -> None:
    if not seg:
        raise KeyValidationError(KEY_INVALID, detail="path segment must not be empty")
    if seg in (".", ".."):
        raise KeyValidationError(KEY_INVALID, detail=f"path segment {seg!r} is forbidden")
    if "/" in seg:
        raise KeyValidationError(
            KEY_INVALID, detail=f"path segment {seg!r} must not contain '/'"
        )


@dataclass(frozen=True, slots=True)
class ObjectKey:
    """Tenant-scoped key inside a bucket.

    Serialized form within a bucket: ``tenants/{tenant_id}/{seg1}/{seg2}/...``.

    Cross-bucket serialized form (used by lifecycle GC, storage-v1 §6.2):
    ``{bucket}::{key}``.
    """

    purpose: BucketPurpose
    tenant_id: str
    path_segments: tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_tenant(self.tenant_id)
        if not self.path_segments:
            raise KeyValidationError(KEY_INVALID, detail="path_segments must not be empty")
        for seg in self.path_segments:
            _validate_segment(seg)

    # ------------------------------------------------------------------ key

    @property
    def key(self) -> str:
        """Return the bucket-relative object key."""
        tail = "/".join(self.path_segments)
        return f"tenants/{self.tenant_id}/{tail}"

    def to_serialized(self, bucket_name: str) -> str:
        """Return ``{bucket_name}::{key}`` for cross-bucket references (GC)."""
        return f"{bucket_name}::{self.key}"

    # --------------------------------------------------------------- parsers

    @classmethod
    def from_string(
        cls,
        serialized: str,
        bucket_to_purpose: Mapping[str, BucketPurpose],
    ) -> ObjectKey:
        """Parse ``{bucket}::tenants/{tenant_id}/...`` back into an ObjectKey.

        ``bucket_to_purpose`` is an explicit mapping from physical bucket name to
        ``BucketPurpose``. Derive it from
        ``StorageSettings.bucket_to_purpose_map()``. The caller-supplied physical
        name is **not** kept on the returned object (the StorageClient handles
        physical mapping at I/O time).
        """
        if "::" not in serialized:
            raise KeyValidationError(
                KEY_INVALID, detail="serialized key must be '{bucket}::{key}'"
            )
        bucket_name, _, key = serialized.partition("::")
        if not bucket_name or not key:
            raise KeyValidationError(KEY_INVALID, detail="empty bucket or key part")

        try:
            purpose = bucket_to_purpose[bucket_name]
        except KeyError as exc:
            raise KeyValidationError(
                KEY_INVALID,
                detail=f"unknown bucket {bucket_name!r}; not in configured bucket map",
            ) from exc

        # Expect "tenants/{tenant_id}/seg1/seg2/..."
        parts = key.split("/")
        if len(parts) < 3 or parts[0] != "tenants":
            raise KeyValidationError(
                KEY_INVALID,
                detail="key must start with 'tenants/{tenant_id}/...'",
            )
        tenant_id = parts[1]
        path_segments = tuple(parts[2:])
        return cls(purpose=purpose, tenant_id=tenant_id, path_segments=path_segments)

    # -------------------------------------------------------------- factories

    @classmethod
    def for_audit_event(
        cls, tenant_id: str, occurred_at: datetime, event_id: str
    ) -> ObjectKey:
        """audit/tenants/{tid}/year={Y}/month={M}/day={D}/hour={H}/{event_id}.json"""
        return cls(
            purpose=BucketPurpose.AUDIT,
            tenant_id=tenant_id,
            path_segments=(
                f"year={occurred_at.year:04d}",
                f"month={occurred_at.month:02d}",
                f"day={occurred_at.day:02d}",
                f"hour={occurred_at.hour:02d}",
                f"{event_id}.json",
            ),
        )

    @classmethod
    def for_workspace_file(
        cls, tenant_id: str, workspace_id: str, file_id: str, filename: str
    ) -> ObjectKey:
        """workspace/tenants/{tid}/workspaces/{wid}/files/{fid}/{filename}"""
        return cls(
            purpose=BucketPurpose.WORKSPACE,
            tenant_id=tenant_id,
            path_segments=(
                "workspaces",
                workspace_id,
                "files",
                file_id,
                filename,
            ),
        )

    @classmethod
    def for_security_ops_report(
        cls, tenant_id: str, resource_type: str, resource_id: str, filename: str
    ) -> ObjectKey:
        """workspace/tenants/{tid}/security-ops/{resource_type}/{resource_id}/{filename}

        Security-ops reports live alongside workspace files in the workspace bucket
        (storage-v1 §3.2) — they are tenant-private but not lifecycle-managed by users.
        """
        return cls(
            purpose=BucketPurpose.WORKSPACE,
            tenant_id=tenant_id,
            path_segments=(
                "security-ops",
                resource_type,
                resource_id,
                filename,
            ),
        )

    @classmethod
    def for_kb_raw_doc(
        cls, tenant_id: str, kb_id: str, doc_id: str, filename: str
    ) -> ObjectKey:
        """kb-raw/tenants/{tid}/kbs/{kb_id}/docs/{doc_id}/{filename}"""
        return cls(
            purpose=BucketPurpose.KB_RAW,
            tenant_id=tenant_id,
            path_segments=(
                "kbs",
                kb_id,
                "docs",
                doc_id,
                filename,
            ),
        )

    @classmethod
    def for_kb_chunk(
        cls, tenant_id: str, kb_id: str, doc_id: str, chunk_id: str
    ) -> ObjectKey:
        """kb-derived/tenants/{tid}/kbs/{kb_id}/docs/{doc_id}/chunks/{chunk_id}.json"""
        return cls(
            purpose=BucketPurpose.KB_DERIVED,
            tenant_id=tenant_id,
            path_segments=(
                "kbs",
                kb_id,
                "docs",
                doc_id,
                "chunks",
                f"{chunk_id}.json",
            ),
        )
