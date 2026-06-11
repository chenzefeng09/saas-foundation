"""StorageClient — the public S3/MinIO abstraction (storage-v1 §4).

Phase 1 scope:
* tenant-scoped key validation (when ``tenant_id`` is supplied);
* boto3 lazy client (sync) wrapped in ``run_in_executor`` for an async surface;
* ``QuotaChecker`` hook around put_object;
* OTel span per operation;
* botocore ``ClientError`` → typed ``StorageError`` subclasses.

Phase 2 will let ``get_storage_client()`` read ``tenant_id`` from a shared
``foundation_context``; for now the tenant must be passed explicitly.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from opentelemetry import trace

from foundation_storage.config import StorageSettings, get_settings
from foundation_storage.errors import (
    KEY_INVALID,
    OBJECT_LOCKED,
    OBJECT_NOT_FOUND,
    STORAGE_UNAVAILABLE,
    KeyValidationError,
    ObjectLockedError,
    ObjectNotFoundError,
    StorageError,
)
from foundation_storage.keys import BucketPurpose, ObjectKey
from foundation_storage.models import ObjectMeta
from foundation_storage.observability import get_logger
from foundation_storage.quota import NoopQuotaChecker, QuotaChecker

if TYPE_CHECKING:
    from collections.abc import Iterable
    from datetime import datetime

log = get_logger(__name__)
tracer = trace.get_tracer(__name__)


_LOCK_ERROR_CODES = frozenset(
    {
        "AccessDenied",
        "InvalidRequest",
        "ObjectLockConfigurationNotFoundError",
    }
)


class StorageClient:
    """Tenant-scoped facade over boto3 S3 client.

    Parameters
    ----------
    settings:
        Loaded ``StorageSettings``.
    tenant_id:
        When set, every ``ObjectKey`` passed in must belong to this tenant.
        Use ``StorageClient.as_system`` for trusted background tasks that
        legitimately need cross-tenant access (lifecycle GC, admin tools).
    quota_checker:
        Optional quota strategy.  Defaults to ``NoopQuotaChecker`` so callers
        are not forced to wire DB before Phase 3.
    """

    def __init__(
        self,
        settings: StorageSettings,
        tenant_id: str | None = None,
        quota_checker: QuotaChecker | None = None,
    ) -> None:
        self.settings = settings
        self.tenant_id = tenant_id
        self.quota_checker: QuotaChecker = quota_checker or NoopQuotaChecker()
        self._boto_client: Any | None = None

    # ------------------------------------------------------------------ ctors

    @classmethod
    def as_system(cls, settings: StorageSettings) -> StorageClient:
        """Build a client with no tenant scope.

        ONLY for trusted background tasks (lifecycle GC, admin migrations).
        Request-handling code MUST pass ``tenant_id`` explicitly.
        """
        return cls(settings=settings, tenant_id=None)

    # -------------------------------------------------------------- internals

    def _get_boto(self) -> Any:
        if self._boto_client is None:
            import boto3
            from botocore.config import Config

            self._boto_client = boto3.client(
                "s3",
                endpoint_url=self.settings.endpoint or None,
                region_name=self.settings.region,
                aws_access_key_id=self.settings.access_key,
                aws_secret_access_key=self.settings.secret_key,
                config=Config(signature_version="s3v4"),
            )
        return self._boto_client

    def _bucket_for(self, purpose: BucketPurpose) -> str:
        match purpose:
            case BucketPurpose.AUDIT:
                return self.settings.bucket_audit
            case BucketPurpose.WORKSPACE:
                return self.settings.bucket_workspace
            case BucketPurpose.KB_RAW:
                return self.settings.bucket_kb_raw
            case BucketPurpose.KB_DERIVED:
                return self.settings.bucket_kb_derived

    def _check_tenant(self, key: ObjectKey) -> None:
        if self.tenant_id is not None and key.tenant_id != self.tenant_id:
            raise KeyValidationError(
                KEY_INVALID,
                detail=(
                    f"key tenant_id {key.tenant_id!r} does not match client "
                    f"tenant_id {self.tenant_id!r}"
                ),
            )

    @staticmethod
    def _map_client_error(exc: Exception, key: ObjectKey | None = None) -> StorageError:
        """Translate botocore ClientError into a typed StorageError."""
        # Late import; botocore is an indirect dep of boto3.
        try:
            from botocore.exceptions import ClientError
        except ImportError:  # pragma: no cover - defensive
            return StorageError(STORAGE_UNAVAILABLE, detail=str(exc))

        if not isinstance(exc, ClientError):
            return StorageError(STORAGE_UNAVAILABLE, detail=str(exc))

        err = exc.response.get("Error", {}) if hasattr(exc, "response") else {}
        code = err.get("Code", "")
        status = (
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if hasattr(exc, "response")
            else None
        )
        if code in ("NoSuchKey", "404", "NoSuchBucket") or status == 404:
            return ObjectNotFoundError(
                OBJECT_NOT_FOUND,
                detail=f"object not found ({code})",
                extra={"key": key.key if key else ""},
            )
        if code in _LOCK_ERROR_CODES:
            return ObjectLockedError(
                OBJECT_LOCKED,
                detail=f"object under WORM retention ({code})",
                extra={"key": key.key if key else ""},
            )
        return StorageError(STORAGE_UNAVAILABLE, detail=f"{code}: {exc!s}")

    # --------------------------------------------------------------- run_in_executor

    @staticmethod
    async def _run(fn: Any) -> Any:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, fn)

    # ==================================================================== API

    async def put_object(
        self,
        key: ObjectKey,
        body: bytes,
        content_type: str | None = None,
        metadata: dict[str, str] | None = None,
        object_lock_mode: str | None = None,
        object_lock_retain_until: datetime | None = None,
    ) -> None:
        """Upload ``body`` to ``key``; runs quota check before and increment after.

        ``object_lock_mode`` / ``object_lock_retain_until`` are forwarded to S3's
        Object Lock API.  Only set them for buckets with Object Lock enabled
        (currently ``audit``).  ``object_lock_mode`` must be ``"COMPLIANCE"`` or
        ``"GOVERNANCE"`` if supplied; both arguments are required together.
        """
        self._check_tenant(key)
        bucket = self._bucket_for(key.purpose)
        # NOTE: Phase 3 will replace len(body) with the result of a subsequent
        # head_object so multipart / streamed bodies are charged accurately.
        size = len(body)

        with tracer.start_as_current_span(
            "storage.put",
            attributes={"bucket": bucket, "key": key.key, "size": size},
        ):
            if self.settings.quota_check_enabled:
                await self.quota_checker.check_before_upload(
                    key.tenant_id, key.purpose, size
                )

            client = self._get_boto()
            kwargs: dict[str, Any] = {"Bucket": bucket, "Key": key.key, "Body": body}
            if content_type is not None:
                kwargs["ContentType"] = content_type
            if metadata:
                kwargs["Metadata"] = metadata
            if object_lock_mode is not None or object_lock_retain_until is not None:
                if object_lock_mode is None or object_lock_retain_until is None:
                    raise KeyValidationError(
                        KEY_INVALID,
                        detail=(
                            "object_lock_mode and object_lock_retain_until must be "
                            "supplied together"
                        ),
                    )
                if object_lock_mode not in ("COMPLIANCE", "GOVERNANCE"):
                    raise KeyValidationError(
                        KEY_INVALID,
                        detail=(
                            f"object_lock_mode must be 'COMPLIANCE' or "
                            f"'GOVERNANCE', got {object_lock_mode!r}"
                        ),
                    )
                kwargs["ObjectLockMode"] = object_lock_mode
                kwargs["ObjectLockRetainUntilDate"] = object_lock_retain_until

            try:
                await self._run(lambda: client.put_object(**kwargs))
            except Exception as exc:
                raise self._map_client_error(exc, key) from exc

            if self.settings.quota_check_enabled:
                await self.quota_checker.increment_used(
                    key.tenant_id, key.purpose, size
                )
            log.info("storage.put", bucket=bucket, key=key.key, size=size)

    async def get_object(self, key: ObjectKey) -> bytes:
        """Download an object and return its full body."""
        self._check_tenant(key)
        bucket = self._bucket_for(key.purpose)
        with tracer.start_as_current_span(
            "storage.get", attributes={"bucket": bucket, "key": key.key}
        ):
            client = self._get_boto()
            try:
                resp = await self._run(
                    lambda: client.get_object(Bucket=bucket, Key=key.key)
                )
            except Exception as exc:
                raise self._map_client_error(exc, key) from exc
            body = resp["Body"].read()
            assert isinstance(body, bytes)
            return body

    async def head_object(self, key: ObjectKey) -> ObjectMeta:
        """Fetch object metadata without downloading the body."""
        self._check_tenant(key)
        bucket = self._bucket_for(key.purpose)
        with tracer.start_as_current_span(
            "storage.head", attributes={"bucket": bucket, "key": key.key}
        ):
            client = self._get_boto()
            try:
                resp = await self._run(
                    lambda: client.head_object(Bucket=bucket, Key=key.key)
                )
            except Exception as exc:
                raise self._map_client_error(exc, key) from exc
            return ObjectMeta(
                key=key.key,
                content_length=int(resp.get("ContentLength", 0)),
                content_type=resp.get("ContentType"),
                last_modified=resp.get("LastModified"),
                metadata=dict(resp.get("Metadata", {}) or {}),
            )

    async def delete_object(self, key: ObjectKey) -> None:
        """Delete an object.  Raises ``ObjectLockedError`` if WORM-protected.

        On success, the quota is decremented by the object's size (fetched via
        ``head_object`` *before* deletion to avoid racing with another writer).
        Failures from head/delete leave the quota untouched — better a small
        positive drift caught by the reconcile job than over-credit.
        """
        self._check_tenant(key)
        bucket = self._bucket_for(key.purpose)
        with tracer.start_as_current_span(
            "storage.delete", attributes={"bucket": bucket, "key": key.key}
        ):
            # Snapshot size before deletion; if head fails (missing object,
            # permission, network), skip quota adjustment — the daily reconcile
            # will catch any drift. We deliberately swallow head errors here
            # so a transient HEAD failure can't block a delete.
            size_bytes: int | None = None
            if self.settings.quota_check_enabled:
                try:
                    meta = await self.head_object(key)
                    size_bytes = int(meta.content_length)
                except StorageError:
                    size_bytes = None

            client = self._get_boto()
            try:
                await self._run(
                    lambda: client.delete_object(Bucket=bucket, Key=key.key)
                )
            except Exception as exc:
                raise self._map_client_error(exc, key) from exc

            if self.settings.quota_check_enabled and size_bytes is not None:
                await self.quota_checker.increment_used(
                    key.tenant_id, key.purpose, -size_bytes
                )
            log.info("storage.delete", bucket=bucket, key=key.key)

    async def list_prefix(
        self,
        purpose: BucketPurpose,
        tenant_id: str,
        prefix_segments: Iterable[str] = (),
        max_keys: int = 1000,
    ) -> list[ObjectMeta]:
        """List objects under ``tenants/{tenant_id}/{prefix...}``."""
        if self.tenant_id is not None and tenant_id != self.tenant_id:
            raise KeyValidationError(
                KEY_INVALID,
                detail=(
                    f"list tenant_id {tenant_id!r} does not match client "
                    f"tenant_id {self.tenant_id!r}"
                ),
            )
        bucket = self._bucket_for(purpose)
        tail = "/".join(prefix_segments)
        prefix = f"tenants/{tenant_id}/" + (f"{tail}/" if tail else "")
        with tracer.start_as_current_span(
            "storage.list", attributes={"bucket": bucket, "prefix": prefix}
        ):
            client = self._get_boto()
            try:
                resp = await self._run(
                    lambda: client.list_objects_v2(
                        Bucket=bucket, Prefix=prefix, MaxKeys=max_keys
                    )
                )
            except Exception as exc:
                raise self._map_client_error(exc) from exc
            out: list[ObjectMeta] = []
            for item in resp.get("Contents", []) or []:
                out.append(
                    ObjectMeta(
                        key=item["Key"],
                        content_length=int(item.get("Size", 0)),
                        last_modified=item.get("LastModified"),
                    )
                )
            return out

    async def compute_tenant_usage(
        self,
        tenant_id: str,
        purpose: BucketPurpose,
    ) -> int:
        """Return the total ``Size`` (bytes) of all objects under the tenant prefix.

        Used by the lifecycle reconcile job (Phase 3 §5.3) — list_prefix
        returns ``ObjectMeta`` objects shaped for app reads, this is a thin
        loop over the boto3 paginator that just sums ``Size`` so we don't
        materialise giant lists for big tenants.

        Cross-tenant: when ``self.tenant_id`` is set the call is rejected
        like every other API; reconcile uses ``StorageClient.as_system()``.
        """
        if self.tenant_id is not None and tenant_id != self.tenant_id:
            raise KeyValidationError(
                KEY_INVALID,
                detail=(
                    f"usage tenant_id {tenant_id!r} does not match client "
                    f"tenant_id {self.tenant_id!r}"
                ),
            )
        bucket = self._bucket_for(purpose)
        prefix = f"tenants/{tenant_id}/"
        with tracer.start_as_current_span(
            "storage.compute_usage",
            attributes={"bucket": bucket, "prefix": prefix},
        ):
            client = self._get_boto()

            def _aggregate() -> int:
                paginator = client.get_paginator("list_objects_v2")
                total = 0
                for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
                    for item in page.get("Contents", []) or []:
                        total += int(item.get("Size", 0))
                return total

            try:
                total: int = await self._run(_aggregate)
            except Exception as exc:
                raise self._map_client_error(exc) from exc
            return total

    async def generate_presigned_url(
        self,
        key: ObjectKey,
        operation: str = "get_object",
        expires_in: int | None = None,
    ) -> str:
        """Return a presigned URL for ``operation`` (``get_object``/``put_object``)."""
        self._check_tenant(key)
        bucket = self._bucket_for(key.purpose)
        ttl = expires_in if expires_in is not None else self.settings.presigned_url_ttl_seconds
        with tracer.start_as_current_span(
            "storage.presign",
            attributes={"bucket": bucket, "key": key.key, "op": operation},
        ):
            client = self._get_boto()
            try:
                url = await self._run(
                    lambda: client.generate_presigned_url(
                        ClientMethod=operation,
                        Params={"Bucket": bucket, "Key": key.key},
                        ExpiresIn=ttl,
                    )
                )
            except Exception as exc:
                raise self._map_client_error(exc, key) from exc
            assert isinstance(url, str)
            return url

    # -------------------------------------------------------------- multipart

    async def initiate_multipart(
        self, key: ObjectKey, content_type: str | None = None
    ) -> str:
        """Start a multipart upload and return the ``UploadId``."""
        self._check_tenant(key)
        bucket = self._bucket_for(key.purpose)
        with tracer.start_as_current_span(
            "storage.multipart_init", attributes={"bucket": bucket, "key": key.key}
        ):
            client = self._get_boto()
            kwargs: dict[str, Any] = {"Bucket": bucket, "Key": key.key}
            if content_type is not None:
                kwargs["ContentType"] = content_type
            try:
                resp = await self._run(
                    lambda: client.create_multipart_upload(**kwargs)
                )
            except Exception as exc:
                raise self._map_client_error(exc, key) from exc
            upload_id = resp["UploadId"]
            assert isinstance(upload_id, str)
            return upload_id

    async def upload_part(
        self,
        key: ObjectKey,
        upload_id: str,
        part_number: int,
        body: bytes,
    ) -> str:
        """Upload one part; returns the part ``ETag`` for completion."""
        self._check_tenant(key)
        bucket = self._bucket_for(key.purpose)
        with tracer.start_as_current_span(
            "storage.multipart_part",
            attributes={
                "bucket": bucket,
                "key": key.key,
                "part": part_number,
                "size": len(body),
            },
        ):
            client = self._get_boto()
            try:
                resp = await self._run(
                    lambda: client.upload_part(
                        Bucket=bucket,
                        Key=key.key,
                        PartNumber=part_number,
                        UploadId=upload_id,
                        Body=body,
                    )
                )
            except Exception as exc:
                raise self._map_client_error(exc, key) from exc
            etag = resp["ETag"]
            assert isinstance(etag, str)
            return etag

    async def complete_multipart(
        self,
        key: ObjectKey,
        upload_id: str,
        parts: list[tuple[int, str]],
    ) -> None:
        """Complete a multipart upload.  ``parts`` is ``[(part_number, etag), ...]``."""
        self._check_tenant(key)
        bucket = self._bucket_for(key.purpose)
        with tracer.start_as_current_span(
            "storage.multipart_complete",
            attributes={"bucket": bucket, "key": key.key, "parts": len(parts)},
        ):
            client = self._get_boto()
            mpu = {
                "Parts": [
                    {"PartNumber": pn, "ETag": etag} for pn, etag in parts
                ]
            }
            try:
                await self._run(
                    lambda: client.complete_multipart_upload(
                        Bucket=bucket,
                        Key=key.key,
                        UploadId=upload_id,
                        MultipartUpload=mpu,
                    )
                )
            except Exception as exc:
                raise self._map_client_error(exc, key) from exc
            log.info(
                "storage.multipart_complete",
                bucket=bucket,
                key=key.key,
                parts=len(parts),
            )

    async def abort_multipart(self, key: ObjectKey, upload_id: str) -> None:
        """Abort an in-flight multipart upload."""
        self._check_tenant(key)
        bucket = self._bucket_for(key.purpose)
        with tracer.start_as_current_span(
            "storage.multipart_abort",
            attributes={"bucket": bucket, "key": key.key},
        ):
            client = self._get_boto()
            try:
                await self._run(
                    lambda: client.abort_multipart_upload(
                        Bucket=bucket, Key=key.key, UploadId=upload_id
                    )
                )
            except Exception as exc:
                raise self._map_client_error(exc, key) from exc


def get_storage_client(
    settings: StorageSettings | None = None,
    tenant_id: str | None = None,
    quota_checker: QuotaChecker | None = None,
) -> StorageClient:
    """Factory.  Phase 1 does NOT auto-read tenant from any context package
    (avoids a foundation_context dependency).  Callers must pass ``tenant_id``
    explicitly; Phase 2 will pull it from a shared request-scope context when
    we wire audit/security-ops onto this layer.
    """
    return StorageClient(
        settings=settings or get_settings(),
        tenant_id=tenant_id,
        quota_checker=quota_checker,
    )
