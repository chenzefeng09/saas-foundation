"""Unit tests for StorageClient — boto3 is mocked at the import boundary."""

from __future__ import annotations

import sys
import types
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from foundation_storage.client import StorageClient, get_storage_client
from foundation_storage.config import StorageSettings
from foundation_storage.errors import (
    KeyValidationError,
    ObjectLockedError,
    ObjectNotFoundError,
    StorageError,
)
from foundation_storage.keys import BucketPurpose, ObjectKey

# ---------------------------------------------------------------------------
# Helpers — inject a fake ``boto3``/``botocore`` into sys.modules so importing
# from inside StorageClient picks up our doubles.
# ---------------------------------------------------------------------------


class _FakeClientError(Exception):
    def __init__(self, code: str, http_status: int = 400) -> None:
        self.response: dict[str, Any] = {
            "Error": {"Code": code, "Message": code},
            "ResponseMetadata": {"HTTPStatusCode": http_status},
        }
        super().__init__(code)


@pytest.fixture
def fake_boto(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Install fake ``boto3`` & ``botocore.exceptions`` modules; yield the mock client."""
    s3_client = MagicMock(name="s3_client")

    boto3_mod = types.ModuleType("boto3")
    boto3_mod.client = MagicMock(return_value=s3_client)  # type: ignore[attr-defined]

    botocore_mod = types.ModuleType("botocore")
    botocore_config = types.ModuleType("botocore.config")
    botocore_config.Config = MagicMock(return_value=MagicMock())  # type: ignore[attr-defined]
    botocore_exceptions = types.ModuleType("botocore.exceptions")
    botocore_exceptions.ClientError = _FakeClientError  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "boto3", boto3_mod)
    monkeypatch.setitem(sys.modules, "botocore", botocore_mod)
    monkeypatch.setitem(sys.modules, "botocore.config", botocore_config)
    monkeypatch.setitem(sys.modules, "botocore.exceptions", botocore_exceptions)
    return s3_client


@pytest.fixture
def settings() -> StorageSettings:
    # Functional S3 tests isolate the storage backend. Mandatory access-control
    # behavior is covered separately in test_access_control.py.
    return StorageSettings(access_control_enabled=False)


# ---------------------------------------------------------------------------
# Tenant scope enforcement
# ---------------------------------------------------------------------------


class TestTenantScope:
    def test_constructor_rejects_implicit_system_scope(
        self, settings: StorageSettings
    ) -> None:
        with pytest.raises(KeyValidationError, match="StorageClient.as_system"):
            StorageClient(settings, tenant_id=None)

    def test_factory_requires_explicit_tenant(self) -> None:
        with pytest.raises(TypeError):
            get_storage_client()  # type: ignore[call-arg]

    @pytest.mark.asyncio
    async def test_put_object_wrong_tenant_rejected(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        client = StorageClient(settings, tenant_id="tnt_01")
        key = ObjectKey.for_workspace_file("tnt_02", "ws_1", "f_1", "x.pdf")
        with pytest.raises(KeyValidationError):
            await client.put_object(key, body=b"x")
        fake_boto.put_object.assert_not_called()

    @pytest.mark.asyncio
    async def test_system_client_accepts_any_tenant(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        client = StorageClient.as_system(settings)
        assert client.tenant_id is None
        key = ObjectKey.for_workspace_file("tnt_anything", "ws_1", "f_1", "x.pdf")
        await client.put_object(key, body=b"x")
        fake_boto.put_object.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_prefix_wrong_tenant_rejected(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        client = StorageClient(settings, tenant_id="tnt_01")
        with pytest.raises(KeyValidationError):
            await client.list_prefix(BucketPurpose.WORKSPACE, "tnt_02")


# ---------------------------------------------------------------------------
# put_object + quota integration
# ---------------------------------------------------------------------------


class TestPutObject:
    @pytest.mark.asyncio
    async def test_put_object_calls_boto_with_expected_args(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        client = StorageClient(settings, tenant_id="tnt_01")
        key = ObjectKey.for_workspace_file("tnt_01", "ws_1", "f_1", "x.pdf")
        await client.put_object(key, body=b"hello", content_type="application/pdf")

        fake_boto.put_object.assert_called_once()
        kwargs = fake_boto.put_object.call_args.kwargs
        assert kwargs["Bucket"] == "foundation-workspace"
        assert kwargs["Key"] == "tenants/tnt_01/workspaces/ws_1/files/f_1/x.pdf"
        assert kwargs["Body"] == b"hello"
        assert kwargs["ContentType"] == "application/pdf"

    @pytest.mark.asyncio
    async def test_put_object_quota_check_then_increment(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        quota = MagicMock()
        quota.check_before_upload = AsyncMock(return_value=None)
        quota.increment_used = AsyncMock(return_value=None)

        client = StorageClient(settings, tenant_id="tnt_01", quota_checker=quota)
        key = ObjectKey.for_workspace_file("tnt_01", "ws_1", "f_1", "x.pdf")
        await client.put_object(key, body=b"abc")

        quota.check_before_upload.assert_awaited_once_with(
            "tnt_01", BucketPurpose.WORKSPACE, 3
        )
        quota.increment_used.assert_awaited_once_with(
            "tnt_01", BucketPurpose.WORKSPACE, 3
        )
        # Order: check happens before put; increment happens after put.
        fake_boto.put_object.assert_called_once()

    @pytest.mark.asyncio
    async def test_put_object_skips_quota_when_disabled(
        self, fake_boto: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("STORAGE_QUOTA_CHECK_ENABLED", "false")
        s = StorageSettings(access_control_enabled=False)
        quota = MagicMock()
        quota.check_before_upload = AsyncMock()
        quota.increment_used = AsyncMock()
        client = StorageClient(s, tenant_id="tnt_01", quota_checker=quota)
        key = ObjectKey.for_workspace_file("tnt_01", "ws_1", "f_1", "x.pdf")
        await client.put_object(key, body=b"x")
        quota.check_before_upload.assert_not_called()
        quota.increment_used.assert_not_called()

    @pytest.mark.asyncio
    async def test_put_object_with_metadata(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        client = StorageClient(settings, tenant_id="tnt_01")
        key = ObjectKey.for_workspace_file("tnt_01", "ws_1", "f_1", "x.pdf")
        await client.put_object(key, body=b"x", metadata={"k": "v"})
        assert fake_boto.put_object.call_args.kwargs["Metadata"] == {"k": "v"}


# ---------------------------------------------------------------------------
# get / head / delete / list / presign
# ---------------------------------------------------------------------------


class TestRead:
    @pytest.mark.asyncio
    async def test_get_object_returns_bytes(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        body_stream = MagicMock()
        body_stream.read.return_value = b"payload"
        fake_boto.get_object.return_value = {"Body": body_stream}

        client = StorageClient(settings, tenant_id="tnt_01")
        key = ObjectKey.for_workspace_file("tnt_01", "ws_1", "f_1", "x.pdf")
        out = await client.get_object(key)
        assert out == b"payload"
        fake_boto.get_object.assert_called_once_with(
            Bucket="foundation-workspace",
            Key="tenants/tnt_01/workspaces/ws_1/files/f_1/x.pdf",
        )

    @pytest.mark.asyncio
    async def test_head_object_meta(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        fake_boto.head_object.return_value = {
            "ContentLength": 42,
            "ContentType": "application/pdf",
            "Metadata": {"k": "v"},
        }
        client = StorageClient(settings, tenant_id="tnt_01")
        key = ObjectKey.for_workspace_file("tnt_01", "ws_1", "f_1", "x.pdf")
        meta = await client.head_object(key)
        assert meta.content_length == 42
        assert meta.content_type == "application/pdf"
        assert meta.metadata == {"k": "v"}

    @pytest.mark.asyncio
    async def test_list_prefix(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        fake_boto.list_objects_v2.return_value = {
            "Contents": [
                {"Key": "tenants/tnt_01/workspaces/ws_1/files/f_1/x.pdf", "Size": 12},
            ]
        }
        client = StorageClient(settings, tenant_id="tnt_01")
        items, next_token = await client.list_prefix(
            BucketPurpose.WORKSPACE, "tnt_01", prefix_segments=["workspaces", "ws_1"]
        )
        assert len(items) == 1
        assert items[0].content_length == 12
        assert next_token is None
        kwargs = fake_boto.list_objects_v2.call_args.kwargs
        assert kwargs["Bucket"] == "foundation-workspace"
        assert kwargs["Prefix"] == "tenants/tnt_01/workspaces/ws_1/"
        assert "ContinuationToken" not in kwargs

    @pytest.mark.asyncio
    async def test_list_prefix_no_segments(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        fake_boto.list_objects_v2.return_value = {"Contents": []}
        client = StorageClient(settings, tenant_id="tnt_01")
        items, next_token = await client.list_prefix(BucketPurpose.WORKSPACE, "tnt_01")
        assert items == []
        assert next_token is None
        assert fake_boto.list_objects_v2.call_args.kwargs["Prefix"] == "tenants/tnt_01/"

    @pytest.mark.asyncio
    async def test_list_prefix_returns_continuation_token(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        fake_boto.list_objects_v2.return_value = {
            "Contents": [
                {"Key": "tenants/tnt_01/a", "Size": 1},
            ],
            "NextContinuationToken": "tok_abc",
        }
        client = StorageClient(settings, tenant_id="tnt_01")
        items, next_token = await client.list_prefix(
            BucketPurpose.WORKSPACE, "tnt_01"
        )
        assert len(items) == 1
        assert next_token == "tok_abc"

    @pytest.mark.asyncio
    async def test_list_prefix_passes_continuation_token(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        fake_boto.list_objects_v2.return_value = {"Contents": []}
        client = StorageClient(settings, tenant_id="tnt_01")
        await client.list_prefix(
            BucketPurpose.WORKSPACE, "tnt_01", continuation_token="tok_in"
        )
        kwargs = fake_boto.list_objects_v2.call_args.kwargs
        assert kwargs["ContinuationToken"] == "tok_in"

    @pytest.mark.asyncio
    async def test_iter_prefix_follows_continuation_across_pages(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        page1 = {
            "Contents": [
                {"Key": "tenants/tnt_01/a", "Size": 1},
                {"Key": "tenants/tnt_01/b", "Size": 2},
            ],
            "NextContinuationToken": "tok_p2",
        }
        page2 = {
            "Contents": [
                {"Key": "tenants/tnt_01/c", "Size": 3},
            ],
        }
        fake_boto.list_objects_v2.side_effect = [page1, page2]

        client = StorageClient(settings, tenant_id="tnt_01")
        collected: list[str] = []
        async for meta in client.iter_prefix(BucketPurpose.WORKSPACE, "tnt_01"):
            collected.append(meta.key)
        assert collected == [
            "tenants/tnt_01/a",
            "tenants/tnt_01/b",
            "tenants/tnt_01/c",
        ]
        assert fake_boto.list_objects_v2.call_count == 2
        second_call_kwargs = fake_boto.list_objects_v2.call_args_list[1].kwargs
        assert second_call_kwargs["ContinuationToken"] == "tok_p2"

    @pytest.mark.asyncio
    async def test_iter_prefix_empty_yields_nothing(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        fake_boto.list_objects_v2.return_value = {"Contents": []}
        client = StorageClient(settings, tenant_id="tnt_01")
        out: list[str] = []
        async for meta in client.iter_prefix(BucketPurpose.WORKSPACE, "tnt_01"):
            out.append(meta.key)
        assert out == []


class TestComputeTenantUsage:
    @pytest.mark.asyncio
    async def test_sums_size_across_pages(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"Contents": [{"Key": "tenants/tnt_01/a", "Size": 100},
                          {"Key": "tenants/tnt_01/b", "Size": 250}]},
            {"Contents": [{"Key": "tenants/tnt_01/c", "Size": 50}]},
        ]
        fake_boto.get_paginator.return_value = paginator

        client = StorageClient.as_system(settings)
        total = await client.compute_tenant_usage("tnt_01", BucketPurpose.WORKSPACE)
        assert total == 400
        paginator.paginate.assert_called_once_with(
            Bucket="foundation-workspace", Prefix="tenants/tnt_01/"
        )

    @pytest.mark.asyncio
    async def test_empty_bucket_returns_zero(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Contents": []}]
        fake_boto.get_paginator.return_value = paginator

        client = StorageClient.as_system(settings)
        total = await client.compute_tenant_usage("tnt_01", BucketPurpose.KB_RAW)
        assert total == 0

    @pytest.mark.asyncio
    async def test_cross_tenant_rejected(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        client = StorageClient(settings, tenant_id="tnt_01")
        with pytest.raises(KeyValidationError):
            await client.compute_tenant_usage("tnt_02", BucketPurpose.WORKSPACE)


class TestPresign:
    @pytest.mark.asyncio
    async def test_generate_presigned_url(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        fake_boto.generate_presigned_url.return_value = "https://signed.example/x"
        client = StorageClient(settings, tenant_id="tnt_01")
        key = ObjectKey.for_workspace_file("tnt_01", "ws_1", "f_1", "x.pdf")
        url = await client.generate_presigned_url(key)
        assert url == "https://signed.example/x"
        kwargs = fake_boto.generate_presigned_url.call_args.kwargs
        assert kwargs["ClientMethod"] == "get_object"
        assert kwargs["ExpiresIn"] == settings.presigned_url_ttl_seconds
        assert kwargs["Params"]["Bucket"] == "foundation-workspace"

    @pytest.mark.asyncio
    async def test_generate_presigned_url_put_with_ttl(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        fake_boto.generate_presigned_url.return_value = "https://signed.example/put"
        client = StorageClient(settings, tenant_id="tnt_01")
        key = ObjectKey.for_workspace_file("tnt_01", "ws_1", "f_1", "x.pdf")
        url = await client.generate_presigned_url(key, operation="put_object", expires_in=60)
        assert url.startswith("https://")
        kwargs = fake_boto.generate_presigned_url.call_args.kwargs
        assert kwargs["ClientMethod"] == "put_object"
        assert kwargs["ExpiresIn"] == 60

    @pytest.mark.asyncio
    @pytest.mark.parametrize("operation", ["delete_object", "head_object", ""])
    async def test_rejects_non_whitelisted_operation(
        self,
        fake_boto: MagicMock,
        settings: StorageSettings,
        operation: str,
    ) -> None:
        client = StorageClient(settings, tenant_id="tnt_01")
        key = ObjectKey.for_workspace_file("tnt_01", "ws_1", "f_1", "x.pdf")

        with pytest.raises(KeyValidationError, match="get_object.*put_object"):
            await client.generate_presigned_url(key, operation=operation)  # type: ignore[arg-type]

        fake_boto.generate_presigned_url.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("expires_in", [0, -1, 61, True])
    async def test_rejects_ttl_outside_configured_limit(
        self,
        fake_boto: MagicMock,
        expires_in: int,
    ) -> None:
        settings = StorageSettings(
            access_control_enabled=False,
            presigned_url_ttl_seconds=60,
        )
        client = StorageClient(settings, tenant_id="tnt_01")
        key = ObjectKey.for_workspace_file("tnt_01", "ws_1", "f_1", "x.pdf")

        with pytest.raises(KeyValidationError, match="between 1 and 60"):
            await client.generate_presigned_url(key, expires_in=expires_in)

        fake_boto.generate_presigned_url.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("expires_in", [1, 60])
    async def test_accepts_ttl_boundaries(
        self,
        fake_boto: MagicMock,
        expires_in: int,
    ) -> None:
        fake_boto.generate_presigned_url.return_value = "https://signed.example/x"
        settings = StorageSettings(
            access_control_enabled=False,
            presigned_url_ttl_seconds=60,
        )
        client = StorageClient(settings, tenant_id="tnt_01")
        key = ObjectKey.for_workspace_file("tnt_01", "ws_1", "f_1", "x.pdf")

        await client.generate_presigned_url(key, expires_in=expires_in)

        assert fake_boto.generate_presigned_url.call_args.kwargs["ExpiresIn"] == expires_in


# ---------------------------------------------------------------------------
# Error mapping
# ---------------------------------------------------------------------------


class TestErrorMapping:
    @pytest.mark.asyncio
    async def test_no_such_key_maps_to_object_not_found(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        fake_boto.get_object.side_effect = _FakeClientError("NoSuchKey", 404)
        client = StorageClient(settings, tenant_id="tnt_01")
        key = ObjectKey.for_workspace_file("tnt_01", "ws_1", "f_1", "x.pdf")
        with pytest.raises(ObjectNotFoundError):
            await client.get_object(key)

    @pytest.mark.asyncio
    async def test_404_status_maps_to_not_found(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        fake_boto.head_object.side_effect = _FakeClientError("OtherCode", 404)
        client = StorageClient(settings, tenant_id="tnt_01")
        key = ObjectKey.for_workspace_file("tnt_01", "ws_1", "f_1", "x.pdf")
        with pytest.raises(ObjectNotFoundError):
            await client.head_object(key)

    @pytest.mark.asyncio
    async def test_access_denied_on_audit_delete_maps_to_locked(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        # head_object is called before delete to size the quota decrement;
        # stub it so we can isolate the AccessDenied → ObjectLockedError mapping.
        fake_boto.head_object.return_value = {"ContentLength": 0}
        fake_boto.delete_object.side_effect = _FakeClientError("AccessDenied", 403)
        client = StorageClient(settings, tenant_id="tnt_01")
        # Audit bucket has Object Lock; AccessDenied here means WORM blocked the delete.
        from datetime import UTC, datetime

        key = ObjectKey.for_audit_event(
            "tnt_01", datetime(2026, 1, 1, tzinfo=UTC), "evt_1"
        )
        with pytest.raises(ObjectLockedError):
            await client.delete_object(key)

    @pytest.mark.asyncio
    async def test_unknown_error_maps_to_storage_error(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        fake_boto.get_object.side_effect = _FakeClientError("InternalError", 500)
        client = StorageClient(settings, tenant_id="tnt_01")
        key = ObjectKey.for_workspace_file("tnt_01", "ws_1", "f_1", "x.pdf")
        with pytest.raises(StorageError) as ei:
            await client.get_object(key)
        assert not isinstance(ei.value, ObjectNotFoundError | ObjectLockedError)

    @pytest.mark.asyncio
    async def test_non_client_error_wrapped(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        fake_boto.put_object.side_effect = RuntimeError("network!")
        client = StorageClient(settings, tenant_id="tnt_01")
        key = ObjectKey.for_workspace_file("tnt_01", "ws_1", "f_1", "x.pdf")
        with pytest.raises(StorageError):
            await client.put_object(key, body=b"x")


# ---------------------------------------------------------------------------
# Multipart
# ---------------------------------------------------------------------------


class TestMultipart:
    @pytest.mark.asyncio
    async def test_initiate_upload_complete_roundtrip(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        fake_boto.create_multipart_upload.return_value = {"UploadId": "upid_xyz"}
        fake_boto.upload_part.return_value = {"ETag": '"etag-1"'}
        fake_boto.complete_multipart_upload.return_value = {}

        client = StorageClient(settings, tenant_id="tnt_01")
        key = ObjectKey.for_workspace_file("tnt_01", "ws_1", "f_1", "big.bin")

        upload_id = await client.initiate_multipart(key, content_type="application/octet-stream")
        assert upload_id == "upid_xyz"

        etag = await client.upload_part(key, upload_id, 1, b"AAA")
        assert etag == '"etag-1"'

        await client.complete_multipart(key, upload_id, [(1, '"etag-1"')])
        complete_kwargs = fake_boto.complete_multipart_upload.call_args.kwargs
        assert complete_kwargs["UploadId"] == "upid_xyz"
        assert complete_kwargs["MultipartUpload"] == {
            "Parts": [{"PartNumber": 1, "ETag": '"etag-1"'}]
        }

    @pytest.mark.asyncio
    async def test_abort_multipart(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        client = StorageClient(settings, tenant_id="tnt_01")
        key = ObjectKey.for_workspace_file("tnt_01", "ws_1", "f_1", "x.bin")
        await client.abort_multipart(key, "upid_xyz")
        fake_boto.abort_multipart_upload.assert_called_once_with(
            Bucket="foundation-workspace",
            Key="tenants/tnt_01/workspaces/ws_1/files/f_1/x.bin",
            UploadId="upid_xyz",
        )


# ---------------------------------------------------------------------------
# Delete + factory
# ---------------------------------------------------------------------------


class TestDeleteAndFactory:
    @pytest.mark.asyncio
    async def test_delete_object_normal(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        # Make head_object return a known size so the quota path runs.
        fake_boto.head_object.return_value = {"ContentLength": 0}
        client = StorageClient(settings, tenant_id="tnt_01")
        key = ObjectKey.for_workspace_file("tnt_01", "ws_1", "f_1", "x.pdf")
        await client.delete_object(key)
        fake_boto.delete_object.assert_called_once_with(
            Bucket="foundation-workspace",
            Key="tenants/tnt_01/workspaces/ws_1/files/f_1/x.pdf",
        )

    @pytest.mark.asyncio
    async def test_delete_object_decrements_quota(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        """head_object size feeds a negative ``increment_used`` after delete."""
        fake_boto.head_object.return_value = {"ContentLength": 4096}
        quota = MagicMock()
        quota.check_before_upload = AsyncMock(return_value=None)
        quota.increment_used = AsyncMock(return_value=None)

        client = StorageClient(settings, tenant_id="tnt_01", quota_checker=quota)
        key = ObjectKey.for_workspace_file("tnt_01", "ws_1", "f_1", "x.pdf")
        await client.delete_object(key)

        quota.increment_used.assert_awaited_once_with(
            "tnt_01", BucketPurpose.WORKSPACE, -4096
        )

    @pytest.mark.asyncio
    async def test_delete_object_skips_quota_when_head_fails(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        """If head_object errors, quota stays untouched and delete proceeds.

        Better a small positive drift caught by reconcile than over-credit.
        """
        fake_boto.head_object.side_effect = _FakeClientError("NoSuchKey", 404)
        quota = MagicMock()
        quota.check_before_upload = AsyncMock(return_value=None)
        quota.increment_used = AsyncMock(return_value=None)

        client = StorageClient(settings, tenant_id="tnt_01", quota_checker=quota)
        key = ObjectKey.for_workspace_file("tnt_01", "ws_1", "f_1", "x.pdf")
        await client.delete_object(key)
        quota.increment_used.assert_not_called()
        fake_boto.delete_object.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_object_failure_skips_increment(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        """WORM-locked delete (audit bucket): we head OK then delete fails —
        the quota must NOT decrement because the object is still there.
        """
        from datetime import UTC, datetime

        fake_boto.head_object.return_value = {"ContentLength": 1024}
        fake_boto.delete_object.side_effect = _FakeClientError("AccessDenied", 403)
        quota = MagicMock()
        quota.check_before_upload = AsyncMock(return_value=None)
        quota.increment_used = AsyncMock(return_value=None)

        client = StorageClient(settings, tenant_id="tnt_01", quota_checker=quota)
        key = ObjectKey.for_audit_event(
            "tnt_01", datetime(2026, 1, 1, tzinfo=UTC), "evt_1"
        )
        with pytest.raises(ObjectLockedError):
            await client.delete_object(key)
        quota.increment_used.assert_not_called()

    def test_get_storage_client_factory(self) -> None:
        c = get_storage_client(tenant_id="tnt_01")
        assert isinstance(c, StorageClient)
        assert c.tenant_id == "tnt_01"

    def test_bucket_for_all_purposes(self, settings: StorageSettings) -> None:
        client = StorageClient.as_system(settings)
        assert client._bucket_for(BucketPurpose.AUDIT) == "foundation-audit"
        assert client._bucket_for(BucketPurpose.WORKSPACE) == "foundation-workspace"
        assert client._bucket_for(BucketPurpose.KB_RAW) == "foundation-kb-raw"
        assert client._bucket_for(BucketPurpose.KB_DERIVED) == "foundation-kb-derived"

    def test_get_boto_caches_client(
        self, fake_boto: MagicMock, settings: StorageSettings
    ) -> None:
        client = StorageClient.as_system(settings)
        a = client._get_boto()
        b = client._get_boto()
        assert a is b
