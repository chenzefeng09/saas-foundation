from __future__ import annotations

import sys
import types
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from foundation_storage.access_control import (
    AccessDecision,
    DLPStorageAccessChecker,
    resource_ref_for_key,
)
from foundation_storage.client import StorageClient
from foundation_storage.config import StorageSettings
from foundation_storage.errors import (
    ACCESS_CONTROL_UNAVAILABLE,
    ACCESS_DENIED,
    AccessControlError,
    KeyValidationError,
)
from foundation_storage.keys import BucketPurpose, ObjectKey

TENANT = "tnt_01"
ACTOR = "usr_01"


@pytest.fixture
def fake_boto(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    s3 = MagicMock()
    body = MagicMock()
    body.read.return_value = b"payload"
    s3.get_object.return_value = {"Body": body}
    s3.generate_presigned_url.return_value = "https://signed.example/file"

    boto3_mod = types.ModuleType("boto3")
    boto3_mod.client = MagicMock(return_value=s3)  # type: ignore[attr-defined]
    botocore_mod = types.ModuleType("botocore")
    botocore_config = types.ModuleType("botocore.config")
    botocore_config.Config = MagicMock(return_value=MagicMock())  # type: ignore[attr-defined]
    botocore_exceptions = types.ModuleType("botocore.exceptions")
    botocore_exceptions.ClientError = Exception  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "boto3", boto3_mod)
    monkeypatch.setitem(sys.modules, "botocore", botocore_mod)
    monkeypatch.setitem(sys.modules, "botocore.config", botocore_config)
    monkeypatch.setitem(sys.modules, "botocore.exceptions", botocore_exceptions)
    return s3


def _key() -> ObjectKey:
    return ObjectKey.for_workspace_file(TENANT, "ws_1", "file_1", "secret.pdf")


@pytest.mark.asyncio
async def test_only_explicit_system_client_bypasses_access_control(
    fake_boto: MagicMock,
) -> None:
    with pytest.raises(KeyValidationError, match="StorageClient.as_system"):
        StorageClient(StorageSettings(), tenant_id=None)

    system_client = StorageClient.as_system(StorageSettings())
    assert await system_client.get_object(_key()) == b"payload"
    fake_boto.get_object.assert_called_once()


@pytest.mark.asyncio
async def test_tenant_read_without_security_context_fails_closed(fake_boto: MagicMock) -> None:
    client = StorageClient(StorageSettings(), tenant_id=TENANT)
    with pytest.raises(AccessControlError) as exc_info:
        await client.get_object(_key())
    assert exc_info.value.error_code == ACCESS_DENIED
    fake_boto.get_object.assert_not_called()


@pytest.mark.asyncio
async def test_tenant_write_without_security_context_fails_closed(fake_boto: MagicMock) -> None:
    client = StorageClient(StorageSettings(), tenant_id=TENANT)
    with pytest.raises(AccessControlError) as exc_info:
        await client.put_object(_key(), body=b"payload")
    assert exc_info.value.error_code == ACCESS_DENIED
    fake_boto.put_object.assert_not_called()


@pytest.mark.asyncio
async def test_dlp_denial_prevents_storage_read(fake_boto: MagicMock) -> None:
    checker = MagicMock()
    checker.check = AsyncMock(
        return_value=AccessDecision(False, sensitivity="L4", reason="clearance insufficient")
    )
    client = StorageClient(
        StorageSettings(),
        tenant_id=TENANT,
        actor_id=ACTOR,
        access_checker=checker,
    )
    with pytest.raises(AccessControlError) as exc_info:
        await client.get_object(_key())
    assert exc_info.value.error_code == ACCESS_DENIED
    fake_boto.get_object.assert_not_called()


@pytest.mark.asyncio
async def test_allowed_download_paths_are_checked(fake_boto: MagicMock) -> None:
    checker = MagicMock()
    checker.check = AsyncMock(return_value=AccessDecision(True, sensitivity="L3"))
    client = StorageClient(
        StorageSettings(),
        tenant_id=TENANT,
        actor_id=ACTOR,
        access_checker=checker,
    )
    assert await client.get_object(_key()) == b"payload"
    assert await client.generate_presigned_url(_key()) == "https://signed.example/file"
    assert checker.check.await_args_list[0].kwargs["action"] == "DOWNLOAD"
    assert checker.check.await_args_list[0].kwargs["destination"] == "service_stream"
    assert checker.check.await_args_list[1].kwargs["action"] == "DOWNLOAD"


@pytest.mark.asyncio
async def test_direct_tenant_listing_is_forbidden(fake_boto: MagicMock) -> None:
    checker = MagicMock()
    checker.check = AsyncMock(return_value=AccessDecision(True))
    client = StorageClient(
        StorageSettings(), tenant_id=TENANT, actor_id=ACTOR, access_checker=checker
    )
    with pytest.raises(AccessControlError) as exc_info:
        await client.list_prefix(BucketPurpose.WORKSPACE, TENANT)
    assert exc_info.value.error_code == ACCESS_DENIED
    fake_boto.list_objects_v2.assert_not_called()


def test_resource_reference_uses_file_id_not_object_path() -> None:
    assert resource_ref_for_key(_key()) == ("file", "file_1")


@pytest.mark.asyncio
async def test_http_checker_uses_context_identity_and_no_clearance_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/core/check:read")
        assert request.headers["X-Tenant-Id"] == TENANT
        assert request.headers["X-User-Id"] == ACTOR
        payload = __import__("json").loads(request.content)
        assert payload == {"resource_type": "file", "resource_id": "file_1"}
        return httpx.Response(200, json={"allowed": True, "sensitivity": "L3"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        checker = DLPStorageAccessChecker(base_url="http://dlp/api/dlp/v1", client=http)
        decision = await checker.check(
            tenant_id=TENANT,
            actor_id=ACTOR,
            key=_key(),
            action="READ",
        )
    assert decision.allowed is True


@pytest.mark.asyncio
async def test_http_checker_failure_is_not_treated_as_allow() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"detail": "down"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        checker = DLPStorageAccessChecker(base_url="http://dlp/api/dlp/v1", client=http)
        with pytest.raises(AccessControlError) as exc_info:
            await checker.check(
                tenant_id=TENANT,
                actor_id=ACTOR,
                key=_key(),
                action="READ",
            )
    assert exc_info.value.error_code == ACCESS_CONTROL_UNAVAILABLE
