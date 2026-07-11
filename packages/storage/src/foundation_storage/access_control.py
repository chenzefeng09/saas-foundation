"""Mandatory DLP clearance checks for tenant-scoped storage operations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

import httpx

from foundation_storage.errors import (
    ACCESS_CONTROL_UNAVAILABLE,
    ACCESS_DENIED,
    AccessControlError,
)
from foundation_storage.keys import BucketPurpose, ObjectKey

AccessAction = Literal["READ", "DOWNLOAD", "WRITE", "DELETE"]


@dataclass(frozen=True, slots=True)
class AccessDecision:
    allowed: bool
    sensitivity: str | None = None
    reason: str | None = None


class StorageAccessChecker(Protocol):
    async def check(
        self,
        *,
        tenant_id: str,
        actor_id: str,
        key: ObjectKey,
        action: AccessAction,
        destination: str | None = None,
    ) -> AccessDecision: ...


def resource_ref_for_key(key: ObjectKey) -> tuple[str, str]:
    """Map canonical object layouts to their DLP resource identifiers."""
    parts = key.path_segments
    if key.purpose == BucketPurpose.WORKSPACE:
        if len(parts) >= 5 and parts[0] == "workspaces" and parts[2] == "files":
            return "file", parts[3]
        if len(parts) >= 4 and parts[0] == "security-ops":
            return parts[1], parts[2]
    if key.purpose in (BucketPurpose.KB_RAW, BucketPurpose.KB_DERIVED):
        if len(parts) >= 4 and parts[0] == "kbs" and parts[2] == "docs":
            return "kb_document", parts[3]
    if key.purpose == BucketPurpose.AUDIT and len(parts) >= 2:
        return "audit_event", parts[-1].removesuffix(".json")
    return "storage_object", key.key


class DLPStorageAccessChecker:
    """HTTP adapter for DLP's context-derived read/download checks."""

    def __init__(
        self,
        *,
        base_url: str,
        timeout_seconds: float = 2.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout_seconds
        self._injected = client

    async def check(
        self,
        *,
        tenant_id: str,
        actor_id: str,
        key: ObjectKey,
        action: AccessAction,
        destination: str | None = None,
    ) -> AccessDecision:
        resource_type, resource_id = resource_ref_for_key(key)
        path = "check:download" if action == "DOWNLOAD" else "check:read"
        payload = {"resource_type": resource_type, "resource_id": resource_id}
        if action == "DOWNLOAD":
            payload["destination"] = destination or "presigned_url"
        headers = {
            "X-Tenant-Id": tenant_id,
            "X-User-Id": actor_id,
            "X-Actor": "USER",
        }
        client = self._injected or httpx.AsyncClient(timeout=self._timeout)
        try:
            try:
                response = await client.post(
                    f"{self._base}/core/{path}",
                    json=payload,
                    headers=headers,
                )
            except (httpx.TimeoutException, httpx.HTTPError) as exc:
                raise AccessControlError(
                    ACCESS_CONTROL_UNAVAILABLE,
                    detail="DLP access check is unavailable; storage read denied",
                ) from exc
        finally:
            if self._injected is None:
                await client.aclose()

        if response.status_code in (401, 403):
            return AccessDecision(allowed=False, reason="DLP denied the request")
        if response.status_code != 200:
            raise AccessControlError(
                ACCESS_CONTROL_UNAVAILABLE,
                detail=f"DLP access check returned {response.status_code}; storage read denied",
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise AccessControlError(
                ACCESS_CONTROL_UNAVAILABLE,
                detail="DLP access check returned invalid JSON; storage read denied",
            ) from exc
        if not isinstance(body, dict) or not isinstance(body.get("allowed"), bool):
            raise AccessControlError(
                ACCESS_CONTROL_UNAVAILABLE,
                detail="DLP access check returned an invalid decision; storage read denied",
            )
        return AccessDecision(
            allowed=body["allowed"],
            sensitivity=body.get("sensitivity"),
            reason=body.get("reason"),
        )


def deny_missing_access_context() -> AccessControlError:
    return AccessControlError(
        ACCESS_DENIED,
        detail="Tenant-scoped storage operations require an actor and DLP access checker",
    )
