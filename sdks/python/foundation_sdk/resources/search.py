"""Search resource — full-text search with tenant + ACL filtering."""

from __future__ import annotations

from typing import Any

from foundation_sdk._transport import Transport


class SearchResource:
    """Full-text search with automatic tenant isolation and ACL filtering."""

    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def query(self, *, q: str, resource_types: list[str] | None = None,
              tags: list[str] | None = None, cursor: str | None = None,
              limit: int = 20) -> dict[str, Any]:
        body: dict[str, Any] = {"q": q, "limit": limit}
        if resource_types:
            body["resource_types"] = resource_types
        if tags:
            body["tags"] = tags
        if cursor:
            body["cursor"] = cursor
        return self._t.request("POST", "/api/search/v1/query", json=body)

    async def query_async(self, *, q: str, resource_types: list[str] | None = None,
                           tags: list[str] | None = None, cursor: str | None = None,
                           limit: int = 20) -> dict[str, Any]:
        body: dict[str, Any] = {"q": q, "limit": limit}
        if resource_types:
            body["resource_types"] = resource_types
        if tags:
            body["tags"] = tags
        if cursor:
            body["cursor"] = cursor
        return await self._t.request_async("POST", "/api/search/v1/query", json=body)

    def index(self, *, resource_type: str, resource_id: str, title: str,
              content: str, tags: list[str] | None = None,
              acl_user_ids: list[str] | None = None,
              metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._t.request("POST", "/api/search/v1/index",
                                json={"resource_type": resource_type,
                                      "resource_id": resource_id,
                                      "title": title, "content": content,
                                      "tags": tags or [], "acl_user_ids": acl_user_ids or [],
                                      "metadata": metadata or {}})

    def deindex(self, resource_type: str, resource_id: str) -> dict[str, Any]:
        return self._t.request("DELETE", f"/api/search/v1/index/{resource_type}/{resource_id}")
