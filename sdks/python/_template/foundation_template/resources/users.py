"""Users resource — example of the standard Resource pattern."""

from __future__ import annotations

from foundation_template._transport import Transport
from foundation_template.models import (
    CreateUserRequest,
    UpdateUserRequest,
    User,
    UserListPage,
    UserStatus,
)


class UsersResource:
    """CRUD over /users."""

    def __init__(self, transport: Transport) -> None:
        self._t = transport

    # ----- sync -----

    def get(self, user_id: str) -> User:
        body = self._t.request("GET", f"/users/{user_id}")
        return User.model_validate(body)

    def list(
        self,
        *,
        cursor: str | None = None,
        limit: int = 50,
        status: UserStatus | None = None,
        email: str | None = None,
        sort: str = "-created_at",
    ) -> UserListPage:
        params: dict[str, str | int] = {"limit": limit, "sort": sort}
        if cursor:
            params["cursor"] = cursor
        if status:
            params["filter.status"] = status.value
        if email:
            params["filter.email"] = email
        body = self._t.request("GET", "/users", params=params)
        return UserListPage.model_validate(body)

    def create(
        self,
        req: CreateUserRequest,
        *,
        idempotency_key: str | None = None,
    ) -> User:
        body = self._t.request(
            "POST",
            "/users",
            json=req.model_dump(mode="json", exclude_none=True),
            idempotency_key=idempotency_key,
        )
        return User.model_validate(body)

    def update(self, user_id: str, req: UpdateUserRequest) -> User:
        body = self._t.request(
            "PATCH",
            f"/users/{user_id}",
            json=req.model_dump(mode="json", exclude_unset=True),
        )
        return User.model_validate(body)

    def delete(self, user_id: str) -> None:
        self._t.request("DELETE", f"/users/{user_id}")

    # ----- async -----

    async def get_async(self, user_id: str) -> User:
        body = await self._t.request_async("GET", f"/users/{user_id}")
        return User.model_validate(body)

    async def list_async(
        self,
        *,
        cursor: str | None = None,
        limit: int = 50,
        status: UserStatus | None = None,
        email: str | None = None,
        sort: str = "-created_at",
    ) -> UserListPage:
        params: dict[str, str | int] = {"limit": limit, "sort": sort}
        if cursor:
            params["cursor"] = cursor
        if status:
            params["filter.status"] = status.value
        if email:
            params["filter.email"] = email
        body = await self._t.request_async("GET", "/users", params=params)
        return UserListPage.model_validate(body)

    async def create_async(
        self,
        req: CreateUserRequest,
        *,
        idempotency_key: str | None = None,
    ) -> User:
        body = await self._t.request_async(
            "POST",
            "/users",
            json=req.model_dump(mode="json", exclude_none=True),
            idempotency_key=idempotency_key,
        )
        return User.model_validate(body)

    async def update_async(self, user_id: str, req: UpdateUserRequest) -> User:
        body = await self._t.request_async(
            "PATCH",
            f"/users/{user_id}",
            json=req.model_dump(mode="json", exclude_unset=True),
        )
        return User.model_validate(body)

    async def delete_async(self, user_id: str) -> None:
        await self._t.request_async("DELETE", f"/users/{user_id}")
