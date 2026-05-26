"""Main client entrypoint.

Usage pattern for service SDKs:
    from foundation_template.client import TemplateClient
    client = TemplateClient.from_env()
    with tenant_context("tnt_01J..."):
        result = client.users.get("usr_01J...")
"""

from __future__ import annotations

from types import TracebackType
from typing import Self

from pydantic_settings import BaseSettings, SettingsConfigDict

from foundation_template._transport import Transport
from foundation_template.resources.users import UsersResource


class TemplateClientSettings(BaseSettings):
    """Read from env: FOUNDATION_TEMPLATE_API_URL, FOUNDATION_TEMPLATE_API_TOKEN."""

    model_config = SettingsConfigDict(
        env_prefix="FOUNDATION_TEMPLATE_",
        env_file=".env",
        extra="ignore",
    )

    api_url: str = "http://localhost:8001/api/template/v1"
    api_token: str = ""
    timeout: float = 30.0


class TemplateClient:
    """High-level client. One instance per service.

    Thread-safe for sync use; for async, prefer one instance per event loop.
    """

    def __init__(
        self,
        api_url: str,
        api_token: str,
        *,
        timeout: float = 30.0,
    ) -> None:
        self._transport = Transport(
            base_url=api_url,
            api_token=api_token,
            timeout=timeout,
        )
        # Resource groups
        self.users = UsersResource(self._transport)
        # Add more here: self.sessions = SessionsResource(self._transport), etc.

        self._verify_version()

    @classmethod
    def from_env(cls) -> Self:
        """Construct from environment variables."""
        settings = TemplateClientSettings()
        if not settings.api_token:
            raise RuntimeError(
                "FOUNDATION_TEMPLATE_API_TOKEN is required. "
                "Set it in env or .env file."
            )
        return cls(
            api_url=settings.api_url,
            api_token=settings.api_token,
            timeout=settings.timeout,
        )

    def _verify_version(self) -> None:
        """Fail fast if server major version doesn't match SDK.

        Per CONVENTIONS.md §5.3. Calls /healthz which returns {service, version}.
        """
        # TODO: implement once /healthz contract is finalized
        # info = self._transport.request("GET", "/healthz")
        # ... compare info["version"] to __version__
        return

    # ------- lifecycle -------

    def close(self) -> None:
        self._transport.close()

    async def aclose(self) -> None:
        await self._transport.aclose()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()
