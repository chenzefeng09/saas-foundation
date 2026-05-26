"""Main client — aggregates all resource groups."""

from __future__ import annotations

import logging
from types import TracebackType
from typing import Self

from pydantic_settings import BaseSettings, SettingsConfigDict

from foundation_sdk._transport import Transport
from foundation_sdk.resources.identity import IdentityResource
from foundation_sdk.resources.authz import AuthzResource
from foundation_sdk.resources.org import OrgResource
from foundation_sdk.resources.billing import BillingResource
from foundation_sdk.resources.audit import AuditResource
from foundation_sdk.resources.lifecycle import LifecycleResource
from foundation_sdk.resources.notification import NotificationResource
from foundation_sdk.resources.search import SearchResource
from foundation_sdk.resources.api_platform import ApiPlatformResource
from foundation_sdk.resources.llm_gateway import LLMGatewayResource
from foundation_sdk.resources.feature_flag import FeatureFlagResource
from foundation_sdk.resources.dlp import DLPResource
from foundation_sdk.resources.crypto import CryptoResource
from foundation_sdk.resources.compliance import ComplianceResource
from foundation_sdk.resources.pam import PAMResource
from foundation_sdk.resources.data_protection import DataProtectionResource

logger = logging.getLogger(__name__)


class FoundationClientSettings(BaseSettings):
    """Read from env: FOUNDATION_API_URL, FOUNDATION_API_TOKEN.

    All service-specific URLs are derived from the base API URL.
    """

    model_config = SettingsConfigDict(
        env_prefix="FOUNDATION_",
        env_file=".env",
        extra="ignore",
    )

    api_url: str = "http://localhost:8000"
    api_token: str = ""
    timeout: float = 30.0


class FoundationClient:
    """High-level client that aggregates all 16 Foundation service resource groups."""

    def __init__(
        self,
        api_url: str = "http://localhost:8000",
        api_token: str = "",
        *,
        timeout: float = 30.0,
    ) -> None:
        self._transport = Transport(
            base_url=api_url,
            api_token=api_token,
            timeout=timeout,
        )

        # --- Service resource groups ---
        self.identity = IdentityResource(self._transport)
        self.authz = AuthzResource(self._transport)
        self.org = OrgResource(self._transport)
        self.billing = BillingResource(self._transport)
        self.audit = AuditResource(self._transport)
        self.lifecycle = LifecycleResource(self._transport)
        self.notification = NotificationResource(self._transport)
        self.search = SearchResource(self._transport)
        self.api_platform = ApiPlatformResource(self._transport)
        self.llm_gateway = LLMGatewayResource(self._transport)
        self.feature_flag = FeatureFlagResource(self._transport)
        self.dlp = DLPResource(self._transport)
        self.crypto = CryptoResource(self._transport)
        self.compliance = ComplianceResource(self._transport)
        self.pam = PAMResource(self._transport)
        self.data_protection = DataProtectionResource(self._transport)

    @classmethod
    def from_env(cls) -> Self:
        """Construct from environment variables (FOUNDATION_API_URL, FOUNDATION_API_TOKEN)."""
        settings = FoundationClientSettings()
        if not settings.api_token:
            raise RuntimeError(
                "FOUNDATION_API_TOKEN is required. Set it in env or .env file."
            )
        return cls(
            api_url=settings.api_url,
            api_token=settings.api_token,
            timeout=settings.timeout,
        )

    # --- lifecycle ---

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
