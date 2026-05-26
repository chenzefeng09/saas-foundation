"""API Platform resource — API keys, OAuth apps, webhooks."""

from __future__ import annotations

from typing import Any

from foundation_sdk._transport import Transport


class ApiPlatformResource:
    """Manage API keys, OAuth applications, and webhook subscriptions."""

    def __init__(self, transport: Transport) -> None:
        self._t = transport

    # --- API Keys ---

    def create_api_key(self, *, name: str, scopes: list[str],
                        ip_whitelist: list[str] | None = None,
                        rate_limit_rpm: int = 60,
                        expires_in_days: int | None = None) -> dict[str, Any]:
        return self._t.request("POST", "/api/api-platform/v1/keys",
                                json={"name": name, "scopes": scopes,
                                      "ip_whitelist": ip_whitelist,
                                      "rate_limit_rpm": rate_limit_rpm,
                                      "expires_in_days": expires_in_days})

    def list_api_keys(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/api-platform/v1/keys")

    def revoke_api_key(self, key_id: str) -> dict[str, Any]:
        return self._t.request("POST", f"/api/api-platform/v1/keys/{key_id}/revoke")

    def validate_api_key(self, *, key_hash: str, required_scope: str | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"key_hash": key_hash}
        if required_scope:
            body["required_scope"] = required_scope
        return self._t.request("POST", "/api/api-platform/v1/keys/validate", json=body)

    # --- OAuth Apps ---

    def register_oauth_app(self, *, name: str, redirect_uris: list[str],
                            scopes: list[str]) -> dict[str, Any]:
        return self._t.request("POST", "/api/api-platform/v1/oauth-apps",
                                json={"name": name, "redirect_uris": redirect_uris,
                                      "scopes": scopes})

    def list_oauth_apps(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/api-platform/v1/oauth-apps")

    # --- Webhooks ---

    def subscribe_webhook(self, *, url: str, event_types: list[str],
                           secret: str | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"url": url, "event_types": event_types}
        if secret:
            body["secret"] = secret
        return self._t.request("POST", "/api/api-platform/v1/webhooks", json=body)

    def list_webhooks(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/api-platform/v1/webhooks")

    def delete_webhook(self, webhook_id: str) -> dict[str, Any]:
        return self._t.request("DELETE", f"/api/api-platform/v1/webhooks/{webhook_id}")
