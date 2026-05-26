"""LLM Gateway resource — probe endpoints, manage model routing."""

from __future__ import annotations

from typing import Any

from foundation_sdk._transport import Transport


class LLMGatewayResource:
    """Manage LLM provider endpoints and probe capabilities."""

    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def probe_endpoint(self, *, url: str, api_key: str,
                        provider_type: str = "openai_compatible") -> dict[str, Any]:
        return self._t.request("POST", "/api/llm-gateway/v1/probe",
                                json={"url": url, "api_key": api_key,
                                      "provider_type": provider_type})

    async def probe_endpoint_async(self, *, url: str, api_key: str,
                                    provider_type: str = "openai_compatible") -> dict[str, Any]:
        return await self._t.request_async("POST", "/api/llm-gateway/v1/probe",
                                            json={"url": url, "api_key": api_key,
                                                  "provider_type": provider_type})

    def list_providers(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/llm-gateway/v1/providers")

    def register_provider(self, *, name: str, api_base: str, api_key: str,
                           provider_type: str, models: list[str] | None = None) -> dict[str, Any]:
        return self._t.request("POST", "/api/llm-gateway/v1/providers",
                                json={"name": name, "api_base": api_base,
                                      "api_key": api_key, "provider_type": provider_type,
                                      "models": models or []})

    def get_model_pricing(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/llm-gateway/v1/pricing")

    def chat(self, *, model: str, messages: list[dict[str, str]],
              temperature: float = 0.7, max_tokens: int | None = None,
              stream: bool = False) -> dict[str, Any]:
        return self._t.request("POST", "/api/llm-gateway/v1/chat",
                                json={"model": model, "messages": messages,
                                      "temperature": temperature, "max_tokens": max_tokens,
                                      "stream": stream})
