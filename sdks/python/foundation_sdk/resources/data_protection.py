"""Data Protection resource — masking engine, data destruction, cross-border transfer."""

from __future__ import annotations

from typing import Any

from foundation_sdk._transport import Transport


class DataProtectionResource:
    """Data protection: masking/anonymization, data destruction, cross-border controls."""

    def __init__(self, transport: Transport) -> None:
        self._t = transport

    # --- Masking ---

    def mask(self, *, data: dict[str, Any], rules: list[dict[str, str]]) -> dict[str, Any]:
        return self._t.request("POST", "/api/data-protection/v1/mask",
                                json={"data": data, "rules": rules})

    def mask_field(self, *, field_name: str, value: str,
                    mask_type: str = "default") -> dict[str, Any]:
        return self._t.request("POST", "/api/data-protection/v1/mask-field",
                                json={"field_name": field_name, "value": value,
                                      "mask_type": mask_type})

    def get_masking_rules(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/data-protection/v1/masking-rules")

    # --- Data Destruction ---

    def request_destruction(self, *, resource_ids: list[str],
                             method: str = "crypto_shred") -> dict[str, Any]:
        return self._t.request("POST", "/api/data-protection/v1/destruction",
                                json={"resource_ids": resource_ids, "method": method})

    def get_destruction_status(self, request_id: str) -> dict[str, Any]:
        return self._t.request("GET",
            f"/api/data-protection/v1/destruction/{request_id}")

    # --- Cross-Border ---

    def check_cross_border(self, *, destination_country: str,
                            data_categories: list[str]) -> dict[str, Any]:
        return self._t.request("POST", "/api/data-protection/v1/cross-border/check",
                                json={"destination_country": destination_country,
                                      "data_categories": data_categories})

    def get_data_residency(self) -> dict[str, Any]:
        return self._t.request("GET", "/api/data-protection/v1/data-residency")
