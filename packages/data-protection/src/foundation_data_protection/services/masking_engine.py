"""Data masking engine (data-protection-v1 §2).

Supports:
  - mask: replace with pattern (138****1234)
  - truncate: keep first N chars
  - hash: deterministic SHA-256(salt + value)
  - pseudonymize: HMAC-SHA256(per-tenant-key, value) — consistent across calls
  - suppress: return null
  - tokenize: replace with generated token (reversible via token vault)
  - noise: add random noise to numeric values
"""

from __future__ import annotations

import hashlib
import hmac
import random
import re
from typing import Any


class MaskingEngine:
    """Stateless masking engine. Per-tenant keys come from crypto-service."""

    def __init__(self, tenant_key: bytes | None = None):
        self._tenant_key = tenant_key or b"dev-static-key-32bytes!!"  # 32 bytes for HMAC

    # ------------------------------------------------------------------ Public API

    def mask(self, value: str | None, method: str, **params: Any) -> str | None:
        """Apply a masking method to a single value.

        Methods: mask, truncate, hash, pseudonymize, suppress, tokenize, noise.
        """
        if value is None:
            return None
        handler = getattr(self, f"_mask_{method}", None)
        if handler is None:
            raise ValueError(f"Unknown masking method: {method}")
        return handler(value, **params)

    def mask_record(self, record: dict[str, Any], rules: dict[str, dict[str, Any]]) -> dict[str, Any]:
        """Apply multiple masking rules to a record (dict of column → value)."""
        result = dict(record)
        for column, rule in rules.items():
            if column in result and result[column] is not None:
                method = rule.get("method", "suppress")
                params = {k: v for k, v in rule.items() if k != "method"}
                result[column] = self.mask(str(result[column]), method, **params)
        return result

    # ------------------------------------------------------------------ Method implementations

    def _mask_mask(self, value: str, pattern: str = "***", keep_start: int = 0,
                   keep_end: int = 0) -> str:
        """Replace middle with pattern. e.g. keep_start=3, keep_end=4: 138****1234"""
        if keep_start + keep_end >= len(value):
            return value
        return value[:keep_start] + pattern + value[-keep_end:] if keep_end else value[:keep_start] + pattern

    def _mask_truncate(self, value: str, keep: int = 6) -> str:
        """Keep first N characters."""
        return value[:keep]

    def _mask_hash(self, value: str, purpose: str = "default") -> str:
        """Deterministic SHA-256(salt + value). Same input → same output."""
        return hashlib.sha256(self._tenant_key + purpose.encode() + value.encode()).hexdigest()[:32]

    def _mask_pseudonymize(self, value: str, purpose: str = "default") -> str:
        """Consistent pseudonym via HMAC-SHA256. Same value + same purpose → same result."""
        h = hmac.new(self._tenant_key, purpose.encode() + value.encode(), hashlib.sha256)
        return h.hexdigest()[:16]

    def _mask_suppress(self, value: str, **_kw: Any) -> str | None:
        return None

    def _mask_tokenize(self, value: str, prefix: str = "tok_", **_kw: Any) -> str:
        """Replace with a generated token (reversible via token vault in v1.1)."""
        h = hashlib.sha256(self._tenant_key + value.encode()).hexdigest()
        return f"{prefix}{h[:12]}"

    def _mask_noise(self, value: str, pct: float = 5.0, **_kw: Any) -> str:
        """Add ±pct% noise to numeric values."""
        try:
            n = float(value)
            factor = 1.0 + random.uniform(-pct / 100, pct / 100)
            return str(round(n * factor, 2))
        except ValueError:
            return value

    def _mask_passthrough(self, value: str, **_kw: Any) -> str:
        return value


# ------------------------------------------------------------------ Pre-built pattern presets

PHONE_PATTERN = {"method": "mask", "keep_start": 3, "keep_end": 4, "pattern": "****"}
ID_CARD_PATTERN = {"method": "mask", "keep_start": 6, "keep_end": 4, "pattern": "********"}
EMAIL_PATTERN = {"method": "mask", "keep_start": 2, "pattern": "***"}
BANK_CARD_PATTERN = {"method": "mask", "keep_start": 4, "keep_end": 4, "pattern": "****"}
NAME_PATTERN = {"method": "pseudonymize", "purpose": "person_name"}

PRESETS: dict[str, dict[str, Any]] = {
    "phone": PHONE_PATTERN,
    "id_card": ID_CARD_PATTERN,
    "email": EMAIL_PATTERN,
    "bank_card": BANK_CARD_PATTERN,
    "person_name": NAME_PATTERN,
}
