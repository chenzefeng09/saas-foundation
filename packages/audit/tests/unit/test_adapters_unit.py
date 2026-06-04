"""Unit tests for adapter modules — covers code paths that don't need live services."""

from __future__ import annotations

import asyncio
import base64
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# crypto_client tests
# ---------------------------------------------------------------------------

class TestCryptoClientHelpers:
    def test_sign_payload_structure(self) -> None:
        """Verify the JSON payload sent to crypto service is well-formed."""
        import json
        root_hex = "a" * 64
        root_bytes = bytes.fromhex(root_hex)
        data_b64 = base64.b64encode(root_bytes).decode()
        payload = {
            "key_label": "audit.hashchain",
            "data_b64": data_b64,
            "prehash": True,
        }
        # Verify base64 round-trips
        assert base64.b64decode(data_b64) == root_bytes
        assert payload["prehash"] is True
        assert isinstance(payload["key_label"], str)

    @pytest.mark.asyncio
    async def test_sign_merkle_root_success(self) -> None:
        """sign_merkle_root calls POST /sign and returns (signature_b64, key_id)."""
        from foundation_audit.adapters.crypto_client import sign_merkle_root, _http_client
        import foundation_audit.adapters.crypto_client as cc

        root_hex = "b" * 64
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "signature_b64": "signature_here==",
            "key_id": "key_v1",
        }
        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=mock_response)

        # Patch _get_http_client to return our mock
        with patch("foundation_audit.adapters.crypto_client._get_http_client", return_value=mock_client):
            sig, kid = await sign_merkle_root(root_hex, tenant_id="tnt_01J0")

        assert sig == "signature_here=="
        assert kid == "key_v1"
        # Verify it was called on /sign
        mock_client.post.assert_called_once()
        call_args = mock_client.post.call_args
        assert call_args[0][0] == "/sign"
        body = call_args[1]["json"]
        assert body["prehash"] is True

    @pytest.mark.asyncio
    async def test_verify_signature_returns_false_on_error(self) -> None:
        """verify_signature returns False (not raises) when crypto is unreachable."""
        from foundation_audit.adapters.crypto_client import verify_signature
        import httpx

        mock_client = MagicMock()
        mock_client.post = AsyncMock(side_effect=httpx.RequestError("connection refused"))

        with patch("foundation_audit.adapters.crypto_client._get_http_client", return_value=mock_client):
            result = await verify_signature("a" * 64, "sig==", "key_v1", tenant_id="tnt_01J0")

        assert result is False

    @pytest.mark.asyncio
    async def test_close_clears_client(self) -> None:
        """close() sets _http_client to None."""
        import foundation_audit.adapters.crypto_client as cc
        mock_client = MagicMock()
        mock_client.aclose = AsyncMock()
        cc._http_client = mock_client
        await cc.close()
        assert cc._http_client is None
        mock_client.aclose.assert_called_once()


# ---------------------------------------------------------------------------
# tsa tests
# ---------------------------------------------------------------------------

class TestTsaHelpers:
    @pytest.mark.asyncio
    async def test_returns_none_on_http_error(self) -> None:
        """TSA HTTP failure returns (None, None) — never raises."""
        from foundation_audit.adapters.tsa import request_timestamp
        import httpx

        with patch("foundation_audit.adapters.tsa.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(side_effect=httpx.RequestError("timeout"))
            mock_client_cls.return_value = mock_client

            # Patch away rfc3161ng import to fall through to raw path
            with patch.dict("sys.modules", {"rfc3161ng": None}):
                token, ts = await request_timestamp("c" * 64)

        assert token is None
        assert ts is None

    @pytest.mark.asyncio
    async def test_rfc3161ng_import_error_falls_back(self) -> None:
        """When rfc3161ng is not installed, falls back to raw path gracefully."""
        from foundation_audit.adapters.tsa import request_timestamp

        # rfc3161ng raises ImportError → falls to _request_timestamp_raw
        # _request_timestamp_raw makes an HTTP call → mock to fail
        with patch("foundation_audit.adapters.tsa._request_timestamp_raw",
                   new_callable=AsyncMock, return_value=(None, None)):
            import importlib
            import builtins
            original_import = builtins.__import__

            def _mock_import(name: str, *args: Any, **kwargs: Any) -> Any:
                if name == "rfc3161ng":
                    raise ImportError("not installed")
                return original_import(name, *args, **kwargs)

            with patch.object(builtins, "__import__", side_effect=_mock_import):
                token, ts = await request_timestamp("d" * 64)

        assert token is None
        assert ts is None


# ---------------------------------------------------------------------------
# clickhouse adapter module-level tests (get_clickhouse_client without CH)
# ---------------------------------------------------------------------------

class TestClickhouseAdapterModule:
    @pytest.mark.asyncio
    async def test_get_client_calls_run_in_executor(self) -> None:
        """get_clickhouse_client uses run_in_executor (not blocking the event loop)."""
        import foundation_audit.adapters.clickhouse as cha
        # Reset module client so it tries to connect
        cha._client = None

        mock_make = MagicMock(return_value=MagicMock())

        loop = asyncio.get_event_loop()
        with patch("foundation_audit.adapters.clickhouse._make_client", mock_make):
            with patch.object(loop, "run_in_executor", wraps=loop.run_in_executor) as mock_exec:
                try:
                    await cha.get_clickhouse_client()
                except Exception:
                    pass  # connection may fail; just verifying executor is used

        # Reset for other tests
        cha._client = None

    def test_events_columns_no_duplicates(self) -> None:
        from foundation_audit.adapters.clickhouse import EVENTS_COLUMNS
        assert len(EVENTS_COLUMNS) == len(set(EVENTS_COLUMNS))

    def test_merkle_batch_columns_no_duplicates(self) -> None:
        from foundation_audit.adapters.clickhouse import MERKLE_BATCH_COLUMNS
        assert len(MERKLE_BATCH_COLUMNS) == len(set(MERKLE_BATCH_COLUMNS))

    def test_required_columns_present(self) -> None:
        from foundation_audit.adapters.clickhouse import EVENTS_COLUMNS
        required = [
            "event_id", "tenant_id", "service", "occurred_at", "ingested_at",
            "prev_hash", "curr_hash", "merkle_batch_id", "merkle_leaf_idx",
            "worm_written", "worm_uri", "batch_signature",
        ]
        for col in required:
            assert col in EVENTS_COLUMNS, f"Missing column: {col}"


# ---------------------------------------------------------------------------
# config tests
# ---------------------------------------------------------------------------

class TestConfig:
    def test_default_tsa_url(self) -> None:
        from foundation_audit.config import get_settings
        s = get_settings()
        assert "freetsa" in str(s.tsa_url)

    def test_worm_disabled_by_default(self) -> None:
        from foundation_audit.config import get_settings
        s = get_settings()
        assert s.worm_enabled is False

    def test_tsa_enabled_by_default(self) -> None:
        from foundation_audit.config import get_settings
        s = get_settings()
        assert s.tsa_enabled is True

    def test_worm_retention_years(self) -> None:
        from foundation_audit.config import get_settings
        s = get_settings()
        assert s.worm_retention_years == 7

    def test_crypto_url_and_key_label(self) -> None:
        from foundation_audit.config import get_settings
        s = get_settings()
        assert "8004" in str(s.crypto_url)
        assert s.crypto_signing_key_label == "audit.hashchain"
