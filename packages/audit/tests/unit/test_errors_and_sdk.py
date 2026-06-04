"""Unit tests for errors.py and sdk/__init__.py — pure Python, no network."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# errors.py
# ---------------------------------------------------------------------------

class TestErrorCodes:
    def test_error_codes_are_unique(self) -> None:
        from foundation_audit.errors import REGISTRY
        codes = [c.code for c in REGISTRY.codes]
        assert len(codes) == len(set(codes))

    def test_permission_denied_is_403(self) -> None:
        from foundation_audit.errors import PERMISSION_DENIED
        assert PERMISSION_DENIED.http_status == 403

    def test_clickhouse_unavailable_is_503(self) -> None:
        from foundation_audit.errors import CLICKHOUSE_UNAVAILABLE
        assert CLICKHOUSE_UNAVAILABLE.http_status == 503

    def test_validation_failed_is_422(self) -> None:
        from foundation_audit.errors import VALIDATION_FAILED
        assert VALIDATION_FAILED.http_status == 422

    def test_unexpected_is_500(self) -> None:
        from foundation_audit.errors import UNEXPECTED
        assert UNEXPECTED.http_status == 500

    def test_foundation_error_message(self) -> None:
        from foundation_audit.errors import PERMISSION_DENIED, FoundationError
        exc = FoundationError(PERMISSION_DENIED, detail="custom detail")
        assert "FOUNDATION.AUDIT.POLICY.PERMISSION_DENIED" in str(exc)
        assert exc.detail == "custom detail"

    def test_foundation_error_defaults(self) -> None:
        from foundation_audit.errors import UNEXPECTED, FoundationError
        exc = FoundationError(UNEXPECTED)
        assert exc.detail == UNEXPECTED.default_detail
        assert exc.extra == {}

    def test_all_codes_start_with_foundation_audit(self) -> None:
        from foundation_audit.errors import REGISTRY
        for c in REGISTRY.codes:
            assert c.code.startswith("FOUNDATION.AUDIT.")


# ---------------------------------------------------------------------------
# sdk/__init__.py
# ---------------------------------------------------------------------------

class TestSDKEmit:
    @pytest.mark.asyncio
    async def test_emit_returns_true_on_202(self) -> None:
        from foundation_audit.sdk import emit
        import foundation_audit.sdk as sdk_mod

        event = _make_sdk_event()
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 202
        mock_client.post = AsyncMock(return_value=mock_resp)

        with patch.object(sdk_mod, "_get_client", return_value=mock_client):
            result = await emit(event)
        assert result is True

    @pytest.mark.asyncio
    async def test_emit_returns_false_on_connection_error(self) -> None:
        from foundation_audit.sdk import emit
        import foundation_audit.sdk as sdk_mod
        import httpx

        event = _make_sdk_event()
        mock_client = MagicMock()
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))

        with patch.object(sdk_mod, "_get_client", return_value=mock_client):
            result = await emit(event)
        assert result is False

    @pytest.mark.asyncio
    async def test_emit_returns_false_on_non_202(self) -> None:
        from foundation_audit.sdk import emit
        import foundation_audit.sdk as sdk_mod

        event = _make_sdk_event()
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_client.post = AsyncMock(return_value=mock_resp)

        with patch.object(sdk_mod, "_get_client", return_value=mock_client):
            result = await emit(event)
        assert result is False

    @pytest.mark.asyncio
    async def test_emit_batch_returns_count(self) -> None:
        from foundation_audit.sdk import emit_batch
        import foundation_audit.sdk as sdk_mod

        events = [_make_sdk_event(), _make_sdk_event(event_id="evt_01J00000000000000000000002")]
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 202
        mock_client.post = AsyncMock(return_value=mock_resp)

        with patch.object(sdk_mod, "_get_client", return_value=mock_client):
            count = await emit_batch(events)
        assert count == 2

    @pytest.mark.asyncio
    async def test_emit_batch_empty_is_noop(self) -> None:
        from foundation_audit.sdk import emit_batch
        count = await emit_batch([])
        assert count == 0

    @pytest.mark.asyncio
    async def test_close_clears_client(self) -> None:
        import foundation_audit.sdk as sdk_mod
        mock_client = MagicMock()
        mock_client.aclose = AsyncMock()
        sdk_mod._client = mock_client
        from foundation_audit.sdk import close
        await close()
        assert sdk_mod._client is None
        mock_client.aclose.assert_called_once()


def _make_sdk_event(
    event_id: str = "evt_01J00000000000000000000001",
) -> "object":
    from foundation_audit.schemas.event import AuditEvent
    return AuditEvent(
        event_id=event_id,
        occurred_at=datetime.now(UTC),
        tenant_id="tnt_01J0000000000000000000TNT1",
        service="identity",
        event_type="test",
        actor_kind="USER",
    )
