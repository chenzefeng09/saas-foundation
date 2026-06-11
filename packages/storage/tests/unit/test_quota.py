"""Unit tests for foundation_storage.quota."""

from __future__ import annotations

import sys
import types
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from foundation_storage.errors import QuotaExceededError
from foundation_storage.keys import BucketPurpose
from foundation_storage.quota import (
    NoopQuotaChecker,
    PostgresQuotaChecker,
    QuotaChecker,
)


class TestNoopQuotaChecker:
    @pytest.mark.asyncio
    async def test_check_before_upload_is_noop(self) -> None:
        q = NoopQuotaChecker()
        result = await q.check_before_upload("tnt_01", BucketPurpose.WORKSPACE, 1024)
        assert result is None

    @pytest.mark.asyncio
    async def test_increment_used_is_noop(self) -> None:
        q = NoopQuotaChecker()
        result = await q.increment_used("tnt_01", BucketPurpose.WORKSPACE, 1024)
        assert result is None

    def test_satisfies_protocol(self) -> None:
        q: QuotaChecker = NoopQuotaChecker()
        assert isinstance(q, QuotaChecker)


# ---------------------------------------------------------------------------
# PostgresQuotaChecker — sqlalchemy is mocked at the import boundary so we can
# assert on the SQL text & params without standing up a real engine.
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_sqlalchemy(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Install a fake ``sqlalchemy`` module exposing ``text``."""
    sqlalchemy_mod = types.ModuleType("sqlalchemy")

    def _text(sql: str) -> dict[str, Any]:
        return {"__text__": sql}

    sqlalchemy_mod.text = _text  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "sqlalchemy", sqlalchemy_mod)
    return sqlalchemy_mod  # type: ignore[return-value]


def _session_factory(session: MagicMock):  # type: ignore[no-untyped-def]
    @asynccontextmanager
    async def factory():  # type: ignore[no-untyped-def]
        yield session

    return factory


class TestPostgresQuotaCheckBeforeUpload:
    @pytest.mark.asyncio
    async def test_under_limit_passes(self, fake_sqlalchemy: MagicMock) -> None:
        session = MagicMock()
        result = MagicMock()
        result.first.return_value = (1_000, 100)  # limit, used
        session.execute = AsyncMock(return_value=result)

        q = PostgresQuotaChecker(_session_factory(session))
        # 100 + 500 = 600 < 1000 → OK
        await q.check_before_upload("tnt_01", BucketPurpose.WORKSPACE, 500)

        session.execute.assert_awaited_once()
        args, _ = session.execute.call_args
        assert args[0]["__text__"].startswith("SELECT limit_bytes, used_bytes")
        assert args[1] == {"tenant_id": "tnt_01", "bucket_purpose": "workspace"}

    @pytest.mark.asyncio
    async def test_over_limit_raises(self, fake_sqlalchemy: MagicMock) -> None:
        session = MagicMock()
        result = MagicMock()
        result.first.return_value = (1_000, 800)
        session.execute = AsyncMock(return_value=result)

        q = PostgresQuotaChecker(_session_factory(session))
        with pytest.raises(QuotaExceededError) as exc:
            # 800 + 300 = 1100 > 1000 → exceeded
            await q.check_before_upload("tnt_01", BucketPurpose.WORKSPACE, 300)
        assert exc.value.extra["limit_bytes"] == "1000"
        assert exc.value.extra["used_bytes"] == "800"
        assert exc.value.extra["tenant_id"] == "tnt_01"

    @pytest.mark.asyncio
    async def test_at_limit_passes(self, fake_sqlalchemy: MagicMock) -> None:
        session = MagicMock()
        result = MagicMock()
        result.first.return_value = (1_000, 500)
        session.execute = AsyncMock(return_value=result)

        q = PostgresQuotaChecker(_session_factory(session))
        # 500 + 500 = 1000 == 1000 → OK (boundary)
        await q.check_before_upload("tnt_01", BucketPurpose.WORKSPACE, 500)

    @pytest.mark.asyncio
    async def test_missing_row_passes(self, fake_sqlalchemy: MagicMock) -> None:
        """No quota row = unmetered tenant; warn but do not block."""
        session = MagicMock()
        result = MagicMock()
        result.first.return_value = None
        session.execute = AsyncMock(return_value=result)

        q = PostgresQuotaChecker(_session_factory(session))
        await q.check_before_upload("tnt_01", BucketPurpose.WORKSPACE, 999_999)


class TestPostgresQuotaIncrementUsed:
    @pytest.mark.asyncio
    async def test_positive_delta(self, fake_sqlalchemy: MagicMock) -> None:
        session = MagicMock()
        result = MagicMock()
        result.rowcount = 1
        session.execute = AsyncMock(return_value=result)
        session.commit = AsyncMock()

        q = PostgresQuotaChecker(_session_factory(session))
        await q.increment_used("tnt_01", BucketPurpose.WORKSPACE, 250)

        args, _ = session.execute.call_args
        assert args[0]["__text__"].startswith("UPDATE lifecycle.tenant_storage_quota")
        assert args[1] == {
            "tenant_id": "tnt_01",
            "bucket_purpose": "workspace",
            "delta": 250,
        }
        session.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_negative_delta_for_delete(self, fake_sqlalchemy: MagicMock) -> None:
        session = MagicMock()
        result = MagicMock()
        result.rowcount = 1
        session.execute = AsyncMock(return_value=result)
        session.commit = AsyncMock()

        q = PostgresQuotaChecker(_session_factory(session))
        await q.increment_used("tnt_01", BucketPurpose.WORKSPACE, -250)

        args, _ = session.execute.call_args
        assert args[1]["delta"] == -250

    @pytest.mark.asyncio
    async def test_zero_rows_does_not_raise(
        self, fake_sqlalchemy: MagicMock
    ) -> None:
        """If the quota row was concurrently deleted, log but do not raise —
        the reconcile job will recreate state."""
        session = MagicMock()
        result = MagicMock()
        result.rowcount = 0
        session.execute = AsyncMock(return_value=result)
        session.commit = AsyncMock()

        q = PostgresQuotaChecker(_session_factory(session))
        await q.increment_used("tnt_01", BucketPurpose.WORKSPACE, 100)

    def test_satisfies_protocol(self) -> None:
        q: QuotaChecker = PostgresQuotaChecker(_session_factory(MagicMock()))
        assert isinstance(q, QuotaChecker)
