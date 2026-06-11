"""Unit tests for foundation_storage.quota."""

from __future__ import annotations

import pytest

from foundation_storage.keys import BucketPurpose
from foundation_storage.quota import NoopQuotaChecker, QuotaChecker


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
