"""Verify context propagation contract from CONVENTIONS.md §3."""

from __future__ import annotations

import pytest

from foundation_template._context import (
    current_context,
    current_context_or_none,
    tenant_context,
)


def test_current_context_raises_when_no_context():
    assert current_context_or_none() is None
    with pytest.raises(RuntimeError, match="No FoundationContext active"):
        current_context()


def test_tenant_context_pushes_and_pops():
    assert current_context_or_none() is None
    with tenant_context("tnt_01J5TEST0000000000000000A"):
        ctx = current_context()
        assert ctx.tenant_id == "tnt_01J5TEST0000000000000000A"
        assert ctx.request_id.startswith("req_")
    assert current_context_or_none() is None


def test_nested_contexts_replace_outer():
    with tenant_context("tnt_01J5OUTER0000000000000000"):
        assert current_context().tenant_id == "tnt_01J5OUTER0000000000000000"
        with tenant_context("tnt_01J5INNER0000000000000000"):
            assert current_context().tenant_id == "tnt_01J5INNER0000000000000000"
        # Inner pops, outer restored
        assert current_context().tenant_id == "tnt_01J5OUTER0000000000000000"
