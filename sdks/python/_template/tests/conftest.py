"""Pytest fixtures for SDK template tests."""

from __future__ import annotations

import pytest

from foundation_template._context import tenant_context
from foundation_template.client import TemplateClient


@pytest.fixture
def tenant_id() -> str:
    return "tnt_01J5XXXXXXXXXXXXXXXXXXXXXX"


@pytest.fixture
def with_tenant(tenant_id: str):
    with tenant_context(tenant_id, user_id="usr_01J5USR000000000000000000"):
        yield


@pytest.fixture
def client() -> TemplateClient:
    return TemplateClient(
        api_url="http://test.example.com/api/template/v1",
        api_token="test-token",
    )
