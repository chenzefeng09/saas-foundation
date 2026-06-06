"""Conformance suite shared fixtures.

Purpose
-------
This conftest provides the minimal fixtures needed to run the conformance
suite against a *mocked* foundation transport layer.  Checks that require
a real running stack are skipped when the relevant environment variables
are absent.

Running (no stack required — mock-based checks):
    cd /path/to/saas-foundation
    pytest tests/conformance/ -v

Running (with full stack — all checks active):
    docker compose -f deploy/docker-compose/dev.yml \\
                   -f deploy/docker-compose/integration.yml up -d
    FOUNDATION_API_URL=http://localhost:8000 \\
    FOUNDATION_API_TOKEN=dev-token \\
    pytest tests/conformance/ -v -m "conformance"

Shared constants (TENANT_A / TENANT_B) are defined in _constants.py in the
same directory and imported directly from there by test modules.
"""

from __future__ import annotations

import os

import pytest

# ---------------------------------------------------------------------------
# Markers
# ---------------------------------------------------------------------------

def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "conformance: marks all conformance self-check tests",
    )
    config.addinivalue_line(
        "markers",
        "e2e: marks full end-to-end tests that require a running foundation stack",
    )
    config.addinivalue_line(
        "markers",
        "needs_stack: skip when FOUNDATION_API_URL env var is not set",
    )


# ---------------------------------------------------------------------------
# Skip helper
# ---------------------------------------------------------------------------

@pytest.fixture
def foundation_url() -> str:
    """Return the base URL of a running foundation stack, or skip the test."""
    url = os.environ.get("FOUNDATION_API_URL")
    if not url:
        pytest.skip(
            "Requires a running foundation stack — "
            "set FOUNDATION_API_URL (and FOUNDATION_API_TOKEN) and re-run."
        )
    return url


@pytest.fixture
def foundation_token() -> str:
    return os.environ.get("FOUNDATION_API_TOKEN", "dev-token")
