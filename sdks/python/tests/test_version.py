"""``pyproject.toml``, ``foundation_sdk.__version__`` and the User-Agent carry one version."""

from __future__ import annotations

import tomllib
from pathlib import Path

import respx
from foundation_sdk import FoundationClient, __version__, tenant_context

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"
BASE_URL = "http://sdk.test"


def test_the_package_reports_the_declared_version() -> None:
    with PYPROJECT.open("rb") as f:
        declared = tomllib.load(f)["tool"]["poetry"]["version"]
    assert __version__ == declared


def test_requests_send_the_version_in_the_user_agent() -> None:
    with respx.mock(base_url=BASE_URL) as router:
        route = router.route().respond(200, json={})
        with tenant_context("tnt_01J9Z8Y7X6W5V4T3S2R1Q0P9N8"):
            FoundationClient(BASE_URL, "tok").identity.get_user("usr_01J9Z8Y7X6W5V4T3S2R1Q0P9N8")

    assert route.calls.last.request.headers["User-Agent"] == f"foundation-sdk-python/{__version__}"
