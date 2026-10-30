"""The SDKs' golden requests for crypto reach a route that accepts them, as documented.

``contracts/sdk/crypto.json`` pins what each SDK method sends; the SDK suites
check that side. See ``tools/contracts/sdk_requests.py`` for what is checked here.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi import FastAPI

from foundation_crypto.main import create_app

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "tools" / "contracts"))
import sdk_requests

SERVICE = "crypto"
CASES = sdk_requests.load_cases(SERVICE)


@pytest.fixture(scope="module")
def app() -> FastAPI:
    return create_app()


@pytest.mark.parametrize("case", CASES, ids=str)
def test_a_route_accepts_the_sdk_request(app: FastAPI, case: sdk_requests.Case) -> None:
    assert sdk_requests.app_problems(app, case) == []


@pytest.mark.parametrize("case", CASES, ids=str)
def test_the_contract_documents_the_sdk_request(app: FastAPI, case: sdk_requests.Case) -> None:
    assert sdk_requests.contract_problems(SERVICE, app, case) == []
