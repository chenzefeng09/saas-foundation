from __future__ import annotations

import pytest
from pydantic import ValidationError

from foundation_dlp.config import Settings


def test_unclassified_default_is_l3() -> None:
    assert Settings().unclassified_sensitivity == "L3"


@pytest.mark.parametrize("unsafe_default", ["L1", "L2"])
def test_unclassified_default_cannot_be_weakened(unsafe_default: str) -> None:
    with pytest.raises(ValidationError):
        Settings(unclassified_sensitivity=unsafe_default)  # type: ignore[arg-type]


@pytest.mark.parametrize("strict_default", ["L3", "L4", "L5"])
def test_unclassified_default_can_be_tightened(strict_default: str) -> None:
    assert Settings(  # type: ignore[arg-type]
        unclassified_sensitivity=strict_default
    ).unclassified_sensitivity == strict_default
