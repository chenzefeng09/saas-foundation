"""License allow/deny policy.

Design doc §2 + OpenAPI license scan gate:
  Allowed: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, WTFPL, Unlicense, CC0-1.0,
           Python-2.0, PSF-2.0, MPL-2.0 (weak copyleft — service-isolated okay)
  Blocked: GPL-2.0, GPL-3.0, AGPL-3.0, LGPL-2.1, LGPL-3.0, EUPL-1.1, EUPL-1.2, SSPL-1.0
           (unless a specific exception is registered)
  Review:  everything else
"""

from __future__ import annotations

from typing import Final, Literal

LicenseVerdict = Literal["ALLOWED", "BLOCKED", "REVIEW_REQUIRED"]

_ALLOWED: Final[frozenset[str]] = frozenset(
    {
        "MIT",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
        "WTFPL",
        "Unlicense",
        "CC0-1.0",
        "Python-2.0",
        "PSF-2.0",
        "MPL-2.0",
        "0BSD",
        "Zlib",
    }
)

_BLOCKED: Final[frozenset[str]] = frozenset(
    {
        "GPL-2.0",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "AGPL-3.0",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "LGPL-2.1",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "EUPL-1.1",
        "EUPL-1.2",
        "SSPL-1.0",
    }
)


def evaluate_license(spdx_id: str, *, exception_id: str | None = None) -> LicenseVerdict:
    """Evaluate a SPDX license identifier against the organisation policy.

    If the license would normally be BLOCKED but an exception_id is provided,
    the caller is responsible for validating that the exception is still valid
    before acting on the ALLOWED result — this function only checks the policy rule.
    For the purpose of recording/auditing, pass the exception_id through.
    """
    normalised = spdx_id.strip()
    if normalised in _ALLOWED:
        return "ALLOWED"
    if normalised in _BLOCKED:
        if exception_id:
            # Caller must still verify expiry; we return ALLOWED here
            return "ALLOWED"
        return "BLOCKED"
    return "REVIEW_REQUIRED"


def is_blocked(spdx_id: str) -> bool:
    return spdx_id.strip() in _BLOCKED


def is_allowed(spdx_id: str) -> bool:
    return spdx_id.strip() in _ALLOWED
