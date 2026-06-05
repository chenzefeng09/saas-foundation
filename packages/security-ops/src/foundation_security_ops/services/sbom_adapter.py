"""SBOM generation adapter — Syft / cosign integration.

Real invocations require Syft and cosign to be present on the system PATH.
When the binary is absent (typical in unit tests / CI build agents without
the toolchain) the adapter raises SbomToolUnavailable; callers can catch this
and store a placeholder record instead.

Interface contract:
    generate_sbom(image_ref, fmt)  -> bytes       CycloneDX or SPDX JSON
    verify_attestation(image_ref)  -> bool
    diff_sbom(ref_a, ref_b)        -> dict
"""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from typing import Literal

SbomFormat = Literal["cyclonedx-json", "spdx-json"]


class SbomToolUnavailable(Exception):
    """Raised when Syft or cosign binary is not found on PATH."""


def generate_sbom(
    image_ref: str,
    *,
    fmt: SbomFormat = "cyclonedx-json",
    timeout: int = 120,
) -> bytes:
    """Invoke `syft <image_ref> -o <fmt>` and return the raw JSON bytes.

    Adapter note: this is a thin shell around the Syft CLI.  If Syft is not
    installed, SbomToolUnavailable is raised so the caller can store a
    placeholder record with an appropriate warning.
    """
    try:
        result = subprocess.run(  # noqa: S603
            ["syft", image_ref, "-o", fmt, "--quiet"],  # noqa: S607
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise SbomToolUnavailable("syft not found on PATH") from exc

    if result.returncode != 0:
        raise RuntimeError(
            f"syft exited {result.returncode}: {result.stderr.decode(errors='replace')}"
        )
    return result.stdout


def verify_attestation(image_ref: str, *, timeout: int = 60) -> bool:
    """Invoke `cosign verify-attestation` and return True on success.

    Adapter note: requires cosign on PATH and network access to Sigstore TUF.
    Returns False (rather than raising) for any non-zero exit so callers can
    record the failure without crashing the service.
    """
    try:
        result = subprocess.run(  # noqa: S603
            [  # noqa: S607
                "cosign",
                "verify-attestation",
                "--type", "cyclonedx",
                image_ref,
            ],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def diff_sbom(sbom_a: bytes, sbom_b: bytes) -> dict:
    """Naive component-level diff between two CycloneDX JSON SBOMs.

    Returns {"added": [...], "removed": [...], "count_a": int, "count_b": int}.
    This is a pure-Python fallback; a full Grype-based diff would need network
    access and is deferred to the adapter.
    """

    def _components(raw: bytes) -> dict[str, str]:
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        comps = doc.get("components", [])
        return {
            f"{c.get('name', '')}@{c.get('version', '')}": c.get("purl", "")
            for c in comps
        }

    comps_a = _components(sbom_a)
    comps_b = _components(sbom_b)
    set_a = set(comps_a)
    set_b = set(comps_b)
    return {
        "added": sorted(set_b - set_a),
        "removed": sorted(set_a - set_b),
        "count_a": len(comps_a),
        "count_b": len(comps_b),
        "diffed_at": datetime.now(UTC).isoformat(),
    }


def stub_sbom(image_ref: str, fmt: SbomFormat = "cyclonedx-json") -> bytes:
    """Return a minimal stub SBOM for use when Syft is unavailable."""
    stub = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "component": {"type": "container", "name": image_ref},
            "tools": [{"name": "foundation-security-ops-stub", "version": "1.0.0a1"}],
        },
        "components": [],
        "_stub": True,
        "_reason": "syft not available; placeholder SBOM",
    }
    return json.dumps(stub, indent=2).encode()
