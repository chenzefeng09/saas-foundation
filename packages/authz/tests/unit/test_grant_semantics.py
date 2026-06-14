"""Grant-semantics unit tests: ``covers`` and ``is_grantable``.

These are the anti-escalation primitives.  ``covers`` must stay dot-segment
consistent with ``_wildcard_match`` (the live decision path) so that "can I
grant X?" never diverges from "does holding X satisfy a check for X?".
"""

from __future__ import annotations

import pytest

from foundation_authz.services.check_service import (
    _wildcard_match,
    covers,
    is_grantable,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# covers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("holder", "requested", "expected"),
    [
        # "*" covers everything (including other wildcards and "*" itself).
        ("*", "anything.at.all", True),
        ("*", "session.*", True),
        ("*", "*", True),
        # exact equality
        ("session.read", "session.read", True),
        ("session.*", "session.*", True),
        # prefix wildcard covers concrete leaf
        ("session.*", "session.read", True),
        ("session.*", "session.message.read", True),
        ("session.message.*", "session.message.read", True),
        # prefix wildcard covers a narrower wildcard (req_core strip)
        ("session.*", "session.message.*", True),
        ("session.message.*", "session.message.attachment.*", True),
        # directionality: a narrow holder does NOT cover a broader request
        ("session.message.*", "session.*", False),
        ("session.message.*", "session.read", False),
        ("session.read", "session.*", False),
        # unrelated trees
        ("session.*", "run.read", False),
        ("run.*", "session.read", False),
        # concrete holder cannot cover anything but itself
        ("session.read", "session.create", False),
        # bare single-segment token is NOT a leaf of any dotted namespace:
        # holding ``session.*`` must NOT cover the standalone token ``session``
        # (it is not a child of the ``session.`` namespace).  See fix #2.
        ("session.*", "session", False),
        ("run.*", "run", False),
        # ``*`` and exact equality still cover the bare token (handled before the
        # wildcard branch, so the single-segment guard does not reach them).
        ("*", "session", True),
        ("session", "session", True),
    ],
)
def test_covers_table(holder: str, requested: str, expected: bool) -> None:
    assert covers(holder, requested) is expected


@pytest.mark.parametrize(
    ("holder", "bare_token"),
    [("session.*", "session"), ("billing.invoice.*", "billing")],
)
def test_bare_single_segment_rejected_consistently(holder: str, bare_token: str) -> None:
    """Fix #2 (Option B): grant- AND check-side both reject a bare single-segment
    token being covered by a ``xxx.*`` holder, so the two never drift.

    ``covers`` (grant side) and ``_wildcard_match`` (live check side) must agree:
    neither may treat ``session`` as a leaf under ``session.*``.
    """
    assert covers(holder, bare_token) is False
    assert _wildcard_match([holder], bare_token) is False


def test_covers_is_consistent_with_wildcard_match() -> None:
    """For any concrete (non-wildcard) request, covers(h, req) must equal the
    live decision semantics _wildcard_match([h], req) OR exact-match."""
    holders = ["*", "session.*", "session.message.*", "billing.invoice.read"]
    requests = [
        "session.read",
        "session.message.read",
        "billing.invoice.read",
        "run.create",
        # bare single-segment requests must stay consistent across both sides too.
        "session",
        "run",
    ]
    for h in holders:
        for req in requests:
            decision = (h == req) or _wildcard_match([h], req)
            assert covers(h, req) is decision, (h, req)


# ---------------------------------------------------------------------------
# is_grantable
# ---------------------------------------------------------------------------

def test_is_grantable_empty_actor_fails_closed() -> None:
    assert is_grantable("session.read", set()) is False
    assert is_grantable("*", set()) is False


def test_is_grantable_covered_token_passes() -> None:
    assert is_grantable("session.read", {"session.*"}) is True
    assert is_grantable("session.message.read", {"session.*", "run.*"}) is True


def test_is_grantable_uncovered_token_fails() -> None:
    assert is_grantable("platform.admin", {"session.*", "run.*"}) is False


def test_is_grantable_star_request_only_for_star_holder() -> None:
    # Requesting to grant "*" requires holding "*".
    assert is_grantable("*", {"*"}) is True
    assert is_grantable("*", {"session.*", "run.*"}) is False
    assert is_grantable("*", {"session.read"}) is False


def test_is_grantable_authz_not_delegable_except_by_star() -> None:
    # A holder of the SPECIFIC authz.role.manage token still cannot delegate it.
    assert is_grantable("authz.role.manage", {"authz.role.manage"}) is False
    assert is_grantable("authz.binding.manage", {"authz.binding.manage"}) is False
    # Even authz.* as a holder cannot delegate authz.* (only bare "*" can).
    assert is_grantable("authz.role.manage", {"authz.*"}) is False
    # Only the bare "*" wildcard can delegate authz.* tokens.
    assert is_grantable("authz.role.manage", {"*"}) is True
    assert is_grantable("authz.binding.manage", {"*"}) is True


def test_is_grantable_non_authz_unaffected_by_delegation_rule() -> None:
    # The authz non-delegation rule must not leak into other services.
    assert is_grantable("session.read", {"session.*"}) is True
    assert is_grantable("authzx.read", {"authzx.*"}) is True  # not the authz. prefix


@pytest.mark.parametrize("token", ["Authz.role.manage", "AUTHZ.role.manage", "AuThZ.binding.manage"])
def test_is_grantable_authz_prefix_case_insensitive(token: str) -> None:
    """Fix #3: the ``authz.`` non-delegation guard must be case-insensitive so a
    case-variant token (e.g. ``Authz.role.manage``) cannot bypass it.

    A non-"*" holder — even one whose own wildcard would otherwise ``cover`` the
    token — must NOT be able to grant any authz. token regardless of case.
    Only the bare ``*`` wildcard delegates authz. tokens."""
    assert is_grantable(token, {"authz.*", "Authz.*"}) is False
    assert is_grantable(token, {"*"}) is True
