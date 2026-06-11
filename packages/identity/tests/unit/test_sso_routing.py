"""Pure-function tests for SSO routing resolution (resolve_routing).

No DB: SsoRoutingRule ORM instances are built in-memory and passed directly.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from foundation_identity.domain.models import SsoRoutingRule
from foundation_identity.services.sso_service import resolve_routing

_T_A = "tnt_01J5TESTAAAAAAAAAAAAAAAAAA"
_T_B = "tnt_01J5TESTBBBBBBBBBBBBBBBBBB"
_BASE = datetime(2026, 1, 1, tzinfo=UTC)


def _rule(
    *,
    match_type: str,
    match_value: str,
    target_tenant_id: str,
    match_attribute: str = "groups",
    priority: int = 100,
    enabled: bool = True,
    default_role: str | None = None,
    created_at: datetime | None = None,
    rid: str = "ssor_x",
) -> SsoRoutingRule:
    return SsoRoutingRule(
        id=rid,
        provider_id="sso_x",
        priority=priority,
        match_attribute=match_attribute,
        match_type=match_type,
        match_value=match_value,
        target_tenant_id=target_tenant_id,
        default_role=default_role,
        enabled=enabled,
        created_at=created_at or _BASE,
        updated_at=created_at or _BASE,
    )


@pytest.mark.unit
def test_email_domain_case_insensitive() -> None:
    rules = [_rule(match_type="EMAIL_DOMAIN", match_value="Acme.COM", target_tenant_id=_T_A)]
    assert resolve_routing(rules, {}, "Alice@ACME.com") == (_T_A, None)


@pytest.mark.unit
def test_email_domain_no_email_returns_none() -> None:
    rules = [_rule(match_type="EMAIL_DOMAIN", match_value="acme.com", target_tenant_id=_T_A)]
    assert resolve_routing(rules, {}, None) is None
    assert resolve_routing(rules, {}, "no-at-sign") is None


@pytest.mark.unit
def test_equals_str_attr() -> None:
    rules = [
        _rule(
            match_type="EQUALS",
            match_attribute="department",
            match_value="Engineering",
            target_tenant_id=_T_A,
            default_role="member",
        )
    ]
    assert resolve_routing(rules, {"department": "engineering"}, None) == (_T_A, "member")


@pytest.mark.unit
def test_equals_list_attr() -> None:
    rules = [
        _rule(
            match_type="EQUALS",
            match_attribute="groups",
            match_value="admins",
            target_tenant_id=_T_B,
        )
    ]
    attrs = {"groups": ["users", "ADMINS", "billing"]}
    assert resolve_routing(rules, attrs, None) == (_T_B, None)


@pytest.mark.unit
def test_equals_no_match() -> None:
    rules = [
        _rule(
            match_type="EQUALS",
            match_attribute="groups",
            match_value="admins",
            target_tenant_id=_T_B,
        )
    ]
    assert resolve_routing(rules, {"groups": ["users"]}, None) is None
    # attribute absent entirely
    assert resolve_routing(rules, {}, None) is None


@pytest.mark.unit
def test_contains_substring_case_insensitive() -> None:
    rules = [
        _rule(
            match_type="CONTAINS",
            match_attribute="org",
            match_value="corp",
            target_tenant_id=_T_A,
        )
    ]
    assert resolve_routing(rules, {"org": "BigCORP-Division"}, None) == (_T_A, None)
    assert resolve_routing(rules, {"org": "nonprofit"}, None) is None


@pytest.mark.unit
def test_regex_match_and_list() -> None:
    rules = [
        _rule(
            match_type="REGEX",
            match_attribute="email",
            match_value=r"^ext-.*@partner\.io$",
            target_tenant_id=_T_B,
        )
    ]
    assert resolve_routing(rules, {"email": "ext-bob@partner.io"}, None) == (_T_B, None)
    assert resolve_routing(rules, {"email": ["a@x.com", "ext-z@partner.io"]}, None) == (
        _T_B,
        None,
    )
    assert resolve_routing(rules, {"email": "bob@other.io"}, None) is None


@pytest.mark.unit
def test_regex_invalid_is_skipped() -> None:
    # Invalid regex must not raise; the rule is skipped and the next one wins.
    bad = _rule(
        match_type="REGEX",
        match_attribute="x",
        match_value="(unclosed",
        target_tenant_id=_T_A,
        priority=1,
    )
    good = _rule(
        match_type="EQUALS",
        match_attribute="x",
        match_value="hit",
        target_tenant_id=_T_B,
        priority=2,
    )
    assert resolve_routing([bad, good], {"x": "hit"}, None) == (_T_B, None)


@pytest.mark.unit
def test_priority_ordering_first_match_wins() -> None:
    low = _rule(
        match_type="EQUALS",
        match_attribute="x",
        match_value="hit",
        target_tenant_id=_T_A,
        priority=10,
    )
    high = _rule(
        match_type="EQUALS",
        match_attribute="x",
        match_value="hit",
        target_tenant_id=_T_B,
        priority=5,
    )
    # high (priority=5) sorts first → its tenant wins
    assert resolve_routing([low, high], {"x": "hit"}, None) == (_T_B, None)


@pytest.mark.unit
def test_priority_tie_broken_by_created_at() -> None:
    earlier = _rule(
        match_type="EQUALS",
        match_attribute="x",
        match_value="hit",
        target_tenant_id=_T_A,
        priority=10,
        created_at=_BASE,
    )
    later = _rule(
        match_type="EQUALS",
        match_attribute="x",
        match_value="hit",
        target_tenant_id=_T_B,
        priority=10,
        created_at=_BASE + timedelta(hours=1),
    )
    assert resolve_routing([later, earlier], {"x": "hit"}, None) == (_T_A, None)


@pytest.mark.unit
def test_disabled_rule_skipped() -> None:
    disabled = _rule(
        match_type="EQUALS",
        match_attribute="x",
        match_value="hit",
        target_tenant_id=_T_A,
        priority=1,
        enabled=False,
    )
    enabled = _rule(
        match_type="EQUALS",
        match_attribute="x",
        match_value="hit",
        target_tenant_id=_T_B,
        priority=2,
    )
    assert resolve_routing([disabled, enabled], {"x": "hit"}, None) == (_T_B, None)


@pytest.mark.unit
def test_no_match_returns_none() -> None:
    rules = [
        _rule(match_type="EMAIL_DOMAIN", match_value="acme.com", target_tenant_id=_T_A),
        _rule(
            match_type="EQUALS",
            match_attribute="dept",
            match_value="eng",
            target_tenant_id=_T_B,
        ),
    ]
    assert resolve_routing(rules, {"dept": "sales"}, "bob@other.com") is None
    assert resolve_routing([], {}, "bob@acme.com") is None
