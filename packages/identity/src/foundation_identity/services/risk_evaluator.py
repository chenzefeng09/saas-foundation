"""Anomalous-login risk scoring.

Pure-application-layer rules — no GeoIP/Fingerprint third party — that catch
the most common signals using only the data already in the identity schema:

  * **CONSECUTIVE_FAILURES** — repeated failed logins within a short window.
  * **NEW_DEVICE**          — this exact User-Agent has never been seen for the
    user before (across all historical sessions).
  * **IP_SUBNET_JUMP**       — current IP's /24 (IPv4) or /64 (IPv6) prefix
    differs from the most recent successful login's prefix.
  * **NEW_USER_AGENT_PATTERN** — the browser / OS major class changed vs the
    user's most recent session.

The evaluator emits :class:`RiskSignal` rows for *every* fired rule (allowed,
stepped-up, or denied) so the data is available for retrospective audit even
when a login was refused (no Session row written).

Decision thresholds:

  * total ≥ 70 → ``DENY``     — raise ``LOGIN_DENIED_RISK``.
  * total ≥ 30 → ``STEP_UP`` — force MFA even if ``user.mfa_enabled=False``.
  * total < 30 → ``ALLOW``.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import timedelta
from typing import Literal

import ulid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from foundation_identity.domain.models import RiskSignal, User
from foundation_identity.domain.models import Session as SessionModel
from foundation_identity.observability import get_logger

log = get_logger(__name__)

Decision = Literal["ALLOW", "STEP_UP", "DENY"]

# Rule weight catalogue.  Tune via PRs, not config — these are security
# decisions, not deployment preferences.
_WEIGHTS: dict[str, int] = {
    "CONSECUTIVE_FAILURES": 60,
    "NEW_DEVICE": 25,
    "IP_SUBNET_JUMP": 35,
    "NEW_USER_AGENT_PATTERN": 15,
}

# Decision thresholds (sum of fired weights).
_DENY_THRESHOLD = 70
_STEP_UP_THRESHOLD = 30

# Sliding window for consecutive-failure detection.
_FAILURE_WINDOW = timedelta(minutes=15)
_FAILURE_FLOOR = 3  # >= this many failures in the window → fire


@dataclass(frozen=True, slots=True)
class RiskContext:
    """Inputs for a login risk evaluation."""

    tenant_id: str
    user_id: str
    ip: str | None
    user_agent: str | None


@dataclass(frozen=True, slots=True)
class RiskOutcome:
    """Aggregate result of running every rule on a login attempt."""

    score: int
    decision: Decision
    fired: tuple[str, ...]


def _ip_prefix(ip: str | None) -> str | None:
    """Return the user's /24 (IPv4) or /64 (IPv6) network as a string, or None."""
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv4Address):
        return str(ipaddress.ip_network(f"{ip}/24", strict=False).network_address)
    return str(ipaddress.ip_network(f"{ip}/64", strict=False).network_address)


_BROWSER_PATTERNS = (
    ("edge", re.compile(r"edg/|edge/", re.IGNORECASE)),
    ("opera", re.compile(r"opr/|opera", re.IGNORECASE)),
    ("firefox", re.compile(r"firefox/|fxios/", re.IGNORECASE)),
    ("chrome", re.compile(r"chrome/|crios/", re.IGNORECASE)),
    ("safari", re.compile(r"safari/", re.IGNORECASE)),
)

_OS_PATTERNS = (
    ("ios", re.compile(r"iphone|ipad", re.IGNORECASE)),
    ("android", re.compile(r"android", re.IGNORECASE)),
    ("windows", re.compile(r"windows", re.IGNORECASE)),
    ("macos", re.compile(r"macintosh|mac os", re.IGNORECASE)),
    ("linux", re.compile(r"linux", re.IGNORECASE)),
)


def _ua_class(user_agent: str | None) -> str:
    """Reduce a User-Agent to a coarse ``browser:os`` class for change detection."""
    if not user_agent:
        return ""
    browser = next(
        (label for label, pat in _BROWSER_PATTERNS if pat.search(user_agent)),
        "unknown",
    )
    os_label = next(
        (label for label, pat in _OS_PATTERNS if pat.search(user_agent)),
        "unknown",
    )
    return f"{browser}:{os_label}"


class RiskEvaluator:
    """Evaluate a login attempt + persist signals + return a decision."""

    async def evaluate(
        self, session: AsyncSession, *, ctx: RiskContext
    ) -> RiskOutcome:
        """Run every rule, persist a row per fired rule, return the outcome.

        Caller is responsible for honouring the decision (raise
        ``LOGIN_DENIED_RISK`` on DENY; force MFA on STEP_UP).  The session
        parameter is the admin-scope async session under which the login is
        already running, so persistence shares the same transaction.
        """
        fired: list[tuple[str, str | None]] = []  # (rule, detail)

        if await self._consecutive_failures(session, ctx):
            fired.append(("CONSECUTIVE_FAILURES", "failed-attempt-floor exceeded"))

        latest = await self._latest_successful_session(session, ctx)
        if await self._new_device(session, ctx):
            fired.append(("NEW_DEVICE", f"ua={_truncate(ctx.user_agent)}"))
        if self._ip_subnet_jump(latest, ctx):
            fired.append(("IP_SUBNET_JUMP", f"ip={ctx.ip}"))
        if self._new_ua_pattern(latest, ctx):
            fired.append(("NEW_USER_AGENT_PATTERN", _ua_class(ctx.user_agent)))

        score = sum(_WEIGHTS[r] for r, _ in fired)
        if score >= _DENY_THRESHOLD:
            decision: Decision = "DENY"
        elif score >= _STEP_UP_THRESHOLD:
            decision = "STEP_UP"
        else:
            decision = "ALLOW"

        for rule, detail in fired:
            session.add(
                RiskSignal(
                    id=f"rsk_{ulid.new()!s}",
                    tenant_id=ctx.tenant_id,
                    user_id=ctx.user_id,
                    rule=rule,
                    weight=_WEIGHTS[rule],
                    decision=decision,
                    ip=ctx.ip,
                    user_agent=_truncate(ctx.user_agent),
                    detail=detail,
                )
            )
        if fired:
            await session.flush()
            log.info(
                "auth.risk_evaluated",
                tenant_id=ctx.tenant_id,
                user_id=ctx.user_id,
                score=score,
                decision=decision,
                fired=[r for r, _ in fired],
            )

        return RiskOutcome(score=score, decision=decision, fired=tuple(r for r, _ in fired))

    # ── rule implementations ─────────────────────────────────────────────── #

    async def _consecutive_failures(
        self, session: AsyncSession, ctx: RiskContext
    ) -> bool:
        """Has the user accumulated ≥ floor failures within the sliding window?

        Uses ``user.failed_login_count`` as a cheap proxy: P2-C wipes it on a
        clean login, so any non-zero count corresponds to the *current* failure
        streak.  A fresh sufficiently-large streak fires the rule.
        """
        result = await session.execute(
            select(User).where(
                User.tenant_id == ctx.tenant_id,
                User.id == ctx.user_id,
            )
        )
        user = result.scalar_one_or_none()
        if user is None:
            return False
        return (user.failed_login_count or 0) >= _FAILURE_FLOOR

    async def _new_device(
        self, session: AsyncSession, ctx: RiskContext
    ) -> bool:
        """First time this exact User-Agent string is seen for the user."""
        if not ctx.user_agent:
            return False
        result = await session.execute(
            select(SessionModel.id).where(
                SessionModel.tenant_id == ctx.tenant_id,
                SessionModel.user_id == ctx.user_id,
                SessionModel.user_agent == ctx.user_agent,
            ).limit(1)
        )
        return result.scalar_one_or_none() is None

    async def _latest_successful_session(
        self, session: AsyncSession, ctx: RiskContext
    ) -> SessionModel | None:
        result = await session.execute(
            select(SessionModel)
            .where(
                SessionModel.tenant_id == ctx.tenant_id,
                SessionModel.user_id == ctx.user_id,
            )
            .order_by(SessionModel.issued_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    def _ip_subnet_jump(
        self, latest: SessionModel | None, ctx: RiskContext
    ) -> bool:
        if latest is None or not ctx.ip or not latest.ip:
            return False
        return _ip_prefix(ctx.ip) != _ip_prefix(latest.ip)

    def _new_ua_pattern(
        self, latest: SessionModel | None, ctx: RiskContext
    ) -> bool:
        if latest is None or not ctx.user_agent or not latest.user_agent:
            return False
        return _ua_class(ctx.user_agent) != _ua_class(latest.user_agent)


def _truncate(value: str | None, limit: int = 500) -> str | None:
    if value is None:
        return None
    return value if len(value) <= limit else value[:limit]


# Single instance is fine — RiskEvaluator holds no state.
_singleton: RiskEvaluator | None = None


def get_risk_evaluator() -> RiskEvaluator:
    """Module-level singleton; tests override via FastAPI dependency_overrides."""
    global _singleton
    if _singleton is None:
        _singleton = RiskEvaluator()
    return _singleton


__all__ = [
    "Decision",
    "RiskContext",
    "RiskEvaluator",
    "RiskOutcome",
    "get_risk_evaluator",
]


# Re-export sliding window for callers that need to label the failure floor.
FAILURE_WINDOW = _FAILURE_WINDOW
FAILURE_FLOOR = _FAILURE_FLOOR
