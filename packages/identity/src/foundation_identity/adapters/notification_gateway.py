"""Notification gateway adapter — delivers SMS / email for MFA flows.

The real implementation routes through ``foundation-notification-service``
(out of scope for identity).  In dev / unit tests we use the no-op
implementation, which logs the delivery and returns immediately so MFA
enrolment + verification can be exercised without a live SMS provider.
"""

from __future__ import annotations

from foundation_identity.observability import get_logger

log = get_logger(__name__)


class NotificationGateway:
    """Default no-op implementation: log + return.

    Production deployments override the FastAPI dependency
    ``notification_gateway`` with an HTTP-backed adapter that calls
    ``foundation-notification-service``.  Keeping the dev default a no-op
    means the identity service can boot and self-test in any environment.
    """

    async def send_sms(self, *, phone: str, body: str) -> None:
        """Send an SMS to ``phone``.  Never logs the body verbatim."""
        log.info("notification.sms.dispatched", phone=phone[-4:], body_len=len(body))


_singleton: NotificationGateway | None = None


def get_notification_gateway() -> NotificationGateway:
    """Module-level singleton; tests override via FastAPI dependency_overrides."""
    global _singleton
    if _singleton is None:
        _singleton = NotificationGateway()
    return _singleton
