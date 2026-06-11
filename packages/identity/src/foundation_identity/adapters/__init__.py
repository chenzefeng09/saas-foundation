"""Outbound adapters — the ONLY place external SDKs (Keycloak, Redis, …) may be imported."""

from foundation_identity.adapters.audit_publisher import AuditPublisher, get_audit_publisher
from foundation_identity.adapters.hibp_gateway import HibpGateway, get_hibp_gateway
from foundation_identity.adapters.keycloak_admin import KeycloakAdminAdapter, get_keycloak_admin
from foundation_identity.adapters.notification_gateway import (
    NotificationGateway,
    get_notification_gateway,
)
from foundation_identity.adapters.password_hasher import PasswordHasher, get_password_hasher
from foundation_identity.adapters.redis_cache import RedisCacheAdapter, get_redis_cache

__all__ = [
    "AuditPublisher",
    "HibpGateway",
    "KeycloakAdminAdapter",
    "NotificationGateway",
    "PasswordHasher",
    "RedisCacheAdapter",
    "get_audit_publisher",
    "get_hibp_gateway",
    "get_keycloak_admin",
    "get_notification_gateway",
    "get_password_hasher",
    "get_redis_cache",
]
