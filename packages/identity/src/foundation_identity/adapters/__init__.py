"""Outbound adapters — the ONLY place external SDKs (Keycloak, Redis, …) may be imported."""

from foundation_identity.adapters.audit_publisher import AuditPublisher, get_audit_publisher
from foundation_identity.adapters.keycloak_admin import KeycloakAdminAdapter, get_keycloak_admin
from foundation_identity.adapters.password_hasher import PasswordHasher, get_password_hasher

__all__ = [
    "AuditPublisher",
    "KeycloakAdminAdapter",
    "PasswordHasher",
    "get_audit_publisher",
    "get_keycloak_admin",
    "get_password_hasher",
]
