"""Outbound adapters — the ONLY place external SDKs (OPA, Redis, …) may be imported."""

from foundation_authz.adapters.audit_publisher import AuditPublisher, get_audit_publisher
from foundation_authz.adapters.opa_client import OpaClient, get_opa_client

__all__ = ["AuditPublisher", "OpaClient", "get_audit_publisher", "get_opa_client"]
