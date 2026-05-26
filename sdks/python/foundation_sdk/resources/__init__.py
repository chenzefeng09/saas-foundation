"""Resource wrappers for Foundation services."""

from foundation_sdk.resources.identity import IdentityResource
from foundation_sdk.resources.authz import AuthzResource
from foundation_sdk.resources.org import OrgResource
from foundation_sdk.resources.billing import BillingResource
from foundation_sdk.resources.audit import AuditResource
from foundation_sdk.resources.lifecycle import LifecycleResource
from foundation_sdk.resources.notification import NotificationResource
from foundation_sdk.resources.search import SearchResource
from foundation_sdk.resources.api_platform import ApiPlatformResource
from foundation_sdk.resources.llm_gateway import LLMGatewayResource
from foundation_sdk.resources.feature_flag import FeatureFlagResource
from foundation_sdk.resources.dlp import DLPResource
from foundation_sdk.resources.crypto import CryptoResource
from foundation_sdk.resources.compliance import ComplianceResource
from foundation_sdk.resources.pam import PAMResource
from foundation_sdk.resources.data_protection import DataProtectionResource

__all__ = [
    "IdentityResource", "AuthzResource", "OrgResource",
    "BillingResource", "AuditResource", "LifecycleResource",
    "NotificationResource", "SearchResource", "ApiPlatformResource",
    "LLMGatewayResource", "FeatureFlagResource", "DLPResource",
    "CryptoResource", "ComplianceResource", "PAMResource",
    "DataProtectionResource",
]
