"""Foundation SDK template.

Replace `template` with the actual service name when copying:
    foundation_template -> foundation_identity
    TemplateClient      -> IdentityClient
"""

from foundation_template.client import TemplateClient
from foundation_template.errors import (
    AuthError,
    DependencyError,
    FoundationError,
    PolicyError,
    QuotaExceededError,
    ValidationError,
)

__version__ = "0.1.0"

__all__ = [
    "TemplateClient",
    "FoundationError",
    "AuthError",
    "PolicyError",
    "QuotaExceededError",
    "DependencyError",
    "ValidationError",
    "__version__",
]
