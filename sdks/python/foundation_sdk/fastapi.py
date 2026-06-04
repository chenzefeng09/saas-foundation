"""Public re-exports of the FastAPI integration helpers.

Importing this module pulls in FastAPI/Starlette; only do so from a service
that actually runs them.  Install with ``pip install foundation-sdk[fastapi]``.
"""

from foundation_sdk._fastapi import (
    RequestContextMiddleware,
    get_request_id,
    get_tenant_id,
    get_user_id,
    install_request_context,
    push_identity,
    register_problem_details,
)

__all__ = [
    "RequestContextMiddleware",
    "get_request_id",
    "get_tenant_id",
    "get_user_id",
    "install_request_context",
    "push_identity",
    "register_problem_details",
]
