"""OTel integration stub.

Real implementation will:
  - Wrap Transport requests in a span named "foundation.<service>.<resource>.<action>"
  - Set attributes: foundation.tenant_id, foundation.user_id, http.status_code
  - Propagate traceparent header to outgoing calls
  - Record exceptions on the span
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator


@contextmanager
def span(name: str, **attributes: object) -> Iterator[None]:
    """Placeholder span context manager.

    TODO: replace with real OTel tracer once foundation_common.observability lands.
    """
    # from opentelemetry import trace
    # tracer = trace.get_tracer("foundation-sdk-template")
    # with tracer.start_as_current_span(name, attributes=attributes):
    #     yield
    del name, attributes
    yield
