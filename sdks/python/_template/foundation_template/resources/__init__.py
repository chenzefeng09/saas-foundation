"""Resource classes — one per top-level API group.

Each Resource is a thin façade over Transport. Keep them stateless and
focused: parse params, call Transport, parse response, return models.

Conventions:
  - Method name = HTTP verb + resource (get/list/create/update/delete/...)
  - Sync method has matching `_async` variant
  - Return type = pydantic model from foundation_template.models
"""
