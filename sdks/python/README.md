# foundation-sdk

Typed Python client for the **SaaS Foundation** internal services
(identity, authz, org, billing, audit, crypto, etc.). Consumed by every
business-layer service that needs to talk to a Foundation API or share
the FastAPI middleware contract.

## Install

From a private PyPI mirror, if you publish the package to one (for CI and
production images):

```bash
pip install --extra-index-url https://pypi.example.com/simple/ \
  "foundation-sdk[fastapi]>=0.1,<0.2"
```

Or directly from a checked-out copy of this repository:

```bash
pip install -e ./sdks/python[fastapi]
```

The `fastapi` extra is required by services that mount
`foundation_sdk.fastapi` middleware; pure-client consumers (CLIs,
workers) can omit it.

## Quick start

```python
from foundation_sdk import FoundationClient

client = FoundationClient.from_env()
with client:
    user = client.identity.get_user("usr_123")
    quota = client.billing.check_quota(dimension="user_seats")
```

See `foundation_sdk/__init__.py` for the full surface.

## Versioning

This package follows semver:

* **patch** (`0.1.0 -> 0.1.1`) — backward-compatible fixes; safe to
  bump anywhere.
* **minor** (`0.1.x -> 0.2.0`) — backward-compatible additions; pinned
  with `>=0.1,<0.2` style ranges in consumers.
* **major** (`0.x -> 1.0`) — breaking; requires coordinated upgrade in
  all consuming services (see `docs/sdk-release.md`).

## Building & publishing

```bash
./build.sh             # produces dist/foundation_sdk-*.whl + .tar.gz
./publish.sh --dry-run # validates upload without pushing
./publish.sh           # uploads to $FOUNDATION_PYPI_URL
```

CI does this automatically on tags of the form `foundation-sdk-v*`
(see `.github/workflows/foundation-sdk-release.yml`).
