# Getting started

This guide takes you from a fresh clone of **SaaS Foundation** to a running local
stack, a migrated and seeded database, and a first call through the Python SDK.

SaaS Foundation is a standalone, reusable enterprise base (identity, authorization,
org, billing, audit, crypto, compliance, DLP, lifecycle, notification, search,
LLM gateway, and more) that any business system can build on. The
[Agent Platform](https://github.com/chenzefeng09/agent-platform) is one such
system: it is built on top of Foundation and calls these services for identity,
authorization, billing, audit, and LLM access.

For a tour of the architecture, see [ARCHITECTURE.md](./ARCHITECTURE.md). For
the production-oriented story (deployment profiles, air-gapped install, SaaS
multi-tenant, domestic-stack), see [deployment.md](./deployment.md).

---

## Prerequisites

The local workflow is driven by the top-level `Makefile`, which uses `bash`
(`-eu -o pipefail`) plus GNU `find`/`paste`. It is macOS/Linux-oriented.

| Tool | Version | Notes |
|---|---|---|
| Docker + Compose | Docker 24+, Compose v2 (`docker compose`) | Brings up all open-source dependencies |
| Python | 3.12+ | Per-package virtualenvs |
| Poetry | 1.8+ | Dependency + venv management (`pipx install poetry`) |
| Node.js | 20+ | Only needed for the OpenAPI contract toolchain (Spectral) and the TypeScript SDK build |
| make + bash | GNU make, bash | Runs the developer workflow |

> **Windows users:** run everything inside **WSL2**. The `Makefile` and the dev
> scripts assume a POSIX shell with GNU coreutils; native PowerShell/CMD is not
> supported for the developer workflow.

Optional, for chart testing and contract work:

- Helm 3.15+ and kubectl 1.30+ (and optionally K3s) — see [deployment.md](./deployment.md).
- The OpenAPI toolchain (Spectral, Redocly, oasdiff, openapi-generator) if you
  edit `contracts/openapi/`.

---

## 1. Clone and bring up the stack

```bash
git clone https://github.com/chenzefeng09/saas-foundation.git
cd saas-foundation

# One-shot: copy .env, start every dependency, wait for Keycloak,
# run business-level init, then assert health.
make up-full
```

`make up-full` is the recommended one-shot. Under the hood it:

1. Runs `make env` — copies `deploy/docker-compose/.env.example` to `.env` if it
   does not yet exist. **Adjust the placeholder passwords before any non-local
   use.**
2. Runs `make up` — `docker compose up -d` on `deploy/docker-compose/dev.yml`,
   bringing up the open-source dependency set:
   **Postgres** (with pgvector), **PgBouncer**, **Redis**, **Keycloak**,
   **ClickHouse**, **OpenSearch**, **Vault**, **MinIO**, **OPA**, **Unleash**,
   the **OpenTelemetry Collector**, **Jaeger**, and **Mailhog**.
3. Waits (up to ~3 min) for the Keycloak `foundation` realm to be importable.
4. Runs `tools/dev/post-up-init.sh` — business-level init: Vault transit engine,
   MinIO buckets, Keycloak Organizations.
5. Runs `tools/dev/healthcheck.sh` — health assertions across the stack.

The first run takes roughly 5–8 minutes (image pulls + Keycloak realm import);
subsequent runs are about a minute.

> The dev compose file brings up **dependencies only** — it does not run the
> Foundation application services themselves. For local service development you
> run each service from its package (see step 5), or use `make integration-up`
> to run a representative subset (identity / authz / org / crypto) in
> containers.

If you prefer to run the steps individually:

```bash
make up               # start the containers
make post-up-init     # Vault transit / MinIO buckets / Keycloak Organizations
make healthcheck      # business-level health assertions
```

To stop or reset:

```bash
make down             # stop services, keep data volumes
make nuke             # ⚠️ stop AND delete all local data volumes (irreversible)
```

---

## 2. Migrate and seed

```bash
make migrate          # alembic upgrade head for every package (as app_migrator)
make seed             # seed a dev tenant + test users
```

`make migrate` runs each package's Alembic migrations using the `app_migrator`
role (the only role with `BYPASSRLS`, reserved for CI/migrations). `make seed`
populates a dev tenant, test users, and supporting fixtures.

Verify the data landed:

```bash
make psql             # psql into the foundation DB as the postgres superuser
# inside psql:
\dt tenant.*
SELECT * FROM tenant.tenant;
\q
```

To validate Row-Level Security the way the app sees it, connect through
PgBouncer as the unprivileged `app_user`:

```bash
make psql-pgbouncer
```

PgBouncer must run in **transaction pool mode** for RLS to hold — see
[multi-tenancy.md](./multi-tenancy.md).

---

## 3. Verify

```bash
make healthcheck      # re-run the health assertions any time
make ps               # docker compose status
make logs SVC=keycloak   # follow one dependency's logs
```

`make healthcheck` asserts the real readiness signals (OPA policy load, Vault
transit, the Keycloak realm, and that the dev user can authenticate), not just
container liveness.

Once the stack is healthy, these dev consoles are reachable (default
credentials come from `.env`, derived from `.env.example` — change them before
any shared use):

| Console | URL | Default credentials |
|---|---|---|
| Keycloak | http://localhost:8080 | `admin` / `keycloak_admin_change_me` |
| MinIO console | http://localhost:9002 | `foundation` / `minio_change_me_min_12_chars` |
| Vault | http://localhost:8200 | token `dev-root-token-change-me` |
| Jaeger | http://localhost:16686 | — |
| Mailhog | http://localhost:8025 | — |
| Unleash | http://localhost:4242 | API token `unleash-insecure-admin-api-token` |

---

## 4. Use the SDK

A business service never talks to the open-source engines (Keycloak, OPA,
ClickHouse, OpenSearch, LiteLLM) directly. Instead it imports
**`foundation-sdk`**, a typed Python client that exposes every Foundation
service as a resource group and derives all per-service URLs from one base URL.

### Install the SDK (sibling checkout / local build)

The SDK is not published to public PyPI. Install it from your checked-out
repository, either editable or as a locally built wheel.

```bash
# Editable install from the checked-out repo (development):
pip install -e "./sdks/python[fastapi]"
```

```bash
# Or build the wheel locally and install that:
make sdk-build        # produces sdks/python/dist/foundation_sdk-*.whl
pip install "./sdks/python/dist/foundation_sdk-<version>-py3-none-any.whl[fastapi]"
```

The `fastapi` extra is only needed by services that mount the SDK's FastAPI
middleware (request-context propagation + RFC 7807 problem details). Pure
clients (CLIs, workers) can omit it:

```bash
pip install -e ./sdks/python
```

> Downstream systems such as the Agent Platform install this same SDK from a
> **sibling checkout** of `saas-foundation` (its build wires
> `../saas-foundation/sdks/python` in). If you are developing the Agent Platform,
> check out both repositories side by side.

### Configure and call

The client reads two environment variables:

```bash
export FOUNDATION_API_URL="http://localhost:8000"   # the Foundation API base URL
export FOUNDATION_API_TOKEN="<bearer-token>"        # a Foundation-issued JWT
```

`FoundationClient.from_env()` raises if `FOUNDATION_API_TOKEN` is unset. All
service URLs (`/api/identity/v1/...`, `/api/authz/v1/...`, etc.) are derived
from the single base URL.

```python
from foundation_sdk import FoundationClient

client = FoundationClient.from_env()
with client:
    # Identity — look up a user
    user = client.identity.get_user("usr_123")

    # Authorization — RBAC + OPA permission check
    decision = client.authz.check(
        action="read",
        resource_type="document",
        resource_id="doc_456",
    )

    # Billing — quota check for a metered dimension
    quota = client.billing.check_quota(dimension="user_seats")
```

`FoundationClient` aggregates 17 resource groups — `identity`, `authz`, `org`,
`billing`, `audit`, `lifecycle`, `notification`, `search`, `api_platform`,
`llm_gateway`, `feature_flag`, `dlp`, `crypto`, `compliance`, `pam`,
`data_protection`, and `security_ops`. Each method has an `_async` counterpart
(e.g. `await client.authz.check_async(...)`). See
[`sdks/python/README.md`](../sdks/python/README.md) and
`foundation_sdk/__init__.py` for the full surface.

---

## Ports reference

Default host ports published by the dev stack (`deploy/docker-compose/dev.yml`).
Every port is overridable via a `PORT_*` variable in `.env`; the defaults are
shown below. Note that several Foundation **services** publish on a shifted host
port to avoid collisions while keeping a stable container port.

### Open-source dependencies

| Component | Host port | Purpose |
|---|---|---|
| Postgres (pgvector) | 5432 | Primary datastore (RLS) |
| PgBouncer | 6432 | Transaction-pool connection pooler |
| Redis | 6379 | Cache / sessions |
| Keycloak | 8080 | OIDC / OAuth2 / SAML IdP |
| ClickHouse | 8123 (HTTP), 9000 (TCP) | Audit / usage event store |
| OpenSearch | 9200 | Search engine |
| Vault | 8200 | Transit engine / KEK store |
| MinIO | 9001 (S3 API), 9002 (console) | Object storage |
| OPA | 8181 | ABAC policy sidecar |
| Unleash | 4242 | Feature-flag backend |
| OTel Collector | 4317 (gRPC), 4318 (HTTP), 8889 (Prometheus) | Telemetry ingest |
| Jaeger | 16686 | Trace UI |
| Prometheus | 9090 | Metrics |
| Mailhog | 8025 (UI), 1025 (SMTP) | Dev mail capture |

### Foundation services (host : container)

| Service | Host port | Container port |
|---|---|---|
| identity | 8001 | 8001 |
| authz | 8002 | 8002 |
| org | 8003 | 8003 |
| crypto | 8004 | 8004 |
| search | 8009 | 8009 |
| llm-gateway | 8011 | 8011 |
| feature-flag | 8012 | 8012 |
| audit | 8013 | 8013 |
| billing | 8017 | 8007 |
| lifecycle | 18006 | 8006 |
| dlp | 18007 | 8007 |
| notification | 18008 | 8008 |
| api-platform | 18010 | 8010 |
| compliance | 18014 | 8014 |
| pam | 18015 | 8015 |
| data-protection | 18016 | 8016 |
| security-ops | 18019 | 8019 |

> The shifted host ports (e.g. billing `8017→8007`, dlp `18007→8007`) exist
> because some services share a container port; the host mapping keeps them
> distinct in local development. Always reach a service on its **host** port
> locally.

---

## Where to go next

- **Architecture** — [ARCHITECTURE.md](./ARCHITECTURE.md): the service catalog,
  the three-wall tenant-isolation model, and the data flow.
- **Multi-tenancy** — [multi-tenancy.md](./multi-tenancy.md): the RLS + PgBouncer
  baseline, the four DB roles, and the SaaS tier → isolation mapping. Read this
  before touching any tenant-scoped table.
- **Conventions** — [CONVENTIONS.md](./CONVENTIONS.md): naming, package layout,
  URL/versioning, pagination, and the SDK compatibility policy.
- **Errors** — [errors.md](./errors.md): the error-code taxonomy.
- **Deployment** — [deployment.md](./deployment.md): small/medium/large profiles,
  air-gapped private cloud, the SaaS multi-tenant profile, and the 信创/国密
  domestic-stack profile.
- **SDK** — [`sdks/python/README.md`](../sdks/python/README.md).

### Common make targets

```bash
make help                 # list all targets
make test                 # pytest across all packages
make lint                 # ruff check + mypy across all packages
make format               # ruff format across all packages
make test-rls-fuzz        # mandatory RLS cross-tenant fuzz suite
make scan                 # gitleaks + semgrep + license scan
make sbom                 # generate CycloneDX + SPDX SBOM
make integration-all      # full docker-compose integration run
```

---

## License

SaaS Foundation is licensed under **Apache-2.0**. See [LICENSE](../LICENSE) and
[NOTICE](../NOTICE).
