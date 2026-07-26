# saas-foundation

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![API](https://img.shields.io/badge/API-OpenAPI%203.1-6ba539.svg)](contracts/openapi/)
[![Errors](https://img.shields.io/badge/errors-RFC%209457-informational.svg)](docs/errors.md)

**English** · [简体中文](README.zh-CN.md)

A reusable enterprise SaaS platform base: **17 independently deployable services**
covering identity, authorization, organization, billing, audit, compliance, DLP, crypto,
notification, search, LLM gateway and more — plus the SDK your application uses to reach
them.

The point is a hard line between platform plumbing and product code. Your application
imports `foundation_sdk` and calls foundation services over HTTP; it never talks to
Keycloak, OPA, ClickHouse, OpenSearch, LiteLLM, Vault or MinIO directly. Those are
implementation details the base owns, and can swap, without your code noticing.

[**cloud·worker**](https://github.com/chenzefeng09/cloud-worker) is the first product
built on this base — see [Who uses this](#who-uses-this).

> **Project status.** In active development, deployed for internal pilots — not yet 1.0.
> Service interfaces still move. The `go` SDK is a placeholder; Python is complete and
> TypeScript is partial.

---

## Table of contents

- [Design goals](#design-goals)
- [What's inside](#whats-inside)
- [Architecture](#architecture)
- [Multi-tenancy: three walls](#multi-tenancy-three-walls)
- [Who uses this](#who-uses-this)
- [Repository layout](#repository-layout)
- [Quick start](#quick-start)
- [Using the SDK](#using-the-sdk)
- [Development](#development)
- [Deployment](#deployment)
- [Compliance](#compliance)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

---

## Design goals

- **Private-cloud first** — the default target is a customer's own datacentre: K8s 1.24+,
  air-gapped install, no outbound calls required.
- **SaaS-capable from the same chart** — flip a profile to get multi-tenant SaaS with
  per-tier isolation, instead of maintaining two codebases.
- **Zero component awareness in business code** — applications import the SDK. They never
  see Keycloak, OPA, LiteLLM, Vault or MinIO, so those can be replaced without touching
  product code.
- **Compliance as a built-in, not a retrofit** — Chinese MLPS 2.0 Level 3 and PIPL are
  covered by design; SM cryptography and domestic hardware come next.
- **Three sizes** — `small` / `medium` / `large` Helm profiles, HA and scaling included.

---

## What's inside

Seventeen services, each owning exactly one capability. One capability per service is a
rule, not a guideline — new capability, new service.

| Service | Port | Responsibility |
|---|---|---|
| `identity` | 8001 | Sessions, users, MFA, SSO, SCIM, password/login policy |
| `authz` | 8002 | Authorization — RBAC and OPA/ABAC on parallel tracks |
| `org` | 8003 | Tenant → OU → Team → User hierarchy |
| `crypto` | 8004 | Envelope encryption, KEK lifecycle, signatures, password hashing |
| `lifecycle` | 18006 | Retention, recycle bin, legal hold, destruction certificates, backup orchestration |
| `dlp` | 18007 | Data loss prevention + content classification |
| `billing` | 8017 | Metering and billing — dual-mode (private licence + SaaS subscription) |
| `notification` | 18008 | Email, webhook, WebSocket, DingTalk, Feishu, WeCom |
| `search` | 8009 | OpenSearch wrapper with ACL-aware result filtering |
| `api-platform` | 18010 | API keys, OAuth apps, outbound webhooks |
| `llm-gateway` | 8011 | LiteLLM wrapper — provider routing, virtual keys, quota |
| `feature-flag` | 8012 | Unleash wrapper |
| `audit` | 8013 | Immutable audit log: OTel → ClickHouse → S3 WORM, hash-chained and signed |
| `compliance` | 18014 | ROPA, DPIA, DSAR, compliance reporting |
| `pam` | 18015 | Privileged access management |
| `data-protection` | 18016 | Masking engine, data destruction, cross-border transfer, consent |
| `security-ops` | 18019 | SSDLC, vulnerability SLA, SBOM, incident response |

Plus **`storage`** — not a service but a library: a boto3-based S3/MinIO client with
tenant-scoped key layout, quota hooks and OTel instrumentation.

Ports above are the docker-compose dev-stack host ports. Several services are published
on a `1xxxx` host port to avoid collisions (`billing` 8017→8007, `notification`
18008→8008, and so on) — see `deploy/docker-compose/dev.yml`.

### Open-source components underneath

| Concern | Component | Fronted by |
|---|---|---|
| Identity provider | Keycloak | `identity` |
| Policy engine | OPA | `authz` |
| Relational store | PostgreSQL + PgBouncer | all services |
| Cache / queue | Redis | several |
| Audit warehouse | ClickHouse | `audit` |
| Search index | OpenSearch | `search` |
| Secrets / KMS | Vault (transit) | `crypto` |
| Object storage | MinIO (S3-compatible) | `storage` |
| Feature flags | Unleash | `feature-flag` |
| LLM routing | LiteLLM | `llm-gateway` |
| Telemetry | OpenTelemetry, Jaeger, Prometheus | all services |

Business code touches none of these directly. That indirection is the product.

---

## Architecture

```
                    Your application  (e.g. cloud·worker)
                              │
                              │  foundation_sdk  ·  HTTP + OpenAPI 3.1
                              ▼
   ┌───────────────────────────────────────────────────────────────────┐
   │                        foundation services                        │
   │                                                                   │
   │  identity   authz    org      crypto     lifecycle   dlp          │
   │  billing    search   audit    compliance pam         notification │
   │  api-platform        llm-gateway   feature-flag   data-protection │
   │  security-ops                                                     │
   └───┬───────────────────────────────────────────────────────────┬───┘
       │                                                           │
       ▼                                                           ▼
   ┌────────────────────────────────┐        ┌───────────────────────────┐
   │  Keycloak · OPA · Vault        │        │  PostgreSQL + PgBouncer   │
   │  ClickHouse · OpenSearch       │        │  (RLS-enforced isolation) │
   │  MinIO · Redis · Unleash       │        │  Redis                    │
   │  LiteLLM                       │        └───────────────────────────┘
   └────────────────────────────────┘
              ▲
              └── never reached directly by business code
```

Every service follows the same internal shape (`docs/CONVENTIONS.md` §1.2):

```
packages/<capability>/
├── src/foundation_<capability>/
│   ├── api/v1/        FastAPI routers — HTTP entry, versioned
│   ├── domain/        domain models
│   ├── services/      business logic — pure Python, no FastAPI import
│   └── adapters/      outbound: DB, Keycloak, OPA, Redis, …
└── tests/
```

Errors are RFC 9457 problem+json across every service, with stable machine-readable
codes and a separate user-facing `user_message` — see [docs/errors.md](docs/errors.md).

---

## Multi-tenancy: three walls

The most consequential contract in the base. Tenant isolation is enforced three times
over, and the order below is the fallback order when one layer fails:

1. **Gateway** — `tenant_id` is extracted from the JWT and injected as `X-Tenant-Id`.
   Business code cannot override it.
2. **Application** — every DB connection issues `SET LOCAL app.tenant_id` on acquire,
   scoped to the transaction.
3. **Data** — PostgreSQL row-level security filters every query, with
   `FORCE ROW LEVEL SECURITY` so even table owners are subject to it.

The result: business code that forgets `WHERE tenant_id = …` still cannot leak across
tenants, and even a SQL injection is confined to the current tenant.

Every tenant-scoped table must carry a `tenant_id` column, enable RLS + FORCE RLS, have a
composite index led by `tenant_id`, and define four policies (select/insert/update/delete).
Four database roles separate concerns — `app_user` (RLS-bound), `app_admin`,
`app_migrator` (the only role with `BYPASSRLS`) and `app_observability`. Business code
connecting as a superuser or a `BYPASSRLS` role is prohibited.

PgBouncer must run in transaction or session mode; statement mode breaks `SET LOCAL` and
is therefore banned.

Full contract and threat model: [docs/multi-tenancy.md](docs/multi-tenancy.md). Changes
here need two architect sign-offs and an ADR. `make test-rls-fuzz` runs cross-tenant
escalation fuzzing against every package.

---

## Who uses this

[**cloud·worker**](https://github.com/chenzefeng09/cloud-worker) — an enterprise AI agent
platform (sandboxed agent runs, reusable Apps, skills, MCP, knowledge) — is built entirely
on this base. It owns everything agent-shaped; saas-foundation owns identity, authz, org,
billing, audit, LLM gateway, storage, crypto, DLP and feature flags underneath it.

That split is worth reading if you're evaluating this base for your own product: see
[cloud·worker's "Relationship with saas-foundation"](https://github.com/chenzefeng09/cloud-worker#relationship-with-saas-foundation).

> **Note for external users:** `foundation-sdk` is not published to public PyPI yet.
> Consumers install it from an internal index or, in development, from a sibling checkout
> of this repository. See [docs/sdk-release.md](docs/sdk-release.md).

---

## Repository layout

```
saas-foundation/
├── packages/           17 capability services + the storage library
├── sdks/
│   ├── python/         complete — FoundationClient, CookieSigner, FastAPI helpers
│   ├── typescript/     partial
│   └── go/             placeholder
├── contracts/
│   ├── openapi/        OpenAPI 3.1 spec per service + shared components
│   ├── opa-bundles/    OPA policy bundles
│   └── proto/          gRPC definitions
├── deploy/
│   ├── docker-compose/ local dev stack
│   ├── helm/           umbrella chart, small/medium/large profiles
│   └── offline-bundle/ air-gapped install packaging
├── docs/
│   ├── CONVENTIONS.md  the architecture contract — read this first
│   ├── design/         per-service design docs
│   └── adr/            architecture decision records
├── tests/
│   ├── conformance/    self-check suite for applications adopting the base
│   ├── integration/    cross-service
│   ├── e2e/
│   └── security/       RLS escalation fuzzing
└── tools/              CI and dev tooling
```

---

## Quick start

**Prerequisites:** Docker with Compose v2, Python 3.12, Poetry.

```bash
git clone https://github.com/chenzefeng09/saas-foundation.git
cd saas-foundation
```

Bring the whole dev stack up — infrastructure, services, initialisation and health checks
in one shot:

```bash
make up-full
```

That runs `make up` (copies `.env.example` to `.env` if missing, starts Postgres,
Keycloak, ClickHouse, OpenSearch, Vault, MinIO, OPA, Unleash and the services), waits for
containers to become ready, runs `post-up-init` (Vault transit keys, MinIO buckets,
Keycloak organizations) and then health-checks everything.

Seed test data — a dev tenant and test users:

```bash
make seed
```

Useful targets:

```bash
make ps
```

```bash
make logs SVC=keycloak
```

```bash
make healthcheck
```

```bash
make down
```

`make nuke` stops everything **and deletes the volumes** — unrecoverable.

More detail: [docs/dev-quickstart.md](docs/dev-quickstart.md).

---

## Using the SDK

Applications depend on `foundation_sdk` rather than on individual services:

```python
from foundation_sdk import FoundationClient, FoundationClientSettings, tenant_context

client = FoundationClient(FoundationClientSettings(...))

with tenant_context("tnt_..."):
    decision = await client.authz.check(user_id=..., action="document.read",
                                        resource_type="document")
```

For FastAPI applications the SDK also supplies the middleware layer — request-context
propagation, RFC 9457 problem+json handlers, and tenant/user extraction:

```python
from foundation_sdk.fastapi import (
    install_request_context, register_problem_details, get_tenant_id, get_user_id,
)

install_request_context(app, service_name="my-service", service_version="1.0.0")
register_problem_details(app)
```

Signed session cookies (for a BFF) come from `CookieSigner` / `CookieSignerSettings`.

Version policy and upgrade procedure: [docs/sdk-release.md](docs/sdk-release.md).

---

## Development

```bash
make lint          # ruff check + mypy across every package
```

```bash
make test          # pytest across every package
```

```bash
make test-rls-fuzz # cross-tenant escalation fuzzing (tests/security/)
```

```bash
make migrate       # alembic upgrade head, as app_migrator
```

Security and supply chain:

```bash
make scan          # gitleaks + semgrep + license check
```

```bash
make sbom          # CycloneDX + SPDX
```

Policy work:

```bash
make opa-test      # OPA policy unit tests
```

Helm:

```bash
make helm-lint     # lint all three profiles
```

Before writing any code, read [docs/CONVENTIONS.md](docs/CONVENTIONS.md) — it governs
service naming, package structure, API versioning, error handling and SDK shape. PRs that
violate it are not merged.

---

## Deployment

**Local development** — docker-compose, as above.

**Kubernetes** — a Helm umbrella chart with three profiles:

| Profile | Intended for |
|---|---|
| `small` | Single-node / edge / PoC |
| `medium` | Standard production, moderate HA |
| `large` | Full HA and horizontal scale |

```bash
make helm-render PROFILE=medium
```

**Air-gapped** — `deploy/offline-bundle/` packages images and charts for environments
with no outbound network access, the default assumption for private-cloud delivery.

---

## Compliance

Compliance is treated as a design input rather than a certification exercise bolted on
afterwards.

- **MLPS 2.0 Level 3** (GB/T 22239-2019) — self-assessment maps 176 of 211 technical
  controls (83%) and 58 of 70 management controls (83%) onto base capabilities. See
  [docs/equal-protection-checklist-v1.md](docs/equal-protection-checklist-v1.md), and
  [the Level 4 gap analysis](docs/equal-protection-level4-gap-v1.md).
- **PIPL** — consent management, cross-border transfer records, DSAR and ROPA are handled
  by `compliance` and `data-protection`.
- **Domestic hardware and OS** — ARM64 (Kunpeng 920, Phytium FT-2000/4 and S2500) and
  x86_64 (Hygon, Zhaoxin) are adapted; LoongArch is planned. See the
  [localization deployment guide](docs/xinchuang-deployment-guide-v1.md).
- **Audit evidence** — the `audit` service produces a hash-chained, digitally signed,
  WORM-stored log; RLS is a database-enforced control that can be demonstrated to an
  auditor rather than argued.

SOC 2 and ISO 27001 alignment is planned, not claimed.

---

## Documentation

| Topic | Document |
|---|---|
| **Architecture contract — start here** | [docs/CONVENTIONS.md](docs/CONVENTIONS.md) |
| Multi-tenancy and RLS baseline | [docs/multi-tenancy.md](docs/multi-tenancy.md) |
| Error codes and handling | [docs/errors.md](docs/errors.md) |
| Local dev quickstart | [docs/dev-quickstart.md](docs/dev-quickstart.md) |
| SDK release and upgrade policy | [docs/sdk-release.md](docs/sdk-release.md) |
| Per-service design docs | [docs/design/](docs/design/) |
| Helm chart | [deploy/helm/README.md](deploy/helm/README.md) |
| OpenAPI contracts | [contracts/openapi/](contracts/openapi/) |

Several design documents are written in Chinese.

---

## Contributing

- Read [docs/CONVENTIONS.md](docs/CONVENTIONS.md) first. It is a contract, not a style
  guide.
- Keep `make lint` and `make test` green.
- Schema changes touching tenant-scoped tables must satisfy
  [docs/multi-tenancy.md](docs/multi-tenancy.md) and pass `make test-rls-fuzz`.
- Changes to the multi-tenancy baseline or to CONVENTIONS need two architect sign-offs and
  an ADR under `docs/adr/`.
- Changes that cross the saas-foundation / consumer boundary need a matching PR in the
  consuming repository — say so in the description.
- Contributions are accepted under Apache 2.0.

---

## License

Licensed under the **Apache License, Version 2.0** — see [LICENSE](LICENSE).

```
Copyright 2026 The saas-foundation Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

The open-source components this base wraps — Keycloak, OPA, PostgreSQL, Redis,
ClickHouse, OpenSearch, Vault, MinIO, Unleash, LiteLLM — remain under their own licenses.
