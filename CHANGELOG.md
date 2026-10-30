# Changelog

All notable changes to SaaS Foundation are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Golden SDK requests** in `contracts/sdk/`. Both SDK suites check that
  every public method sends exactly its pinned request. Every service suite
  checks that the request reaches a route that accepts it and that the
  contract documents it. `.github/workflows/sdk-ci.yml` runs both SDK suites
  on pull requests.

### Changed
- **Breaking:** `foundation-sdk` and `@foundation/sdk` 1.0.0. Every method now
  sends the request its service serves. Six methods with no route behind them
  are removed and seventeen change signature. The lifecycle resource gains the
  four-eyes approval requests, and its hard-delete and legal-hold release now
  wait for a second user's approval. See
  [ADR 0001](docs/adr/0001-sdk-1-0-follows-served-routes.md).
- org: `GET /org-units` and `GET /teams` filter by `filter.parent_id` and
  `filter.org_unit_id`, as the contract documents. The bare names still work
  as deprecated aliases.
- Contracts: every operation the SDKs call documents its route as served.

### Fixed
- lifecycle: a restore sent with `{}` or `{"restored_by": null}` records the
  caller as the restorer instead of NULL.

[Unreleased]: https://github.com/chenzefeng09/saas-foundation/compare/v0.1.0...HEAD

## [0.1.0] - 2026-06-15

First public release of SaaS Foundation — a reusable, multi-tenant enterprise
base that any business system can build on (it is the foundation the
[Agent Platform](https://github.com/chenzefeng09/agent-platform) is built upon).

### Added

- **18 capability services**, each an independent, single-purpose service
  following the project conventions (`/api/<service>/v1`, `snake_case` JSON,
  four-segment error codes): identity, authz, org, crypto, audit, lifecycle,
  dlp, data-protection, notification, search, opa-bundle, scim-dingtalk, pam,
  feature-flag, compliance, billing, api-platform, and llm-gateway.
- **Contract-first OpenAPI 3.1** as the single source of truth: 18 specs in
  `contracts/openapi/`, Spectral-linted under six machine-enforced rules, with
  an `oasdiff` breaking-change gate on every change.
- **Python and TypeScript SDKs** generated from and versioned against the
  contracts. `foundation-sdk` (Python) exposes a `FoundationClient.from_env()`
  aggregating 17 resource groups plus an optional FastAPI request-context /
  problem-details extra; `@foundation/sdk` (TypeScript) mirrors the same surface
  1:1 (fetch-based, dual ESM/CJS, zero runtime dependencies). A Go SDK is
  planned and not yet generated.
- **Multi-tenant isolation built on PostgreSQL Row-Level Security.** Three
  enforcement walls — gateway-injected `X-Tenant-Id`, transaction-scoped
  `SET LOCAL app.tenant_id`, and `FORCE ROW LEVEL SECURITY` policies — with
  least-privilege DB roles (`NOBYPASSRLS` application roles), PgBouncer pinned to
  transaction-pool mode, and a mandatory RLS cross-tenant fuzz-test gate
  (`make test-rls-fuzz`) for every tenant table.
- **Authorization** combining Keycloak OIDC with OPA (RBAC + ABAC), using
  crypto-service-signed OPA policy bundles with shadow → canary → 100% rollout,
  a global kill switch, and one-click rollback.
- **Single crypto boundary.** A dedicated crypto-service providing envelope
  encryption (MasterKey → KEK → DEK) over a Vault transit / PKCS#11 HSM backend,
  with 90-day KEK rotation.
- **Tamper-evident audit.** Structured audit events to ClickHouse, archived to
  S3/MinIO WORM storage, with a signed hash chain and chain-integrity
  verification.
- **Compliance baseline targeting 等保 2.0 三级 (DJCP / MLPS level 3) and PIPL**,
  including a compliance-mode source of truth, ROPA/DPIA/DSAR workflows, an
  equal-protection self-assessment checklist, optional 国密 (SM2/SM3/SM4 + GMTLS)
  crypto, `cn-only` data-residency enforcement, and SOC 2 / ISO 27001 evidence
  export.
- **Helm umbrella chart with small / medium / large profiles** (the same chart
  switched by `values-<profile>.yaml`), private-cloud-first / offline-oriented,
  and SaaS-compatible by profile. A `信创` (domestic-stack) profile overlay
  targets ARM64 (Kunpeng / Phytium) on Kylin / UOS with domestic-DB substitution.
- **Local development stack** via docker-compose (PostgreSQL, PgBouncer, Redis,
  Keycloak, ClickHouse, OpenSearch, Vault, MinIO, OPA, Unleash, OpenTelemetry
  Collector + Jaeger, Mailhog) driven by a top-level Makefile (`make up-full`,
  `make migrate && make seed`, `make test-rls-fuzz`).
- **Supply-chain / SSDLC security gates:** gitleaks (secrets), semgrep (SAST,
  incl. OWASP Top Ten), pip-licenses (GPL / AGPL / LGPL banned), and syft SBOM
  (CycloneDX + SPDX).
- **Project and contributor documentation:** the binding `docs/CONVENTIONS.md`
  contract, the `docs/multi-tenancy.md` RLS baseline, per-service design docs,
  and compliance / 信创 checklists.

### Notes

- This is a pre-1.0 release. APIs and SDKs are governed by the semantic-version
  and compatibility policy in [`docs/CONVENTIONS.md`](./docs/CONVENTIONS.md) §5;
  breaking changes before 1.0 may occur on minor bumps and will be noted here.

[0.1.0]: https://github.com/chenzefeng09/saas-foundation/releases/tag/v0.1.0
