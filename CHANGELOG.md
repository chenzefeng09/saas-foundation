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
- lifecycle: **four-eyes approvals** for a manual hard-delete or legal-hold
  release. Asking opens an approval request. A user other than the
  requester carries it out with `POST /approval-requests/{id}/approve`
  (the requester gets 403 `SELF_APPROVAL_FORBIDDEN`), `/reject` turns it
  down or withdraws it, and `GET /approval-requests` lists them. A request
  nobody decides within `LIFECYCLE_APPROVAL_WINDOW_MINUTES` (default 30)
  expires.
- llm-gateway: a job (hourly by default,
  `LLM_GATEWAY_EPHEMERAL_KEY_PURGE_CRON`) deletes ephemeral run keys once
  they have been expired for `LLM_GATEWAY_EPHEMERAL_KEY_PURGE_GRACE_HOURS`
  (default 168).
- llm-gateway: `GET` and `DELETE /users/{user_id}/preferences` let ADMIN and
  SERVICE callers export and erase a member's model preferences.
- authz: `GET /bindings` takes `filter.status`, and its items carry `status`,
  `revoked_by` and `revoked_reason`. `bootstrap_tenant_roles.py` gains
  `--bind-user` and `--restore-revoked`.
- audit: `POST /events:verify-integrity` pages with `cursor` and
  `next_cursor`. Its response says per chain where the check started
  (`chains`: `genesis`, `previous_event` or `predecessor_not_retained`) and
  counts the Merkle batches it could prove neither intact nor tampered
  (`signatures_unverifiable`).
- dlp: `GET /core/events` and `GET /core/classifications` take `cursor` and
  return `next_cursor`.
- Contract lint warns when an operation does not declare `X-Request-Id`.

### Changed
- **Breaking:** `foundation-sdk` and `@foundation/sdk` 1.0.0. Every method now
  sends the request its service serves. Six methods with no route behind them
  are removed and seventeen change signature. The lifecycle resource gains the
  four-eyes approval requests, and its hard-delete and legal-hold release now
  wait for a second user's approval. See
  [ADR 0001](docs/adr/0001-sdk-1-0-follows-served-routes.md).
- **Breaking:** lifecycle: `POST /recycle-bin/{bin_id}:hard-delete` and
  `POST /legal-holds/{hold_id}:release` no longer act at once. They answer
  202 with an approval request, and nothing is destroyed or released until a
  second user approves it.
- org: `GET /org-units` and `GET /teams` filter by `filter.parent_id` and
  `filter.org_unit_id`, as the contract documents. The bare names still work
  as deprecated aliases.
- Contracts: every operation the SDKs call documents its route as served.
- audit: `audit.events` rows expire 90 days after `ingested_at`, which
  follows chain order, instead of `occurred_at`, so a chain loses its
  oldest events first. `verify-integrity` leaves out events within a day of
  expiry (`AUDIT_EVENTS_TTL_DAYS`, 90 like the TTL).
- audit: the worker seals one Merkle batch per chain (tenant and service),
  signed under that tenant's key, instead of one batch across tenants.
- llm-gateway: `GET /tenant-keys` lists only enabled, unexpired keys that are
  not ephemeral, oldest first.
- CI runs security-ops, which `ci.yml` left out, in the quick checks and as
  its own batch with the 80% coverage gate.
- Contract lint: every error response must come from `_common.yaml`
  (README rule 3), every spec with paths needs a root `security`
  requirement, and SCIM resources keep their RFC 7643 attribute names
  instead of failing the snake_case rule.

### Deprecated
- lifecycle: the `restored_by`, `destroyed_by`, `witness_user_id` and
  `released_by` body fields, which are ignored.
- audit: `from_event_id` on `POST /events:verify-integrity`; send the last
  call's `next_cursor` as `cursor`.
- dlp: `before` and `next_before` on `GET /core/events` and
  `GET /core/classifications`, now aliases of `cursor` and `next_cursor`.

### Fixed
- Cursor paging skipped or repeated rows. Lists handed out the lookahead
  row's id as the next cursor, or resumed on a key their sort did not
  follow: identity users and platform tenants and users, org teams and org
  units, authz bindings and roles, lifecycle legal holds and recycle bin,
  audit `POST /events:query` and `:export`, and the dlp governance lists.
  lifecycle, audit and dlp now page on the full sort key with opaque
  cursors, and answer 422 to a cursor they did not issue, such as an old
  bare id or timestamp.
- lifecycle: `GET /legal-holds` filters by `filter.resource_type` and
  `filter.resource_id`. It returned every active hold of the tenant.
- identity: sessions ended after 5 minutes instead of the absolute session
  timeout (8 h by default). A refresh that fails on Keycloak (502/503) can
  be retried with the same token. A correct password on an account with
  required actions pending answers 401
  `FOUNDATION.IDENTITY.AUTH.ACCOUNT_SETUP_REQUIRED` and does not count as a
  failed attempt, and an expired password can be changed.
- audit: datetimes reach ClickHouse as their exact UTC instant. Events were
  stored off by the host's UTC offset, and by their own offset when not in
  UTC, and `occurred_from` / `occurred_to` lost their milliseconds.
- audit: `verify-integrity` reported breaks in chains nobody had touched.
  The worker and verify now hash the same canonical event and read a chain
  in the order it was chained, the worker moves a chain head on only once
  ClickHouse holds the batch, each Merkle batch a window touches is checked
  whole, and `first_break_event_id` names an event, not a leaf hash.
- dlp: `/core/scan` refused every caller but SERVICE and ADMIN with 403. Any
  caller with a tenant context now gets the verdict; only SERVICE and ADMIN
  callers update the resource's classification label.
- dlp: `classification.updated_at`, `dlp_rule.created_at` and
  `dlp_event_outbox.occurred_at` are NOT NULL, as the models declare. A NULL
  `updated_at` made classification paging fail with a 500.
- llm-gateway: minting an ephemeral key checks `run_id` (1-64 characters)
  and an explicit `provider_id` (404 `PROVIDER_NOT_FOUND`), and without one
  binds the tenant's oldest enabled provider rather than an arbitrary one.
- authz: re-running `bootstrap_tenant_roles.py` no longer revives a binding
  an admin revoked, and `GET /bindings` leaves revoked bindings out unless
  `filter.status` asks for them.
- Python SDK: `foundation_sdk.__version__` stays importable without being
  listed in `__all__` (conformance check C2-g).
- security-ops: the image installs the package itself.
- Contracts: `audit.yaml` parses again, and `verify-integrity` documents what
  the route serves.
- Contracts: `scim-dingtalk` paths no longer repeat the version
  (`/scim/v2/Users`, not `/scim/v2/v1/Users`).
- Contracts: `_common.yaml`'s `Error.code` pattern accepts the shared
  `FOUNDATION._.<CAT>.<NAME>` codes that errors.md §12 registers.
- Contract lint: CI's contract-check could not fail (its missing-spec fallback
  also swallowed every Spectral error), and it used a second ruleset whose
  `/vN`-in-path rule contradicted CONVENTIONS §2.2. It now runs
  `contracts/openapi/.spectral.yaml`, as `make lint` does (that ruleset did
  not load), with Spectral 6.17.0 pinned, and fails on errors.
- A request without tenant context (no `X-Tenant-Id`) gets an RFC 9457 `401`
  with `FOUNDATION.<SVC>.AUTH.TENANT_CONTEXT_MISSING` instead of FastAPI's
  `{"detail": ...}`, in api-platform, audit, authz, billing, compliance,
  crypto, data-protection, dlp, feature-flag (user overrides), identity,
  lifecycle, llm-gateway, notification, org, pam and search. feature-flag's
  user overrides without a user get
  `FOUNDATION.FEATURE_FLAG.AUTH.USER_CONTEXT_MISSING`, and lifecycle's
  missing-scope `403` is `FOUNDATION.LIFECYCLE.POLICY.INSUFFICIENT_SCOPE`.
- Contracts: llm-gateway's `POST /tenant-keys/ephemeral` and
  `POST /tenant-keys/revoke-run` document their `401` as `_common.yaml`'s
  `Unauthorized`, which is what the service sends.
- Local stack: seed users can sign in again after the realm's 90-day
  password expiry (a keycloak-init job resets them on every `up`), web
  sessions can refresh, services get the env names they read, and
  `minio-init` runs on the MinIO server image.

### Security
- lifecycle: restore, hard-delete and release record the authenticated
  caller (`X-User-Id`) as who acted. They took that person from the body,
  so any caller could put someone else into the retention and destruction
  trail. The approver of a hard-delete is the certificate's witness.
- **Breaking:** llm-gateway: `POST /tenant-keys/ephemeral` and
  `/tenant-keys/revoke-run` serve SERVICE callers only, and a caller proves
  SERVICE with `X-Internal-Service-Token` instead of claiming it with
  `X-Actor`. Anything else gets 403, and an unproven `X-Actor: SERVICE`
  counts as USER on every route.
- security-ops: the session context reaches Postgres through `set_config()`
  bind parameters instead of f-string `SET LOCAL`, and an `X-Actor` that is
  not an `ActorKind` gets 400.
- authz: `bootstrap_tenant_roles.py` passes the tenant id to `set_config()`
  as a bound parameter instead of formatting it into `SET LOCAL`.

### Notes
Upgrading from 0.1.0:
- Run the new migrations: lifecycle 0007, llm-gateway 0005, dlp 0004 and
  0005.
- Give the llm-gateway and its SERVICE callers the same
  `LLM_GATEWAY_INTERNAL_SERVICE_TOKEN`. Compose takes it from
  `LLM_GATEWAY_SERVICE_TOKEN`, Helm from the optional
  `foundation-llm-gateway-service-token` secret. Left empty, the gateway
  proves no caller SERVICE, so nothing can mint or revoke run keys.
- An existing `audit.events` table keeps its old TTL until it is given the
  new one, and `AUDIT_EVENTS_TTL_DAYS` must match whatever TTL it has:
  `ALTER TABLE audit.events MODIFY TTL toDateTime(ingested_at) + INTERVAL 90 DAY DELETE`.
- Lifecycle hard-delete and legal-hold release need a second user, and admin
  UIs that call them must handle the 202 and the approval requests.

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
