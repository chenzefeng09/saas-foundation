# Deployment

SaaS Foundation ships as a single **Helm umbrella chart** (`deploy/helm/foundation`)
that deploys all Foundation services together. You choose a **profile** by
selecting a values file; the chart body itself does not change between profiles.

```bash
helm install foundation . -f values-<profile>.yaml
```

The design target is **private-cloud first** — the customer's own data center,
Kubernetes 1.24+, with offline (air-gapped) install as a first-class path — and
**SaaS-compatible** through the same chart by switching the profile and tenant
isolation mode.

For chart internals (directory layout, dependency subcharts, upgrade/rollback,
the externalization checklist), see
[`deploy/helm/README.md`](../deploy/helm/README.md). For local development, see
[getting-started.md](./getting-started.md).

> The Agent Platform (https://github.com/chenzefeng09/agent-platform) deploys on
> top of a running Foundation. It has its own Helm chart with a Foundation
> subchart dependency and reuses these same small/medium/large profile names.

---

## Deployment profiles

The three sizing profiles differ only in their values file
(`-f values-{small|medium|large}.yaml`):

| | **small** | **medium** | **large** |
|---|---|---|---|
| Target | POC / demo / ≤50 users | Enterprise private cloud, 100–500 users | Cross-AZ, 1000+ users / SaaS master cluster |
| Nodes | 1–3 (K3s) | 3–10 (K8s), HA | 20+ across zones, HA+ |
| Third-party deps | All embedded in-cluster | External or customer-shared | All external (customer-provided) |
| Replicas | 1 | 3+, HPA | 5+ (e.g. authz 8, audit 10, llm-gateway 10, search 6), HPA + custom metrics |
| HA | ❌ | ✅ | ✅ + topology spread, PDB `minAvailable: 3` |
| mTLS | off | cert-manager + self-signed CA | cert-manager + self-signed CA |
| PgBouncer | embedded | **mandatory** standalone (transaction pool mode) | standalone (transaction pool mode) |
| Autoscaling | none | HPA | HPA + custom-metric scaling |
| Pod hardening | baseline | baseline | `runAsNonRoot`, drop ALL caps, `readOnlyRootFilesystem`, NetworkPolicy |
| Baseline resources | 8C / 32G / 500GB single node | ~32C / 128G | elastic |
| Compliance defaults | — | — | `pipl` + `equal_protection_3` + `soc2` (opt-in `equal_protection_4` / `finance_jrt0071`) |

Switching profiles is purely a values change — **the chart body stays the same**.

### small — POC / single-node K3s

All open-source dependencies (Postgres, Redis, Keycloak, ClickHouse, OpenSearch,
Vault in dev mode, MinIO) are embedded and enabled. One replica, no HA, no mTLS,
no autoscaling, Traefik ingress, TLS off.

```bash
cd deploy/helm/foundation
helm dependency update            # pull the third-party subcharts
helm install foundation . \
    -f values-small.yaml \
    -n foundation --create-namespace

# watch rollout
kubectl -n foundation get pods -w

# health gate
helm test foundation -n foundation
```

### medium — enterprise private cloud / HA

3+ replicas with HPA, HA, mTLS via cert-manager, secrets injected from Vault or
External Secrets, and a **mandatory standalone PgBouncer** in transaction pool
mode. Third-party components are external or shared with the customer's existing
infrastructure (`enabled: false` for embedded deps; you supply
`global.database.host` and friends).

```bash
helm upgrade --install foundation . \
    -f values-medium.yaml \
    -n foundation --create-namespace
```

### large — cross-AZ / SaaS master cluster

All third-party components are external/customer-provided (Postgres, Redis,
Keycloak, ClickHouse, OpenSearch, Vault, MinIO, Unleash all `enabled: false`;
external S3/OSS with object-lock buckets). 5+ replicas with HPA plus
custom-metric scaling, PodDisruptionBudgets, topology spread across zones, a
hardened pod security context, and NetworkPolicies. Default compliance modes are
`pipl` + `equal_protection_3` + `soc2`, with `equal_protection_4` and
`finance_jrt0071` available opt-in.

```bash
helm upgrade --install foundation . \
    -f values-large.yaml \
    -n foundation --create-namespace
```

> **medium / large notes:** never write passwords into a values file — reference
> a Secret populated from Vault / External Secrets. Verify `storageClassName`
> matches the customer's CSI, and keep PgBouncer in transaction pool mode (a
> startup health check refuses to boot otherwise, because `SET LOCAL` tenant
> context would leak across pooled connections). See
> [`deploy/helm/README.md`](../deploy/helm/README.md) and
> [multi-tenancy.md](./multi-tenancy.md).

Upgrade and rollback follow standard Helm:

```bash
helm upgrade  foundation . -f values-<profile>.yaml -n foundation
helm rollback foundation -n foundation        # roll back to the previous revision
helm history  foundation -n foundation
```

---

## Private cloud / offline (air-gapped)

Private cloud is the **design default**. The deliverable is the `foundation`
umbrella Helm chart plus an offline bundle of everything the cluster needs to
install without internet access.

- **Offline bundle** (`deploy/offline-bundle/`) — *planned*; it packages all
  image tarballs + the Helm chart + CRDs for an air-gapped install. The SDK
  offline tarballs (Python wheel/sdist, TypeScript tgz) ship alongside the chart
  so downstream business systems can consume the SDK without a package index.
- **Credentials** are injected via Vault or Kubernetes External Secrets — never
  baked into values files.
- **mTLS** is provided by cert-manager with a self-signed CA.
- **Image registry** — mirror the bundled images into the customer's internal
  registry and override the image repositories in your values file before
  install.

The umbrella chart and docker-compose dev stack pin the **same** versions of the
underlying engines (Postgres 16, Keycloak 25, ClickHouse 24.8, etc.) so the
offline bundle matches what was developed and tested.

---

## SaaS multi-tenant profile

The same chart serves SaaS by switching the profile (typically **large**) and
choosing a per-tenant isolation mode. RLS stays **enabled in every tier** —
isolation modes layer *additional* separation on top of it, never replace it.

SaaS plan tiers map to isolation modes as follows (see
[multi-tenancy.md](./multi-tenancy.md) §11 and the
[`saas-isolation-routing-v1`](./design/saas-isolation-routing-v1.md) design):

| SaaS tier | Isolation mode | RLS role |
|---|---|---|
| Free / Pro | Shared DB + shared tables | RLS is the **only** isolation boundary |
| Business | Schema-per-tenant (`search_path` switch) | RLS as a double-insurance layer |
| Enterprise | Database-per-tenant | RLS retained per database |
| Dedicated | Isolated cluster / database | RLS retained |

The `tenant_router` resolves a per-tenant DSN (`resolve_dsn`) so a request lands
on the correct database/schema, and RLS then filters rows by
`current_setting('app.tenant_id')` regardless of tier. Because RLS is never
disabled, a business-code bug (or even a SQL injection) cannot cross tenants.

---

## 信创 / 国密 (domestic-stack) profile

For domestic-stack (Xinchuang) and 国密 (Chinese commercial cryptography)
deployments, layer a `values-xinchuang.yaml` overlay over the small or medium
profile. Full hardware/OS compatibility, algorithm, and domestic-DB details are
in the [Xinchuang deployment guide](./xinchuang-deployment-guide-v1.md).

> The 信创 overlay values file (`values-xinchuang.yaml`) is part of the v1.1
> roadmap; today the chart ships the `small`/`medium`/`large` profiles, and the
> domestic-stack knobs below are applied as `--set` overrides (or your own
> overlay) on top of one of them.

```bash
helm upgrade --install foundation . \
    -f values-medium.yaml \
    -f values-xinchuang.yaml \
    --set global.dataResidency=cn-only \
    --set crypto.gmtls.enabled=true \
    --set crypto.provider=tongsuo_pkcs11 \
    -n foundation --create-namespace
```

Highlights:

- **Compliance modes** — `pipl` + `equal_protection_3`; data residency pinned to
  `cn-only` (overseas LLM providers and cross-border transfers are then
  rejected).
- **国密 cryptography** — GMTLS enabled, SM2/SM3/SM4 via **Tongsuo (铜锁)** as the
  primary provider behind a PKCS#11 HSM, with **GmSSL** as a fallback.
- **Multi-arch images** — `linux/amd64` and `linux/arm64` for Kunpeng 920 /
  Phytium (LoongArch planned, v1.2).
- **Domestic OS** — Kylin V10 / UOS V20.
- **Domestic databases** — swappable to KingbaseES / DM8 (PostgreSQL-compatible);
  K3s / RKE2 for the cluster.

> The 信创 profile is part of the v1.1 compliance roadmap (国密 + 信创); v1.0
> covers 等保 2.0 level 3 + PIPL. Treat items the guide marks as planned as
> roadmap, not shipped.

---

## Helm chart reference

This page covers the profiles and deployment shapes; for everything chart-level
— the directory layout, the third-party subchart dependencies, the
externalization checklist for medium/large, and upgrade/rollback details — see:

→ **[`deploy/helm/README.md`](../deploy/helm/README.md)**

Validate chart rendering locally before deploying:

```bash
make helm-lint                    # lint all three profiles
make helm-render PROFILE=medium   # render the umbrella chart to /tmp for inspection
```

---

## License

SaaS Foundation is licensed under **Apache-2.0**. See [LICENSE](../LICENSE) and
[NOTICE](../NOTICE).
