# Project governance

This document describes how the SaaS Foundation project is run: who makes
decisions, how decisions are recorded, how contributors grow into maintainers,
and how releases and SDK versions are managed. It complements
[CONTRIBUTING.md](./CONTRIBUTING.md) (how to contribute) and the binding
[`docs/CONVENTIONS.md`](./docs/CONVENTIONS.md) (what the contributions must
satisfy).

## Governance model

SaaS Foundation uses a **maintainer-led** model. A small group of maintainers is
collectively responsible for the project's technical direction, the integrity of
its contracts and isolation guarantees, releases, and community health.

- Most changes are decided through ordinary pull-request review: a change merges
  once a maintainer approves it and the required CI gates pass.
- Decisions are made by **lazy consensus** — a proposal that draws no sustained
  objection from maintainers proceeds. When maintainers disagree and consensus
  cannot be reached through discussion, the matter is resolved by a simple
  majority vote of the maintainers; ties are decided by the project lead.
- Changes that affect the architecture, the public API contracts, the
  multi-tenancy/isolation model, or the security posture require explicit
  maintainer sign-off and an Architecture Decision Record (see below). Per
  CONVENTIONS, convention changes require review by at least two maintainers.

The current maintainers are listed in `MAINTAINERS.md` (or the GitHub
repository's permissions) once that file is established.

## Decisions and ADRs

Significant or hard-to-reverse decisions are recorded as **Architecture Decision
Records (ADRs)** in [`docs/adr/`](./docs/adr/), so the reasoning behind the
project's shape stays discoverable instead of living only in a reviewer's head.

Write an ADR when a change:

- alters or deviates from [`docs/CONVENTIONS.md`](./docs/CONVENTIONS.md) (service
  naming, URL/versioning, error model, tenant-context rules);
- changes the multi-tenancy / RLS isolation model
  ([`docs/multi-tenancy.md`](./docs/multi-tenancy.md));
- introduces or replaces a core technology (datastore, IdP, policy engine,
  crypto backend);
- makes a breaking API or SDK change;
- otherwise sets a precedent future contributors should follow.

Process:

1. Copy the established ADR template (or follow the format of an existing ADR)
   into `docs/adr/NNNN-<short-title>.md`, numbered sequentially.
2. Capture **context**, the **decision**, the **alternatives considered**, and
   the **consequences**. Keep it short and factual.
3. Open it as a pull request and let maintainers review. Status moves
   `Proposed → Accepted` (or `Rejected`); superseded ADRs are marked
   `Superseded by NNNN` rather than deleted, preserving the history.

> **Status:** [ADR 0001](./docs/adr/0001-sdk-1-0-follows-served-routes.md) is the
> first ADR; its numbering and layout are the template later ADRs follow.

## Contribution ladder

Roles are earned through sustained, high-quality participation. There is no
fixed timeline — the path is about demonstrated judgment and trust.

| Role | What it means | How you get there |
|---|---|---|
| **Contributor** | Anyone who opens an issue or PR. | Just contribute — see [CONTRIBUTING.md](./CONTRIBUTING.md). |
| **Reviewer** | Trusted to give meaningful review on an area; reviews are weighed heavily by maintainers. | A track record of quality contributions and reviews in that area; proposed by a maintainer. |
| **Maintainer** | Commit/merge rights; shares responsibility for direction, releases, and security. Can approve merges and cast governance votes. | Sustained reviewer-level work plus demonstrated care for the contracts and isolation guarantees; nominated and approved by existing maintainers. |
| **Project lead** | Breaks ties, is the final escalation point, and stewards overall direction. | Designated from among the maintainers. |

Maintainers who become inactive for an extended period may be moved to emeritus
status by agreement of the active maintainers; emeritus maintainers are welcome
to return.

## Release and versioning policy

### Project releases

The foundation as a whole is versioned with **semantic versioning**
(`MAJOR.MINOR.PATCH`), following the compatibility rules in CONVENTIONS §5:

- **PATCH / MINOR** are fully forward-compatible — no field removals, no
  semantic changes, no new required fields, and only additive enum/endpoint
  changes.
- **MAJOR** may contain breaking changes; these ship with a migration guide and
  a dual-write/overlap window, and a public API version is bumped to `v2` only
  on a breaking change (the previous API version is maintained for at least
  12 months).
- Each service carries its own version but follows the foundation's MAJOR;
  MINOR/PATCH evolve independently per service.

Notable changes are recorded in [CHANGELOG.md](./CHANGELOG.md) following the
"Keep a Changelog" format.

### Contract and breaking-change gate

Because the OpenAPI specs in [`contracts/openapi/`](./contracts/openapi/) are the
source of truth, API compatibility is **machine-enforced**: CI runs `oasdiff`
(`make diff-base`) on every PR and blocks any breaking change unless the author
bumps the major version and adds a `BREAKING:` commit footer. See
[CONTRIBUTING.md](./CONTRIBUTING.md#contract-first-openapi-workflow).

### SDK semver policy

The Python (`foundation-sdk`) and TypeScript (`@foundation/sdk`) SDKs are
generated from and versioned against the contracts (CONVENTIONS §5.3):

- An SDK's version is the corresponding API **MAJOR** plus an independently
  evolving MINOR.PATCH; the SDK MAJOR moves only when the API it targets makes a
  breaking change.
- SDKs are forward-compatible within a MAJOR. On initialization the SDK checks
  the server `/healthz` version and **fails fast** if it is incompatible.
- The Python and TypeScript surfaces are kept 1:1 in sync. (A Go SDK is on the
  roadmap and not yet generated.)

The SDK build, version-bump, and publish mechanics — including offline tarballs
shipped alongside the Helm chart for private-cloud customers — are documented in
[`docs/sdk-release.md`](./docs/sdk-release.md) and driven by the `make sdk-*`
targets.

## Changing this document

This governance document evolves with the project. Amendments are themselves a
significant decision: propose changes via pull request, and merge them with
maintainer consensus (recording the rationale in an ADR when the change is
substantive).

---

## 中文摘要

SaaS Foundation 采用 **maintainer 主导**的治理模式。日常变更通过 PR 评审决策：
maintainer 批准且 CI 门禁通过即可合并；决策以 **lazy consensus** 为主，分歧无法
达成共识时由 maintainer 简单多数表决，平票由 project lead 决定。涉及架构、公共 API
契约、多租户/隔离模型或安全姿态的变更，须 maintainer sign-off 并补
**架构决策记录（ADR）**，写入 [`docs/adr/`](./docs/adr/)（编号与模板以第一条
[ADR 0001](./docs/adr/0001-sdk-1-0-follows-served-routes.md) 为准）。

贡献阶梯为 Contributor → Reviewer → Maintainer → Project lead，按持续的高质量
贡献与评审晋升，由现任 maintainer 提名通过。

发布遵循语义化版本（CONVENTIONS §5）：MINOR/PATCH 完全前向兼容，MAJOR 才允许
破坏并提供迁移指南；老 API 版本至少维护 12 个月。OpenAPI 契约的破坏性变更由
`oasdiff`（`make diff-base`）机器门禁强制。SDK（Python `foundation-sdk` /
TypeScript `@foundation/sdk`）版本对齐对应 API 的 MAJOR，初始化时校验服务端
`/healthz` 版本，不兼容则 fail-fast；Python 与 TypeScript 接口保持 1:1（Go SDK
规划中）。发布机制详见 [`docs/sdk-release.md`](./docs/sdk-release.md)。变更记录见
[CHANGELOG.md](./CHANGELOG.md)。
