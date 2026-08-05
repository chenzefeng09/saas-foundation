English | [中文](#中文)

# Security policy

SaaS Foundation is a multi-tenant enterprise base that other systems trust for
identity, authorization, crypto, audit, and data protection. We take security
reports seriously and appreciate responsible disclosure.

## Supported versions

The project is pre-1.0; security fixes land on the latest `0.x` minor and the
`main` branch.

| Version | Supported |
|---|---|
| `0.1.x` | ✅ Yes (current) |
| `main` (unreleased) | ✅ Yes |
| `< 0.1.0` | ❌ No |

Once a `1.0` line is released, this table will be updated to name the maintained
release branches.

## Reporting a vulnerability

**Please do not open a public GitHub issue, pull request, or discussion for a
security vulnerability.** Public reports expose other users before a fix is
available.

Instead, report privately by email to **<chenzefeng09@gmail.com>** with the
subject prefixed `[SECURITY] saas-foundation`. Where possible include:

- a description of the issue and its impact (e.g. cross-tenant data exposure,
  authentication/authorization bypass, secret leakage, RLS escape);
- the affected service/package, version or commit, and configuration/profile;
- steps to reproduce or a proof of concept;
- any suggested remediation.

If you prefer encrypted email, say so in a first plain-text message and we will
exchange a key.

### Response timeline

| Stage | Target |
|---|---|
| Acknowledgement of your report | within **3 business days** |
| Initial assessment and severity triage | within **7 business days** |
| Fix or mitigation plan communicated | within **30 days** (sooner for critical issues) |
| Coordinated public disclosure | after a fix ships, by mutual agreement |

We will keep you informed throughout, credit you in the release notes and
`CHANGELOG.md` if you wish, and coordinate a disclosure date with you. Please
give us a reasonable window to remediate before any public discussion.

## Security & compliance model

Security in SaaS Foundation is a designed-in property, not an add-on. The
controls below are summarized here; the authoritative descriptions live in
[`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) and the binding multi-tenancy
contract [`docs/multi-tenancy.md`](./docs/multi-tenancy.md).

- **Multi-tenant isolation via three walls.** Tenant context is enforced end to
  end: the API gateway extracts `tenant_id` from the verified JWT and
  force-injects `X-Tenant-Id` (the client cannot override it); the app/DB
  adapter runs `SET LOCAL app.tenant_id` inside a transaction on every
  connection acquire; and PostgreSQL **Row-Level Security** (`ENABLE` + `FORCE
  ROW LEVEL SECURITY`, four policies per table) filters every row by
  `current_setting('app.tenant_id')`. The design holds even if business code
  forgets a `WHERE tenant_id` or a SQL injection is attempted. PgBouncer is
  pinned to transaction-pool mode (statement mode would leak `SET LOCAL` and is
  refused at startup), application DB roles are `NOBYPASSRLS`, and mandatory
  RLS cross-tenant fuzz tests gate every tenant table.
- **Single crypto boundary.** All cryptography goes through one
  `crypto-service`. It performs envelope encryption (MasterKey → KEK → DEK), the
  KEK never leaves the HSM/Vault, the default backend is the HashiCorp Vault
  transit engine behind a PKCS#11 HSM abstraction, KEKs rotate on a 90-day
  cycle, and key-destroy = data-destroy is gated by PAM just-in-time access with
  four-eyes approval.
- **OPA-signed authorization policy.** Authorization combines Keycloak OIDC with
  OPA (RBAC + ABAC). OPA policy bundles are **JWS-signed by the crypto-service**
  and rolled out shadow → canary → 100% with a global kill switch and one-click
  rollback.
- **Tamper-evident audit (WORM hash chain).** Every API call emits a structured
  audit event; events land in ClickHouse and are archived to S3/MinIO **WORM**
  storage. The audit service builds a **hash chain** and signs the roots
  (Ed25519 by default, SM2 in compliance mode), and exposes chain-integrity
  verification. Cross-tenant/system operations require an explicit
  `as_tenant()`/`SYSTEM` actor and are always audited.
- **Compliance posture (等保 2.0 / PIPL).** The baseline targets China's
  Multi-Level Protection Scheme (等保 / DJCP 2.0) **level 3** and the Personal
  Information Protection Law (**PIPL**), with `data-residency = cn-only`
  enforcement, optional 国密 (SM2/SM3/SM4 + GMTLS) crypto, and a compliance
  service that is the source of truth for the active compliance mode. SOC 2 /
  ISO 27001 evidence export is provided; level-4 and certain controls remain
  customer responsibility or roadmap items (see the compliance checklists under
  `docs/`).
- **Supply-chain / SSDLC gates.** CI enforces `gitleaks` (secret scanning),
  `semgrep` (SAST incl. OWASP Top Ten), `pip-licenses` (GPL/AGPL/LGPL banned),
  and `syft` SBOM (CycloneDX + SPDX); image-digest and SBOM verification run at
  startup, with hardened pod security contexts in the large/production profile.

### Operational hardening notes

The local `docker-compose` dev stack ships intentionally weak default
credentials and a dev-mode Vault — it is for development only. Production
deployments must inject secrets from Vault / K8s External Secrets, enable mTLS
(cert-manager), and use a non-dev profile. Never commit real secrets; the
`gitleaks` gate exists to catch accidents, not to license carelessness.

---

<a id="中文"></a>

[English](#security-policy) | 中文

# 安全策略

SaaS Foundation 是一个多租户企业级底座，其他系统在身份、鉴权、加密、审计与数据
保护上都依赖它。我们认真对待安全报告，并感谢负责任的漏洞披露。

## 受支持版本

项目尚处 1.0 之前；安全修复落在最新的 `0.x` minor 与 `main` 分支。

| 版本 | 是否支持 |
|---|---|
| `0.1.x` | ✅ 是（当前） |
| `main`（未发布） | ✅ 是 |
| `< 0.1.0` | ❌ 否 |

`1.0` 发布后，本表将更新为受维护的发布分支。

## 漏洞报告

**请不要为安全漏洞开公开的 GitHub issue、PR 或 discussion。** 公开报告会在修复
就绪前把其他用户暴露于风险中。

请通过邮件私下报告至 **<chenzefeng09@gmail.com>**，主题前缀
`[SECURITY] saas-foundation`，并尽量包含：

- 问题描述与影响（如跨租户数据泄露、认证/鉴权绕过、密钥泄露、RLS 逃逸）；
- 受影响的服务/包、版本或 commit、以及配置/profile；
- 复现步骤或 PoC；
- 可能的修复建议。

如需加密邮件，请先发一封明文邮件说明，我们再交换密钥。

### 响应时限

| 阶段 | 目标 |
|---|---|
| 确认收到报告 | **3 个工作日**内 |
| 初步评估与定级 | **7 个工作日**内 |
| 给出修复或缓解方案 | **30 天**内（严重问题更快） |
| 协同公开披露 | 修复发布后，双方约定时间 |

全程我们会与你保持沟通；如你愿意，会在发布说明与 `CHANGELOG.md` 中致谢，并与你
约定披露日期。请在公开讨论前给我们合理的修复窗口。

## 安全与合规模型

安全在 SaaS Foundation 中是设计内建属性，而非附加项。下列控制为概要，权威描述见
[`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) 与具有强制约束力的多租户契约
[`docs/multi-tenancy.md`](./docs/multi-tenancy.md)。

- **三道墙的多租户隔离**：网关从已验签 JWT 提取 `tenant_id` 并强制注入
  `X-Tenant-Id`（客户端不可覆盖）→ 应用/DB adapter 在每次 acquire 的事务内
  `SET LOCAL app.tenant_id` → PostgreSQL **行级安全（RLS）**（`ENABLE` +
  `FORCE ROW LEVEL SECURITY`，每表四条 policy）按 `current_setting('app.tenant_id')`
  过滤每一行。即便业务漏写 `WHERE tenant_id` 或遭遇注入也不越权。PgBouncer 固定
  事务级池化（statement 模式会泄露 `SET LOCAL`，启动即拒绝），应用 DB 角色
  `NOBYPASSRLS`，且每张租户表都有强制的 RLS 越权 fuzz 测试门禁。
- **单一加密边界**：所有密码学操作经唯一的 `crypto-service`；信封加密
  （MasterKey → KEK → DEK），KEK 永不离开 HSM/Vault，默认后端为 Vault transit +
  PKCS#11 HSM 抽象，KEK 90 天轮换，密钥销毁=数据销毁须经 PAM JIT + 四眼审批。
- **OPA 签名策略**：鉴权结合 Keycloak OIDC 与 OPA（RBAC + ABAC）；OPA 策略包由
  **crypto-service 做 JWS 签名**，按 shadow → canary → 100% 灰度发布，带全局
  kill switch 与一键回滚。
- **防篡改审计（WORM 哈希链）**：每次 API 调用产生结构化审计事件，落 ClickHouse
  并归档至 S3/MinIO **WORM**；审计服务构建**哈希链**并对根签名（默认 Ed25519，
  合规模式 SM2），提供链完整性校验。跨租户/系统操作须显式 `as_tenant()`/`SYSTEM`
  actor 并被审计。
- **合规姿态（等保 2.0 / PIPL）**：基线面向等保（DJCP 2.0）**三级**与个人信息
  保护法（**PIPL**），支持 `data-residency = cn-only`、可选国密（SM2/SM3/SM4 +
  GMTLS），并由 compliance 服务作为当前合规模式的真相源；提供 SOC 2 / ISO 27001
  证据导出。四级及部分控制项仍为客户责任或路线图事项（见 `docs/` 下的合规清单）。
- **供应链 / SSDLC 门禁**：CI 强制 `gitleaks`（密钥）、`semgrep`（SAST，含 OWASP
  Top Ten）、`pip-licenses`（禁 GPL/AGPL/LGPL）、`syft` SBOM（CycloneDX + SPDX）；
  启动时校验镜像摘要与 SBOM，large/生产 profile 启用加固的 pod 安全上下文。

### 运维加固提示

本地 `docker-compose` 开发栈带有故意弱化的默认凭证与 dev 模式 Vault，**仅供开发**。
生产部署必须从 Vault / K8s External Secrets 注入密钥、启用 mTLS（cert-manager）、
使用非 dev 的 profile。切勿提交真实密钥；`gitleaks` 门禁用于兜底失误，而非纵容大意。
