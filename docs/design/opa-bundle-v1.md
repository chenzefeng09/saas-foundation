# OPA Bundle 制品流水线与灰度发布 v1

> authz-v1 已定义 OPA 双轨架构。本文档专注 **OPA bundle 的「生产实践」**：编译 → 签名 → 分发 → 灰度 → 回滚 → kill switch。

| 字段 | 值 |
|---|---|
| 状态 | Draft v1 |
| Owner | Foundation 安全 + Authz 后端 |
| 实施 milestone | A-M3 |
| 相关文档 | authz-v1 / audit / notification |

## 0. TL;DR

- **Bundle 制品**：tarball（rego policies + data.json + manifest.json + .signature）
- **签名**：crypto-service 用 OPA bundle 签名 key（per-bundle-channel）签 JWS；OPA 启动时 verifies
- **分发**：bundle service 暴露 HTTPS endpoint；OPA sidecar 5s poll；ETag + If-None-Match 减带宽
- **环境**：dev → staging → production，三套独立 bundle，独立签名 key
- **灰度**：4 阶段 — shadow（dry-run）→ canary 10% → 50% → 100%；每阶段必经观察期 + 自动指标守卫
- **回滚**：bundle service 一键 revert 到上一版本；kill switch 全局 fallback 到「全 deny」或「上一版本」
- **审计**：每次 publish / rollback / kill 全审计；签名链可外审

## 1. Context（为什么必须做）

- **OPA 写错 = 全局停摆**：一个 wrong policy 上线 → 所有 check 返回 deny → 全平台不可用
- **OPA 写错 = 全局放行**：rule 短路逻辑错误 → 所有 check 返回 allow → 全部越权
- 行业最佳实践：每次 policy 上线必走 shadow + canary，监控指标稳后才全量
- 等保审计要求：policy 变更必有审批 + 版本 + 回滚机制

## 2. Bundle 结构

```
bundle-foundation-authz-v20260522-001.tar.gz
├── manifest.json                    # 元数据 + 版本 + 依赖
├── policies/
│   ├── foundation/
│   │   ├── authz/
│   │   │   ├── core.rego            # 入口 package foundation.authz
│   │   │   ├── rbac.rego
│   │   │   ├── abac.rego
│   │   │   └── compliance.rego
│   │   └── shared.rego
│   └── tenant_overrides/            # 租户自定义 policy（如有）
│       └── tnt_a/
│           └── custom.rego
├── data/
│   ├── permissions.json             # role→permission 静态映射
│   ├── kill_switch.json             # 紧急开关
│   └── compliance_matrix.json
├── tests/                            # 必含 opa test
│   ├── core_test.rego
│   ├── rbac_test.rego
│   └── abac_test.rego
└── .signatures.json                  # 文件 hash 列表 + JWS 签名
```

### 2.1 manifest.json

```json
{
  "bundle_id": "foundation-authz-v20260522-001",
  "version": "20260522.001",
  "schema_version": 1,
  "previous_bundle_id": "foundation-authz-v20260521-003",
  "channel": "production",
  "scope": "global",
  "tenant_overrides_included": ["tnt_a", "tnt_b"],
  "roots": ["foundation/authz", "tenant_overrides"],
  "metadata": {
    "git_commit": "abc123def...",
    "git_branch": "main",
    "built_at": "2026-05-22T10:00:00Z",
    "built_by": "ci-pipeline",
    "test_results": {
      "passed": 248,
      "failed": 0,
      "coverage": 0.94
    }
  }
}
```

### 2.2 .signatures.json（OPA 原生支持）

```json
{
  "signatures": [
    {
      "keyid": "foundation-authz-prod-2026",
      "algorithm": "ES256",
      "signed": "eyJhbGc...",         // JWS compact serialization
      "files": [
        {"name": "manifest.json", "hash": "sha256:..."},
        {"name": "policies/foundation/authz/core.rego", "hash": "sha256:..."},
        ...
      ]
    }
  ]
}
```

**算法选 ES256（ECDSA P-256 / SHA-256）的理由**：
- OPA bundle 原生支持 ES256/RS256/HS256，**不支持 Ed25519**（参见 OPA `--signing-alg` 文档）
- crypto-v1 §3.1 默认 Ed25519 + 备选 ES256；本场景为 OPA 兼容约束，取 ES256 子集
- authz-v1 §4.5 同步更新："OPA bundle 签名走 crypto-service 的 ES256 通道（OPA bundle signing 例外，不用默认 Ed25519）"
- 国密 SM2 场景需要 OPA 自定义 verifier 插件（v1.1 评估）

OPA 启动时 `--bundle-verification-key` 加载公钥；不通过即不加载。

## 3. 制品流水线（CI/CD）

```
┌──────────────────────────────────────────────────────────────┐
│ git push policies/  → GitHub Actions opa-bundle.yml          │
└─────────────┬────────────────────────────────────────────────┘
              │
              ▼
   1. opa fmt --diff                    （格式必规整）
              │
   2. opa check policies/               （静态检查 + 类型）
              │
   3. opa test policies/ -v             （单元测试，cov ≥ 90%）
              │
   4. opa eval --bundle ... --benchmark （性能基线，复杂 policy < 5ms）
              │
   5. conftest test                     （结构 / 命名规范校验）
              │
   6. shift-left fuzz                   （opa-fuzzer，已知 vector 0 false-allow）
              │
   7. opa build -b policies/ -o bundle.tar.gz -s --signing-key ... --signing-plugin foundation
              │
   8. cosign sign-blob bundle.tar.gz     （二次签名 with Sigstore，留证据）
              │
   9. upload to bundle-service (channel=staging)
              │
   ▼
   人工 / 自动触发 promote staging → production
              │
   ▼
   bundle-service: 写 db、生成 publish event、广播给 OPA sidecar
```

### 3.1 测试覆盖率门槛

- `opa test --coverage` 每次 ≥ 90%
- 必含：每个 allow rule 一个 happy path + ≥ 2 个 negative case
- 必含：边界 case（空 role_grants、空 compliance_modes、None timestamp）
- 必含：default deny 保护测试

### 3.2 Fuzz 测试

- 工具：自研 + open-policy-agent/opa-fuzzer
- 100 个随机 input 模板 × 10000 次 / build
- 红线：任何已知越权 case 命中即 build 失败

## 4. Bundle Service

### 4.1 架构

```
┌─────────────┐    ┌──────────────┐    ┌──────────────────┐
│ CI Pipeline │ ─→ │ bundle-svc   │ ←─ │ Admin Console UI │
│  (upload)   │    │   (FastAPI)  │    │   (publish/rollback) │
└─────────────┘    │              │    └──────────────────┘
                   │  - DB        │
                   │  - Object    │           ┌──────────────────┐
                   │    Storage   │ ←──poll── │ OPA sidecar (×N) │
                   │  - Signing   │           └──────────────────┘
                   └──────────────┘
```

### 4.2 数据模型

```sql
CREATE TABLE opa.bundle (
  bundle_id        TEXT PRIMARY KEY,
  channel          TEXT NOT NULL,           -- 'dev'/'staging'/'production'
  version          TEXT NOT NULL,
  scope            TEXT NOT NULL,           -- 'global' / 'tenant:tnt_a'
  storage_uri      TEXT NOT NULL,           -- s3://...bundle.tar.gz
  manifest         JSONB NOT NULL,
  size_bytes       BIGINT NOT NULL,
  sha256           TEXT NOT NULL,
  signature_keyid  TEXT NOT NULL,
  uploaded_by      TEXT NOT NULL,
  uploaded_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  status           TEXT NOT NULL,           -- 'uploaded'/'shadow'/'canary'/'active'/'archived'/'rolled_back'
  promoted_from    TEXT,                    -- 上一 bundle_id
  promoted_at      TIMESTAMPTZ
);
CREATE INDEX idx_bundle_channel_active ON opa.bundle(channel, status) WHERE status IN ('shadow','canary','active');

CREATE TABLE opa.rollout (
  rollout_id       TEXT PRIMARY KEY,
  bundle_id        TEXT NOT NULL REFERENCES opa.bundle(bundle_id),
  channel          TEXT NOT NULL,
  stage            TEXT NOT NULL,           -- 'shadow'/'canary_10'/'canary_50'/'full'
  traffic_pct      INT NOT NULL,
  started_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  ended_at         TIMESTAMPTZ,
  ended_status     TEXT,                    -- 'promoted'/'aborted'/'rolled_back'
  metrics_snapshot JSONB,                   -- err rate / deny rate / latency 对比
  approved_by      TEXT,                    -- 推进人
  reason           TEXT
);

CREATE TABLE opa.kill_switch (
  channel          TEXT PRIMARY KEY,
  enabled          BOOLEAN NOT NULL DEFAULT FALSE,
  mode             TEXT NOT NULL,           -- 'fail_close'(全 deny) / 'fallback_previous'
  enabled_by       TEXT,
  enabled_at       TIMESTAMPTZ,
  reason           TEXT
);
```

### 4.3 OPA 拉取协议

OPA sidecar 配置：
```yaml
services:
  bundle-svc:
    url: https://bundle-svc.internal/opa
    headers:
      X-Tenant-ID: shared            # bundle 是全局，不带租户
    response_header_timeout_seconds: 5

bundles:
  authz:
    service: bundle-svc
    resource: bundles/authz/active   # bundle-svc 根据 channel 路由
    polling:
      min_delay_seconds: 5
      max_delay_seconds: 30
    signing:
      keyid: foundation-authz-prod-2026
      scope: write
      exclude_files: []
```

bundle-svc 实现 `/bundles/authz/active` 端点：
- 检查 If-None-Match → 304 减带宽
- 根据 OPA pod 的 sidecar 标签（traffic_bucket）路由到 shadow/canary/full bundle
- 返回 tar.gz + ETag

### 4.4 流量分桶（canary）

OPA pod 启动时通过 downward API 注入 `POD_HASH = hash(pod_name)`：
- bundle-svc 配置「canary 10%」 → `POD_HASH % 100 < 10` 拿 canary，其他拿 previous
- pod 数量变化不影响（hash 一致性）

或更精细：在 SDK `check()` 调用层按 `tenant_id` hash 分桶，bundle-svc 维护「shadow / canary tenant 列表」。
- 优势：可指定特定租户先体验（友好客户做 alpha tester）
- 实现：OPA 不变，SDK 在调用前查「该 tenant 此刻用哪个 bundle」→ 路由到对应 OPA replica
- v1 选 SDK 分桶（更可控）

## 5. 灰度发布 4 阶段

### 5.1 Stage 1: Shadow（dry-run）

- 新 bundle 部署，但**不影响真实决策**
- SDK 同时调用 active bundle + shadow bundle，对比结果
- 不一致写 `opa.shadow_mismatch` 表 + 告警
- 持续 ≥ 24h；mismatch rate 必须 < 0.1%

```python
# SDK 内部
active_decision = opa_active.check(input)
shadow_decision = opa_shadow.check(input)
if shadow_enabled and active_decision.allow != shadow_decision.allow:
    log_mismatch(input, active_decision, shadow_decision)
return active_decision  # 仍用 active
```

### 5.2 Stage 2: Canary 10%

- 10% 流量走新 bundle
- 监控关键指标对比：
  - p95/p99 延迟
  - error rate（OPA 内部错）
  - allow_rate / deny_rate 是否漂移 ±5%
  - 业务侧 403 增长
- 持续 ≥ 2h；任一指标越界自动 rollback

### 5.3 Stage 3: Canary 50%

- 50% 流量；持续 ≥ 4h
- 同样指标守卫

### 5.4 Stage 4: Full 100%

- 全量；旧 bundle 进入 `archived` 状态保留 30 天供回滚
- 全量观察 24h 后才能开始下一次 publish

### 5.5 自动指标守卫

每阶段配 SLO 阈值：

```yaml
slo_guards:
  - metric: opa_decision_latency_p95_ms
    threshold: "< 10"
    breach_action: rollback
  - metric: opa_decision_error_rate
    threshold: "< 0.001"
    breach_action: rollback
  - metric: deny_rate_delta
    threshold: "|delta| < 0.05"     # 与上一阶段相比偏差 < 5%
    breach_action: pause            # 不自动 rollback，等人工
  - metric: business_403_rate_delta
    threshold: "delta < 0.10"       # 业务 403 增长 < 10%
    breach_action: rollback
```

由 Prometheus alert manager + bundle-svc 联动；触发 `breach_action` 时自动调 `/rollouts/{id}/abort` 或 `/rollback`。

## 6. Kill Switch

### 6.1 触发条件

- 安全管理员手动触发（控制台一键）
- 自动触发（多个 SLO 同时严重违反）
- OPA bundle service 不可达超 60s

### 6.2 两种模式

| 模式 | 行为 | 用途 |
|---|---|---|
| `fail_close` | OPA 返回全 deny | 怀疑越权风险时；接受业务停摆换安全 |
| `fallback_previous` | OPA fallback 上一已知 good bundle | 怀疑新 bundle 有 bug；优先业务连续 |

### 6.3 实现

- 写 `opa.kill_switch` 表
- bundle-svc 推送给 OPA `/v1/data/foundation/kill_switch` 数据（也是 bundle 的一部分）
- OPA core.rego 加 short-circuit：
  ```rego
  default allow := false
  
  allow if {
      not kill_switch_active
      rbac_check
  }
  
  kill_switch_active if {
      data.kill_switch.enabled == true
      data.kill_switch.mode == "fail_close"
  }
  ```
- `fallback_previous` 模式：bundle-svc 直接 serve 上一 bundle

### 6.4 解除

- 解除必须双人审批（kill switch 触发的回滚通常是事故）
- 解除后 bundle-svc 写解除事件 + 通知中心广播

## 7. 租户自定义 Policy

> v1 仅支持 global bundle；v1.1 支持租户 override。

**v1 限制**：所有 policy 由平台方维护。租户可配置 input 维度的 `data`（如 `tenant.compliance_modes`），但不能写 rego。

**v1.1 计划**：
- 租户可上传 `policies/tenant_overrides/<tenant_id>/*.rego`
- 必经 sandbox 测试（不能写跨租户的规则）
- 自动注入 namespace prefix 防污染 global
- 单租户 bundle 独立发布通道（不影响其他租户）

## 8. 监控看板（必备）

Grafana 面板 + AlertManager 告警：

| 指标 | 来源 | 告警阈值 |
|---|---|---|
| `opa_bundle_version` (info) | OPA `/health?bundles=true` | bundle stale > 60s |
| `opa_decision_latency_p95_ms` | OPA `/metrics` | > 10ms |
| `opa_decision_rate` | OPA | 业务量参考 |
| `opa_decision_allow_rate` / `deny_rate` | OPA | 漂移 ±5% 30min 持续 |
| `opa_loaded_bundle_failed` | OPA event | 任何 > 0 |
| `bundle_svc_publish_total` | bundle-svc | — |
| `bundle_svc_rollback_total` | bundle-svc | > 0 必复盘 |
| `kill_switch_active` | bundle-svc | > 0 立即告警 + on-call |
| `shadow_mismatch_rate` | bundle-svc | > 0.001 阻断 promote |

## 9. 错误码

| code | HTTP |
|---|---|
| `FOUNDATION.OPA.BUNDLE.SIGNATURE_INVALID` | 500 |
| `FOUNDATION.OPA.BUNDLE.NOT_FOUND` | 404 |
| `FOUNDATION.OPA.BUNDLE.CHANNEL_MISMATCH` | 409 |
| `FOUNDATION.OPA.ROLLOUT.IN_PROGRESS` | 409 |
| `FOUNDATION.OPA.ROLLOUT.SLO_BREACH` | 503 |
| `FOUNDATION.OPA.KILL_SWITCH.ACTIVE` | 503 |
| `FOUNDATION.OPA.SIDECAR.UNREACHABLE` | 503 |

## 10. 与其他模块集成

| 模块 | 集成 |
|---|---|
| **authz** | bundle 是 authz 决策的源头；SDK check 走 sidecar |
| **audit** | 所有 publish / rollback / kill 落 audit；shadow mismatch 落 audit |
| **notification** | 关键事件（promote / abort / kill）告警 security-admin |
| **compliance** | 审计 trail 是合规自查必要凭据 |
| **crypto** | bundle 签名 key 走 crypto-service 管理 |
| **identity** | bundle-svc 操作需 admin role + MFA |

## 11. 部署形态

| 形态 | bundle-svc | OPA sidecar | shadow |
|---|---|---|---|
| small | 1 实例 | 每 service pod 1 sidecar | 不支持（dev 直接 publish） |
| medium | 3 实例 HA | 每 pod 1 sidecar | 支持 |
| large | 5-10 实例 + CDN（如客户允许） | 每 pod 1 sidecar | 支持 + per-tenant canary |

## 12. 验证标准（A-M3 出口）

| # | 验证 | 通过 |
|---|---|---|
| 1 | CI pipeline e2e | fmt/check/test/build/sign/upload 全绿 |
| 2 | 签名验证 | 篡改 .signatures.json → OPA 拒载 |
| 3 | shadow mode | mismatch 正确记录；不影响业务 |
| 4 | canary 10% | 10% 流量精确分桶；指标守卫触发 rollback 演练 |
| 5 | full rollout | 24h 观察期；archived bundle 可回滚 |
| 6 | kill switch fail_close | 触发后全 deny；解除后恢复 |
| 7 | kill switch fallback_previous | 触发后用上一 bundle；业务连续 |
| 8 | bundle-svc 不可达 | OPA 用 cached bundle 继续工作；超 cache TTL 进入 fail_close |
| 9 | 性能 | bundle pull < 100ms；OPA decision < 1ms p95 |
| 10 | 审计完整 | 所有 publish/rollback/kill/shadow_mismatch 在 audit 可查 |
| 11 | 测试覆盖率 | ≥ 90%；fuzz 0 false-allow |
| 12 | 文档 | runbook 含「OPA 完全不可用怎么办」「policy 上线误开放怎么办」两个场景 |

## 13. 待解决问题

| # | 问题 | 决策 |
|---|---|---|
| 1 | bundle 大小（含 data.json） | 控制 < 10MB；大数据移出 bundle 改 OPA 实时查询 |
| 2 | tenant_overrides v1 不做 | v1 文档明确说明；客户自定义需求记录排到 v1.1 |
| 3 | shadow 流量翻倍 OPA 资源 | shadow 用独立 sidecar pool；按需扩 |
| 4 | rego 性能 profiling 工具 | 集成 OPA `opa eval --metrics --profile`；CI 跑 benchmark |
| 5 | bundle 跨集群同步 | bundle-svc 自身 multi-AZ；OPA sidecar 走最近 endpoint |
| 6 | policy 作者权限管理 | 写 policies/ 的人必须有 `role:opa-author`；review 必须有 `role:opa-reviewer`（不同人）|
| 7 | rollback 数据兼容性 | bundle 的 input/data schema 必须向后兼容；breaking change 走 major version |
| 8 | 应急流程演练 | 季度演练 1 次 kill switch + rollback |
