# DLP + Classification 详细设计 v1

> 数据分级（5 级）+ 数据防泄漏（DLP）联合服务。基线：金融/政务/医疗常用的 L1-L5 分级模型；DLP 三大能力：上传扫描、下载拦截、外发管控。

| 字段 | 值 |
|---|---|
| 状态 | Draft v1 |
| Owner | Security / 合规 PM |
| 评审 | 架构 / 安全 / 合规 / 法务 |
| 实施 milestone | A-M2（基线）+ A-M3（扫描 worker）+ A-M4（外发管控） |
| 相关文档 | crypto-v1 / audit-v1 / lifecycle-v1 / authz-v1 / data-protection-v1（后置） |

## 0. TL;DR

- **Classification（分级）**：每个资源（文件 / 数据库行 / 消息 / 提示词响应）打 `sensitivity ∈ {L1,L2,L3,L4,L5}`；默认 L2「内部」
- **DLP**：4 个执行点 — **上传扫描**（异步 worker）、**下载拦截**（同步 SDK）、**外发管控**（邮件 / Webhook / 三方分享，同步）、**剪贴板/打印**（业务前端拦截，后置 v1.1）
- **租户可配规则库**：默认敏感词样本（身份证 / 手机号 / 银行卡 / 病历号 / 关键词 blocklist）+ 租户自定义
- **L5 绝密**：四眼审批 + 操作录屏 + 销毁联动 + 不可降级 + 不可分享外部
- **联动**：authz（用户 clearance ≥ 资源 sensitivity 才能访问）、audit（所有命中事件必审）、lifecycle（L4/L5 默认更长 retention + crypto destroy）、notification（违规告警安全管理员）

## 1. Context（为什么做）

| 驱动 | 体现 |
|---|---|
| 等保三级 8.1.4.2 | 「应对重要数据进行标识，并制定标识管理规范」→ Classification 必备 |
| PIPL §51 | 「个人信息处理者应当采取措施确保个人信息的安全」→ DLP 必备 |
| 金融 JR/T 0071 | 「敏感数据出生产前强制脱敏」→ 外发管控 + data-protection 联动 |
| GDPR Art.32 | 「适当的技术和组织措施」→ 上传扫描 + 下载拦截 |
| 客户驱动 | 银行/政务/医疗 POC 强制要求文件分级 + 下载日志可追溯 |

**业务后果**：缺这一块 → 等保过不了；客户合规审查直接打回。

## 2. 分级模型（5 级，金融常用）

| 级别 | 名称 | 定义 | 典型样例 | 默认控制 |
|---|---|---|---|---|
| **L1** | 公开 | 可对外发布 | 营销文案、产品文档、公开 API | 无 |
| **L2** | 内部 | 仅租户内部可见（默认） | 普通工作文档、内部公告 | 租户内身份认证 |
| **L3** | 秘密 | 仅授权人员可见，泄露损害业务 | 客户名单、合同、源代码 | RBAC 显式授权 + 下载审计 |
| **L4** | 机密 | 仅核心团队可见，泄露重大损失 | 财务数据、未发布战略、密钥配置 | MFA + 下载拦截白名单 + 行为分析 |
| **L5** | 绝密 | 仅指定个人，泄露危及组织生存或国家安全 | 并购草案、核心算法、加密 master key | 四眼访问 + 操作录屏 + 不可外发 + WORM 保留 |

### 2.1 用户 Clearance（密级）

用户也有 `clearance ∈ {L1,L2,L3,L4,L5}`：

| 角色基线 | 默认 clearance |
|---|---|
| 普通员工 | L2 |
| 部门主管 | L3 |
| 高管 / 安全管理员 | L4 |
| 董事 / 核心机密持有人 | L5（须背景调查 + 单独签 NDA + 安全管理员特批） |

**访问基本约束**：`user.clearance >= resource.sensitivity` 才能读取（认证后第一道关）。
**仅 L1 例外**：所有人都可访问 L1。

### 2.2 升级 / 降级规则

- **自动升级**：上传扫描命中高级别敏感词 → 自动升 sensitivity（且只升不降）
- **手动升级**：资源 owner 或安全管理员可手动升级（审计）
- **降级**：**仅安全管理员可降**，且需 4 眼审批 + 完整理由 + 审计；L5 → ≤L4 禁止单方降级，必须走合规委员会
- **跨级写入**：禁止 L3 资源被 L4/L5 内容覆盖而不升级；写入时同步扫描

## 3. 公共契约（对外 SDK / API）

### 3.1 Python SDK

```python
from foundation_dlp import DLPClient, Classification, AccessDecision

client = DLPClient.from_env()

# 1. 给资源打标（创建时）
client.classification.tag(
    resource_id="res_01J7XYZ",
    resource_type="document",
    sensitivity="L3",
    tags=["pii", "contract"],
    reason="contains_customer_data",
)

# 2. 读取访问前检查（同步，<5ms）
decision: AccessDecision = client.dlp.check_read(
    user_id="usr_01J7ABC",
    resource_id="res_01J7XYZ",
)
if not decision.allowed:
    raise PermissionDenied(decision.reason)  # 自动审计；reason_code 见 §12（如 FOUNDATION.DLP.POLICY.CLEARANCE_INSUFFICIENT）

# 3. 下载拦截（同步）
decision = client.dlp.check_download(
    user_id="usr_01J7ABC",
    resource_id="res_01J7XYZ",
    destination="laptop",  # or "external_share", "email"
)

# 4. 外发拦截（邮件/分享链接生成前）
decision = client.dlp.check_external_send(
    user_id="usr_01J7ABC",
    resource_ids=["res_01J7XYZ", "res_01J7DEF"],
    channel="email",
    recipients=["external@partner.com"],
)

# 5. 上传时入扫描队列（异步）
client.scanner.enqueue_scan(
    resource_id="res_01J7XYZ",
    storage_uri="s3://foundation/tnt_a/res_01J7XYZ",
    content_type="application/pdf",
)
# scanner 完成后通过 webhook 回调业务层（也会自动调 classification.tag 升级）
```

### 3.2 REST API（OpenAPI 摘要）

> 服务命名分两个 service（CONVENTIONS §1.1）：`classification`（打标 + 降级） + `dlp`（检查 + 规则 + 扫描 + 事件）。
> URL 前缀遵守 CONVENTIONS §2.2：`/api/<service>/<version>/<resource>`。

| Method | Path | 说明 |
|---|---|---|
| POST | `/api/classification/v1/labels` | 打标（资源创建/升级） |
| GET  | `/api/classification/v1/labels/{resource_id}` | 查询当前标签 |
| POST | `/api/classification/v1/downgrade-requests` | 申请降级（走审批） |
| POST | `/api/dlp/v1/check-read` | 读取检查 |
| POST | `/api/dlp/v1/check-download` | 下载检查 |
| POST | `/api/dlp/v1/check-external-send` | 外发检查 |
| POST | `/api/dlp/v1/scanner/jobs` | 入扫描队列 |
| GET  | `/api/dlp/v1/scanner/jobs/{job_id}` | 扫描结果 |
| GET  | `/api/dlp/v1/rules` | 列租户规则 |
| PUT  | `/api/dlp/v1/rules` | 更新租户规则（管理员） |
| GET  | `/api/dlp/v1/incidents` | 列违规事件（按 tenant / user / 时间） |
| POST | `/api/dlp/v1/incidents/{id}/resolve` | 标记已处理 |

所有接口标准头：`X-Tenant-ID` / `X-Request-ID` / `Authorization: Bearer <jwt>`。

### 3.3 AccessDecision 结构

```python
@dataclass
class AccessDecision:
    allowed: bool
    reason_code: str    # FOUNDATION.DLP.POLICY.CLEARANCE_INSUFFICIENT 等
    reason_human: str
    matched_rules: list[str]  # 命中的规则 id
    risk_score: int     # 0-100
    require_mfa: bool   # 提示前端走 step-up MFA 重试
    require_approval: bool  # 提示走审批流，附 approval_workflow_id
```

## 4. 数据模型

> 库名：`foundation_dlp` / `foundation_classification`（同一物理库不同 schema）。所有表 RLS 强制 `tenant_id`。

### 4.1 classification.resource_label

资源 → 标签。

```sql
CREATE TABLE classification.resource_label (
  tenant_id        TEXT NOT NULL,
  resource_type    TEXT NOT NULL,          -- 'document'/'message'/'db_row' 等
  resource_id      TEXT NOT NULL,
  sensitivity      sensitivity_level NOT NULL DEFAULT 'L2',  -- enum L1-L5
  tags             TEXT[] NOT NULL DEFAULT '{}',  -- 'pii','contract','source_code'
  source           TEXT NOT NULL,          -- 'user'/'scanner'/'imported'/'inherited'
  reason           TEXT,
  upgraded_from    sensitivity_level,      -- 升级前级别
  set_by           TEXT NOT NULL,          -- user_id 或 'system:scanner'
  set_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, resource_type, resource_id)
);
CREATE INDEX idx_label_tenant_sens ON classification.resource_label(tenant_id, sensitivity);
CREATE INDEX idx_label_tags ON classification.resource_label USING GIN (tags);
```

### 4.2 classification.user_clearance

```sql
CREATE TABLE classification.user_clearance (
  tenant_id        TEXT NOT NULL,
  user_id          TEXT NOT NULL,
  clearance        sensitivity_level NOT NULL DEFAULT 'L2',
  granted_by       TEXT NOT NULL,
  granted_reason   TEXT NOT NULL,
  expires_at       TIMESTAMPTZ,            -- 可临时授权（如出差访问敏感）
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, user_id)
);
```

### 4.3 classification.downgrade_request

```sql
CREATE TABLE classification.downgrade_request (
  tenant_id        TEXT NOT NULL,
  request_id       TEXT NOT NULL,
  resource_id      TEXT NOT NULL,
  from_level       sensitivity_level NOT NULL,
  to_level         sensitivity_level NOT NULL,
  requested_by     TEXT NOT NULL,
  reason           TEXT NOT NULL,
  status           TEXT NOT NULL,           -- 'pending'/'approved'/'rejected'/'expired'
  approver_1       TEXT, approved_1_at TIMESTAMPTZ,
  approver_2       TEXT, approved_2_at TIMESTAMPTZ,  -- L4/L5 须 4 眼
  rejected_reason  TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, request_id)
);
```

### 4.4 dlp.rule

租户级 DLP 规则；可继承全局基线。

```sql
CREATE TABLE dlp.rule (
  tenant_id        TEXT NOT NULL,
  rule_id          TEXT NOT NULL,
  name             TEXT NOT NULL,
  type             TEXT NOT NULL,           -- 'regex'/'keyword'/'ml_classifier'/'fingerprint'
  pattern          TEXT NOT NULL,           -- regex / 关键词 / 模型 id / 文档指纹哈希
  applies_to       TEXT[] NOT NULL,         -- ['document','message']
  on_match_action  TEXT NOT NULL,           -- 'tag_only'/'upgrade_sens'/'block'/'alert'
  on_match_sens    sensitivity_level,       -- 命中后自动升到此级别
  enabled          BOOLEAN NOT NULL DEFAULT TRUE,
  inherited_from   TEXT,                    -- 'global_baseline' / NULL
  created_by       TEXT NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, rule_id)
);
CREATE INDEX idx_rule_enabled ON dlp.rule(tenant_id) WHERE enabled = TRUE;
```

### 4.5 dlp.scanner_job

```sql
CREATE TABLE dlp.scanner_job (
  tenant_id        TEXT NOT NULL,
  job_id           TEXT NOT NULL,
  resource_id      TEXT NOT NULL,
  resource_type    TEXT NOT NULL,
  storage_uri      TEXT NOT NULL,
  content_type     TEXT,
  status           TEXT NOT NULL,           -- 'QUEUED'/'SCANNING'/'DONE'/'FAILED'
  matched_rules    JSONB,                   -- [{rule_id, count, samples_redacted}]
  matched_sens     sensitivity_level,
  enqueued_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at       TIMESTAMPTZ,
  finished_at      TIMESTAMPTZ,
  failure_reason   TEXT,
  PRIMARY KEY (tenant_id, job_id)
);
CREATE INDEX idx_job_status ON dlp.scanner_job(status, enqueued_at) WHERE status IN ('queued','scanning');
```

### 4.6 dlp.incident

每一次 check_* 拒绝或扫描命中告警 = 1 个 incident。

```sql
CREATE TABLE dlp.incident (
  tenant_id        TEXT NOT NULL,
  incident_id      TEXT NOT NULL,
  type             TEXT NOT NULL,           -- 'unauthorized_read'/'download_blocked'/'external_send_blocked'/'scan_match_l4plus'
  severity         TEXT NOT NULL,           -- 'low'/'medium'/'high'/'critical'
  user_id          TEXT,
  resource_id      TEXT,
  rule_ids         TEXT[],
  context          JSONB,                   -- IP / UA / channel / recipients / etc
  status           TEXT NOT NULL DEFAULT 'open',  -- 'open'/'investigating'/'resolved'/'false_positive'
  resolved_by      TEXT,
  resolved_note    TEXT,
  resolved_at      TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, incident_id)
);
CREATE INDEX idx_incident_open ON dlp.incident(tenant_id, severity, created_at DESC) WHERE status = 'open';
```

### 4.7 dlp.external_send_audit

```sql
CREATE TABLE dlp.external_send_audit (
  tenant_id        TEXT NOT NULL,
  audit_id         TEXT NOT NULL,
  user_id          TEXT NOT NULL,
  resource_ids     TEXT[] NOT NULL,
  channel          TEXT NOT NULL,           -- 'email'/'webhook'/'share_link'/'api'
  recipients       TEXT[],
  allowed          BOOLEAN NOT NULL,
  decision_reason  TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, audit_id)
);
```

### 4.8 RLS 模板

全部 7 张表 + 标准 4 policy（详见 multi-tenancy.md §6）。`set_by = 'system:scanner'` 行需通过 `app_admin` 写入（绕开 RLS 应用层校验，但 RLS 仍兜底）。

## 5. 状态机

### 5.1 资源 sensitivity 升级

```
   created (default L2)
        │
        ├─→ scanner 命中 L3 规则 ─→ L3 (auto, audit)
        ├─→ scanner 命中 L4 规则 ─→ L4 (auto, audit, notify security)
        ├─→ scanner 命中 L5 规则 ─→ L5 (auto, audit, notify security, lock 4-eye)
        └─→ user/admin 手动升级 ─→ L3/L4/L5 (audit)

   降级路径：仅 admin 申请 → 4 眼审批 → 通过 → 降级（审计）
   L5 → ≤L4 不允许单方降级；走合规委员会
```

### 5.2 扫描 job

```
queued ──worker pick──> scanning ──ok──> done
                             │
                             └─fail──> failed (retry up to 3 times)
```

### 5.3 incident

```
open ──security_engineer triage──> investigating ──> resolved
                                          │
                                          └──> false_positive (rule 调优)
```

## 6. 扫描 worker 架构

### 6.1 拓扑

```
    上传完成事件 (foundation.storage.uploaded)
              │
              ▼
       enqueue_scan SDK
              │
              ▼
      ┌───────────────┐         ┌───────────────┐
      │ dlp.scanner_  │ ◀─────  │ scanner-worker│  (KEDA 触发，按队列长度伸缩)
      │ job (queue)   │         │  pool (5-50)  │
      └───────────────┘         └───────────────┘
              │                          │
              │                          ├─ 1. fetch from storage (MinIO/S3)
              │                          ├─ 2. extract text (Apache Tika / PDF)
              │                          ├─ 3. run rules
              │                          │      ├─ regex (re2)
              │                          │      ├─ keyword (Aho-Corasick)
              │                          │      ├─ fingerprint (SHA256 of normalized doc)
              │                          │      └─ ML classifier (transformer, optional)
              │                          ├─ 4. 命中 → upgrade sens + create incident
              │                          ├─ 5. update scanner_job
              ▼                          └─ 6. emit foundation.dlp.scan_completed
       业务回调 (webhook)
```

### 6.2 扫描规则引擎

| 类型 | 实现 | 性能基线（4C/8G worker） |
|---|---|---|
| regex | `re2`（避免 ReDoS） | 100 MB/s |
| keyword blocklist | `pyahocorasick`（多模式串） | 50 MB/s（10w 关键词） |
| fingerprint | SHA-256 of normalized text | 200 MB/s |
| ML classifier | 蒸馏 BERT (ONNX runtime) | 20 MB/s |
| OCR（图片/扫描件） | Tesseract（按需启用） | 1 MB/s（瓶颈，单独节点池） |

**默认基线规则库**（v1 内置）：
- 中国身份证（18 位 + 校验位）
- 手机号（13-19 开头 11 位）
- 银行卡号（Luhn）
- 邮箱（RFC 5322 子集）
- 信用卡 PAN（PCI DSS）
- 病历号（HIPAA 推荐）
- 关键词：「绝密」「机密」「内部」「password=」「secret=」「BEGIN PRIVATE KEY」
- 文件指纹：客户上传「文档样本库」生成哈希（如客户合同模板）

### 6.3 扫描精度

| 指标 | 目标 |
|---|---|
| 召回率（敏感数据被识别） | ≥ 95% (regex) / 80% (ML) |
| 误报率 | ≤ 5% （误报 → incident 标 false_positive → 入规则调优样本） |
| 扫描延迟（P95） | < 60s（10MB 文件）/ < 5min（100MB 文件，含 OCR） |
| 单 worker 吞吐 | 100 文件/分钟（小文件） |

### 6.4 增量扫描 / 重扫

- 资源更新 → 重新入队（去重：同 resource_id + content_hash 24h 内只跑一次）
- 规则更新 → 安全管理员可触发全量重扫（KEDA 自动扩到 50 个 worker）

## 7. 下载拦截 SDK（同步检查）

### 7.1 决策流程

```
check_download(user, resource, destination):
  1. 查 user.clearance vs resource.sensitivity
     - clearance < sensitivity → DENY (FOUNDATION.DLP.POLICY.CLEARANCE_INSUFFICIENT)
  2. 查 RBAC/OPA：user 有 download 权限？
     - 否 → DENY (foundation.authz.permission_denied)
  3. L4/L5 资源 → 检查 download 白名单（destination ∈ trusted_devices）
     - 否 → DENY (FOUNDATION.DLP.POLICY.DESTINATION_NOT_ALLOWED)
  4. 检查租户 DLP 规则（destination=external_share 时 L3+ 自动拒）
  5. 风险评估（IP / 设备 / 时段）
     - 风险 ≥ 60 → require_mfa = True
     - 风险 ≥ 80 → require_approval = True（异步流程）
  6. 命中规则 → 写 incident（即使 allow 也记 audit）
  7. 返回 AccessDecision
```

### 7.2 destination 类型

| destination | 说明 | 默认控制 |
|---|---|---|
| `browser_view` | 浏览器查看（不落盘） | L1-L4 允许，L5 需 watermark |
| `laptop` | 下载到本地磁盘 | L4+ 需 MFA |
| `external_share` | 分享链接给外部 | L3+ 默认拒，需审批 |
| `email` | 邮件附件 | L3+ 默认拒 |
| `api_export` | API 批量导出 | L3+ 需 special role + 审计 |
| `print` | 打印 | L4+ 默认拒（v1.1 业务层拦截） |

### 7.3 水印（watermark）

L3+ 浏览器查看时强制叠加水印：`<user_email>@<tenant>@<timestamp>@<resource_id>`，半透明斜纹。
后端生成（防前端绕过）：PDF / 图片 → server-side 加水印；HTML → 前端 CSS overlay + 后端校验 referer。

## 8. 外发管控（external send）

### 8.1 触发点

业务层任何外发动作（不在租户内闭环）必须先调 `check_external_send`：
- 邮件发送（包括通知模块自身发往租户外邮箱）
- 生成对外分享链接
- Webhook 推送到外部 URL
- API 导出到三方系统

### 8.2 决策

```
check_external_send(user, resources, channel, recipients):
  1. 所有 resources 中 max(sensitivity) = M
  2. 收件人外部域名（不在 tenant.allowed_domains）→ trigger
  3. M >= L5 → 永远拒绝（绝密不可外发）
  4. M = L4 → 需 4 眼审批（同步阻塞 + 异步通知审批人）
  5. M = L3 → 需安全管理员审批（异步）
  6. M ≤ L2 → 允许（但记 audit）
  7. recipients 数量超阈值（如 > 50 收件人）→ 额外审批
  8. 写 dlp.external_send_audit
```

### 8.3 审批流

- 同步阻塞场景（如 4 眼）：API 返回 `require_approval=True` + `approval_workflow_id`；前端轮询或 WebSocket 等待
- 异步场景：API 返回 `pending`；通知中心发钉钉/飞书审批卡片；审批通过后回调业务层重试

## 9. 与其他模块集成

### 9.1 authz

OPA policy 引入 sensitivity 维度：

```rego
package foundation.authz

allow if {
  input.action == "document.read"
  user_clearance >= resource_sensitivity
  rbac_check
}

user_clearance := levels[input.user.clearance]
resource_sensitivity := levels[input.resource.sensitivity]
levels := {"L1": 1, "L2": 2, "L3": 3, "L4": 4, "L5": 5}
```

`authz-service` 调 `dlp` 拉 user.clearance + resource.sensitivity → 注入 OPA input。

### 9.2 audit

所有 DLP/Classification 事件强制 audit（详见 audit-v1.md 事件清单）：

- `foundation.dlp.access_denied` — 任何 check_* 返回 deny
- `foundation.dlp.scan_match_high` — 扫描命中 L4/L5
- `foundation.dlp.external_send` — 外发（含成功的）
- `foundation.classification.upgraded` — 自动 / 手动升级
- `foundation.classification.downgrade_requested` — 降级申请
- `foundation.classification.downgrade_approved` — 降级通过

### 9.3 lifecycle

- L4 默认 retention ≥ 3 年（合规可调）
- L5 默认 retention ≥ 7 年 + 销毁必走 `CRYPTO_KEY_DESTROY` 方法（详见 lifecycle-v1.md §10）+ 双人见证销毁证书
- Legal Hold 优先级 > sensitivity；挂 hold 期间 L5 也不许销毁

### 9.4 notification

- L4/L5 自动告警安全管理员组（`role:security-admin`）
- 单用户 24h 内触发 ≥ 5 次 dlp 拒绝 → 安全管理员告警 + 自动锁账户（可配）
- 扫描完成 → webhook 业务层

### 9.5 crypto

- L5 资源静态加密用专用 KEK（per-tenant per-purpose `purpose=l5-confidential`）
- 销毁时通过 `crypto.kek_mark_for_destruction(kek_id)` + 30 天冷却 + `crypto.kek_destroy(kek_id)` 销毁该 KEK → 资源密文永久不可解（详见 crypto-v1 §7.4，由 lifecycle-service 编排，dlp 不直接调）

### 9.6 data-protection

- 外发到测试环境前必须经 data-protection 脱敏（详见 data-protection-v1.md，待写）
- 脱敏后资源的 sensitivity 自动降 1 级（L4 脱敏 → L3；L5 不可脱敏外发）

## 10. 部署形态差异

| 形态 | scanner-worker | OCR pool | ML classifier | 规则库 |
|---|---|---|---|---|
| small | 1 实例（同步降级，无 KEDA） | 关闭 | 关闭 | 仅默认基线 |
| medium | 5-20 实例（KEDA） | 1 实例（按需启用） | 1 实例（按需启用） | 默认 + 租户自定义 |
| large | 50-200 实例（KEDA + Karpenter） | 5 实例 GPU 节点 | 5 实例 GPU 节点 | + 文档指纹库（≥10w 模板） |

资源开销估算（medium）：每 1000 文件/日 → 0.5 vCPU·h；ML/OCR 增 5x。

## 11. 合规模式联动

| 合规模式 | 影响 |
|---|---|
| `equal_protection_3` | sensitivity 必须 ≥ L3 资源默认禁外发 |
| `equal_protection_4` | + L4 启用四眼读取 + 操作录屏 |
| `finance_jrt0071` | 默认启用 fingerprint + ML classifier；外发到测试必走脱敏 |
| `pipl` | 自动启用「身份证 / 手机号 / 银行卡」规则；命中即升 L3 |
| `gdpr` | 启用「邮箱 / IP / 设备 ID」PII 规则；命中即升 L3；外发 EEA 外触发跨境告警 |
| `hipaa` | 启用「病历号 / SSN / 诊断码」规则；保留期 ≥ 6 年；强制加密 |

## 12. 错误码

| code | HTTP | 说明 |
|---|---|---|
| `FOUNDATION.DLP.POLICY.CLEARANCE_INSUFFICIENT` | 403 | 用户密级低于资源 |
| `FOUNDATION.DLP.POLICY.DESTINATION_NOT_ALLOWED` | 403 | 目的地不在白名单 |
| `FOUNDATION.DLP.POLICY.EXTERNAL_SEND_BLOCKED` | 403 | 外发被规则阻断 |
| `FOUNDATION.DLP.POLICY.L5_NOT_EXPORTABLE` | 403 | L5 绝对禁外发 |
| `FOUNDATION.DLP.MFA.STEP_UP_REQUIRED` | 401 | 需 step-up MFA |
| `FOUNDATION.DLP.APPROVAL.PENDING` | 202 | 异步审批中 |
| `FOUNDATION.DLP.APPROVAL.REJECTED` | 403 | 审批拒绝 |
| `FOUNDATION.CLASSIFICATION.DOWNGRADE.FORBIDDEN` | 403 | L5 不可降级 |
| `FOUNDATION.DLP.SCANNER.UNSUPPORTED_FORMAT` | 415 | 扫描器不支持该格式 |
| `FOUNDATION.DLP.RULE.INVALID_PATTERN` | 400 | 规则正则无效 |

## 13. 性能与容量

| 接口 | 目标 P95 | 备注 |
|---|---|---|
| check_read | < 5ms | 全部命中缓存（user.clearance + resource.sensitivity Redis 5min TTL） |
| check_download | < 20ms | + 风险评估 |
| check_external_send | < 50ms | + 收件人解析 + 同步审批查询 |
| scan(10MB PDF) | < 60s | 异步 |
| scan(100MB PDF + OCR) | < 5min | 异步 |

容量基线（medium profile，1k 租户，100 用户/租户）：
- check 调用 1000 QPS（峰值 5000）
- scan job 10k/日
- incident 100/日（其中 L4+ 约 5/日，需人工 triage）

## 14. 待解决问题

| # | 问题 | 决策 |
|---|---|---|
| 1 | ML classifier 选模型 | v1 不强制；提供接口给客户接入自有模型（PyTorch / ONNX）；v1.1 内置蒸馏 BERT |
| 2 | 全量重扫的资源消耗 | KEDA + Karpenter 扩容；夜间窗口跑；进度可视化 |
| 3 | Watermark 是否需 server-side 强制 | L5 强制 server-side；L3/L4 前端 + 后端 referer 校验（双层） |
| 4 | 移动设备打印 / 截屏拦截 | v1 不做；标识为 client-side 责任，写入合规承诺 |
| 5 | 跨租户共享（B2B 场景） | v1 不支持；走外发流程（接收方租户作为 external recipient） |
| 6 | 规则版本管理 | 规则表加 `version` + `effective_from`；变更走灰度发布（先 dry-run 24h） |
| 7 | scanner 误报申诉 | incident UI 提供「标 false_positive」按钮 → 自动入「规则调优样本库」 → 安全管理员评审后调整规则 |
| 8 | 与 Agent 框架 tool call 集成（B 阶段以 AgentScope v2 落实） | agent 通过 `read_file` 读 L4+ 时需触发 DLP check；返回前自动脱敏（B 阶段） |
| 9 | OPA 缓存 vs 实时 | user.clearance / resource.sensitivity Redis 5 min；规则变更 Pub/Sub 主动失效 |
| 10 | 大批量扫描的 storage egress 费用 | medium/large profile 优先本地 MinIO；scanner 与 storage 同 AZ |

## 15. 验证标准（A-M2 + A-M3 出口）

| # | 验证项 | 通过标准 |
|---|---|---|
| 1 | 分级 5 级模型 e2e | 创建 L1-L5 资源，对应 clearance 用户读取通过/拒绝符合预期 |
| 2 | 升级自动化 | 上传含身份证 PDF → 扫描 → 自动升 L3 → 审计可查 |
| 3 | 下载拦截 | L4 资源 user.clearance=L3 拒绝；clearance=L4 + 非白名单 destination 拒绝 |
| 4 | 外发拦截 | L3 资源发给外部邮箱 → require_approval；L5 永远 deny |
| 5 | 四眼降级 | L4 资源降 L3 需 2 个审批人；流程 e2e |
| 6 | 扫描性能 | 100MB PDF + OCR < 5 min；10MB 普通 PDF < 60s |
| 7 | 规则灰度 | 新规则 dry-run 24h 后再生效；dry-run 期 incident 标 `would_block` |
| 8 | 误报率 | 默认规则库 1000 文件样本误报率 ≤ 5% |
| 9 | RLS 隔离 | tenant A 不能查询 tenant B 的 resource_label / rule / incident |
| 10 | 与 audit 联动 | 所有 deny/upgrade 事件在 audit ClickHouse 可查 |
| 11 | 与 lifecycle 联动 | L5 资源销毁触发 `CRYPTO_KEY_DESTROY` + 销毁证书 |
| 12 | 与 authz 联动 | OPA policy 引入 sensitivity 维度 e2e |
| 13 | 压测 | check_read 5000 QPS P95 < 5ms（缓存命中）；scan 1000 文件/分钟 |
| 14 | 合规自检 | 等保三级 / PIPL / 金融 JR/T 0071 控制项映射文档完整 |

## 16. 实施排期

| Sprint | 内容 |
|---|---|
| A-M2 W1-2 | 5 级模型 + 标签表 + classification SDK |
| A-M2 W3 | check_read + user_clearance + 与 authz 集成 |
| A-M2 W4 | 默认规则库（regex + keyword） + 同步扫描 v0（小文件） |
| A-M3 W1 | scanner-worker pool + KEDA + 异步扫描 |
| A-M3 W2 | check_download + 风险评估 + watermark |
| A-M3 W3 | check_external_send + 审批流 + 4 眼降级 |
| A-M3 W4 | incident UI + 规则灰度 + 性能压测 |
