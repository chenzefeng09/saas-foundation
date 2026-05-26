# Data Protection 详细设计 v1

> 数据保护：**脱敏引擎**（生产→测试/分析的安全出院）、**数据销毁**（与 lifecycle 协同 + 销毁证明 PDF）、**跨境传输合规**（数据驻留 + PIPL 标准合同）、**个人信息告知与同意管理**（DSAR 入口前置）。

| 字段 | 值 |
|---|---|
| 状态 | Draft v1 |
| Owner | 合规 PM + 安全工程 |
| 评审 | 架构 / 安全 / 合规 / 法务 |
| 实施 milestone | A-M2（脱敏 v0）+ A-M4（跨境 + DSAR + 销毁证明完善） |
| 相关文档 | dlp-classification-v1 / crypto-v1 / lifecycle-v1 / audit-v1 / compliance（后置） |

## 0. TL;DR

四大子能力：

| 子能力 | 一句话 | 出口 |
|---|---|---|
| **脱敏引擎** | 字段级 + 一致性脱敏；用于生产→测试导出、数据分析、对外报表 | SDK + REST + Postgres FDW 适配 |
| **数据销毁** | 与 lifecycle 联动；DoD 覆写 / 加密密钥销毁 / 物理销毁；输出销毁证明 PDF | `destroy()` SDK + 销毁证书 |
| **跨境传输管控** | 数据流向境外即检测+告警；PIPL 标准合同模板；安全评估申报材料生成 | `check_cross_border()` + 模板生成器 |
| **告知与同意** | PII 处理告知书 + 用户同意记录 + DSAR 7 种权利入口 | `consent.record()` + DSAR 工作流 |

## 1. Context

| 驱动 | 落点 |
|---|---|
| 金融 JR/T 0071 | "数据出生产环境强制脱敏" → 脱敏引擎 |
| PIPL §13/§14/§17 | 告知同意 + DSAR 7 项权利 → 告知/同意 + DSAR 工作流 |
| PIPL §38 | 跨境传输需安评 / 标准合同 / 认证 → 跨境管控 |
| GDPR Art.15-22 | DSAR 一致 |
| 等保 8.1.4.5 | "数据销毁要求" → 销毁证明 |
| HIPAA Privacy Rule | PHI 脱敏 De-identification（Safe Harbor + Expert Determination） |
| 客户驱动 | 金融客户：测试环境必须脱敏才能上 |

## 2. 子能力一：脱敏引擎

### 2.1 脱敏方法分类

| 方法 | 输出可逆？ | 用途 | 示例 |
|---|---|---|---|
| **Mask（掩码）** | 否 | 显示给非授权用户 | `1380****1234` |
| **Truncate（截断）** | 否 | 报表展示 | 身份证保留前 6 位 |
| **Hash** | 否 | join key 但隐藏原值 | `SHA256(salt + value)` 一致 |
| **Pseudonymize（假名化）** | 是（持密钥） | 测试环境保持业务连通性 | `张三 → 用户A1B2C3`，同值同结果 |
| **Tokenize（令牌化）** | 是（持金库） | 支付场景 PAN | `4111-1111-1111-1111 → tok_xyz` |
| **Synthesize（合成）** | 否 | 训练数据 | 真实分布的伪造数据 |
| **Generalize（泛化）** | 否 | k-匿名 | `年龄 23 → 20-30`；`地址 → 省级` |
| **Suppress（抑制）** | 否 | 删除字段 | `field = null` |
| **Noise（加噪）** | 否 | 统计聚合 | 金额 ±5% 噪音；差分隐私 ε |

### 2.2 一致性脱敏（Deterministic）

> 同一原始值经脱敏后始终得到同一脱敏值 → 测试环境跨表 join 仍可用。

实现：`pseudonymize(value, purpose) = HMAC-SHA256(per_tenant_per_purpose_key, value)`
- key 存 Vault transit；purpose 维度隔离（"customer_id" / "phone" 各一把）
- 不同租户、不同 purpose 不串
- 密钥销毁 → 该套脱敏映射永久不可逆向（合规销毁通道）

### 2.3 字段级规则 DSL（YAML）

```yaml
# tenant_xxx 的 production→test 导出规则
source: "postgres://prod/foundation.customer"
target: "postgres://test/foundation.customer"

rules:
  - column: "id"
    method: "passthrough"           # 主键不变（FK 完整性）

  - column: "name"
    method: "pseudonymize"
    purpose: "customer_name"        # 一致性脱敏，同 name 永远 → 同假名

  - column: "phone"
    method: "mask"
    pattern: "###****####"          # 138****1234

  - column: "id_card"
    method: "truncate"
    keep_prefix: 6                  # 前 6 位
    keep_suffix: 0

  - column: "email"
    method: "mask"
    pattern: "a*@domain"            # 显示首字符 + @域名

  - column: "address"
    method: "generalize"
    level: "province"               # 省级

  - column: "salary"
    method: "noise"
    type: "multiplicative"
    factor_range: [0.95, 1.05]      # ±5%

  - column: "ssn"
    method: "suppress"              # 直接 null
```

### 2.4 公共 SDK

```python
from foundation_data_protection import MaskingClient, MaskingRule

client = MaskingClient.from_env()

# 1. 单值脱敏（在线 API 用，如对外报表）
masked = client.masking.mask_value(
    value="13800001234",
    rule=MaskingRule(method="mask", pattern="###****####"),
)  # "138****1234"

# 2. 一致性脱敏
pseudo = client.masking.pseudonymize(
    value="张三",
    purpose="customer_name",
)  # "用户A1B2C3"，下次同值同结果

# 3. 整批脱敏（导出场景）
job = client.masking.create_export_job(
    source_uri="postgres://prod/foundation.customer",
    target_uri="postgres://test/foundation.customer",
    rule_set_id="prod_to_test_v1",
    requested_by="alice@tenant-a",
    approval_required=True,    # 走审批
)
# → 返回 job_id，状态机：pending_approval → approved → running → done

# 4. 反查脱敏映射（仅可信角色，审计）
original = client.masking.reverse_pseudonym(
    pseudo="用户A1B2C3",
    purpose="customer_name",
    reason="legal_investigation_case_xxx",
)  # 强审计 + 4 眼
```

### 2.5 接入 Postgres FDW（可选高级特性，v1.1）

为给已有 BI / 分析工具透明使用：在 test 环境用 `postgres_fdw` 指向 prod 的 view，view 内置脱敏函数，BI 无感知。
v1 暂不做，留接口。

### 2.6 数据出院审批流

```
申请人 (DA/dev) ──提交 export_job──> data-protection-service
                                          │
                                          ▼
                              查 rule_set 是否覆盖所有列（completeness check）
                                          │
                                          ├─ 未覆盖列 → 拒绝（防漏脱敏）
                                          ▼
                                  通知数据 owner + 安全管理员审批
                                          │
                                          ├─ 拒绝 → audit + 反馈
                                          ▼
                                      跑脱敏（worker pool）
                                          │
                                          ├─ 校验：抽样验证脱敏正确性
                                          ├─ 校验：行数一致 + 主键完整
                                          ▼
                                      写入 target + 生成报告
                                          │
                                          ▼
                                       审计存档
```

## 3. 子能力二：数据销毁

### 3.1 销毁方法（细化 lifecycle-v1 §10）

| 方法 | 适用 | 强度 | 备注 |
|---|---|---|---|
| `CRYPTO_KEY_DESTROY` | 字段级加密 / L5 资源 | ★★★★★ | 销毁 KEK → 全部密文永远不可解，最快最彻底 |
| `DOD_5220_22_M` | 块存储 / 文件 | ★★★★ | 3 遍覆写（0/1/random），适合机械盘 |
| `NIST_800_88_CLEAR` | SSD | ★★★ | 单遍覆写（SSD 多遍无意义） |
| `NIST_800_88_PURGE` | SSD | ★★★★ | 厂商 ATA Secure Erase + verify |
| `NIST_800_88_DESTROY` | 物理销毁 | ★★★★★ | 粉碎 / 焚烧 / 退磁；适合退役硬件 |
| `TRUNCATE` | DB 表 / 软删 | ★★ | 仅业务上不可见，磁盘可能还有；不算合规销毁 |
| `CUSTOM_HOOK` | 业务自定义 | — | 业务层提供 webhook |

### 3.2 销毁证明 PDF

> 生成不可篡改、可外审展示的销毁证书。lifecycle-v1 §10 已定义；这里展开格式。

**字段**：
- 证书编号（snowflake）
- 租户 / 资源 ID / 资源描述
- 数据分类（含 sensitivity）
- 销毁方法 + 强度等级
- 执行人 + 见证人（4 眼）
- 执行时间 + 时区 + 物理位置（数据中心 ID）
- 销毁前哈希（SHA-256 of metadata，不含原数据）
- 销毁后验证（如 KEK 销毁则 vault read 返回 404 截图哈希；如覆写则 sample 读取全 0/random 抽样哈希）
- 合规模式标识（等保/HIPAA/GDPR …）
- 国密 SM2 / RSA 数字签名（compliance-service 私钥）
- RFC 3161 可信时间戳（TSA 出印）
- WORM 归档位置（s3 object-lock URI）

**实现栈**：
- 模板：Jinja2 + WeasyPrint → PDF/A-3（带嵌入字体，长期保存）
- 签名：PKCS#7 detached signature embed 到 PDF（PAdES B-LT level）
- TSA：嵌入 RFC 3161 时间戳响应到 PDF document timestamp field

### 3.3 销毁联动加密密钥

L5 资源销毁专用路径：
1. 标记 destruction_job status=running
2. 调 `crypto.kek_mark_for_destruction(key_id, reason)` → 30 天冷却 → `crypto.kek_destroy(key_id)`（统一命名，crypto-v1 §5.2）
3. 冷却期内任何读取尝试触发告警（防误操作）
4. 30 天到期 → crypto 真删除 key material
5. 生成证书（含 vault 验证截图哈希）
6. WORM 归档证书
7. lifecycle resource 状态 → destroyed

## 4. 子能力三：跨境传输管控

### 4.1 触发检测

`check_cross_border(operation)` SDK，业务层在以下场景必调：
- 数据写入境外存储（S3 us-east-1、Azure West Europe 等）
- 调用境外 API（外部 LLM provider、外部 SaaS）
- 备份到境外
- 多区域复制

```python
decision = client.cross_border.check(
    tenant_id="tnt_a",
    data_classes=["pii", "id_card", "phone"],
    operation="store",
    destination_country="US",
    destination_region="us-east-1",
    legal_basis="standard_contract",   # 'standard_contract' / 'security_assessment' / 'certification' / 'consent'
)
if not decision.allowed:
    raise ComplianceViolation(decision.reason)
```

### 4.2 PIPL 跨境合法基础（4 选 1）

| 路径 | 适用 | 出口物 |
|---|---|---|
| **安全评估** | CII / 处理 100w+ 个人信息 / 10w+ 敏感 PI / 1w+ 敏感 PI 累计出境 | 申报材料模板（自动生成 60% 内容，剩 40% 人工补） |
| **标准合同** | 一般场景 | PIPL 标准合同模板（2023 网信办版）+ PIA 报告生成器 |
| **保护认证** | 集团内部传输 | 引用认证证书 |
| **单独同意** | 用户授权 | consent 模块记录明示同意 |

### 4.3 数据驻留约束（data residency）

租户级配置：
```json
{
  "data_residency": "cn-only",
  "allowed_regions": ["cn-north-1", "cn-south-1"],
  "denied_regions": ["us-*", "eu-*"]
}
```
注入各模块（storage / crypto / backup / llm-gateway）启动时校验，违反即拒绝写入。

LLM Gateway 强制：cn-only 租户禁止注册任何海外 provider 端点。

### 4.4 GDPR 视角

EEA 出境同样管控：
- 充分性认定地区（adequacy）→ 允许
- 标准合同条款（SCCs 2021）→ 模板
- 约束性公司规则（BCRs）→ 引用

### 4.5 申报材料生成器

输入：租户配置 + 数据流图（compliance-service ROPA 扫描结果）
输出：
- 《数据出境安全评估申报书》（Word + PDF）
- 《个人信息保护影响评估报告》（DPIA）
- 《标准合同》（甲乙双方信息预填）
- 数据流向图（draw.io / mermaid）

## 5. 子能力四：告知与同意 + DSAR 入口

### 5.1 个人信息处理告知书

> PIPL §17：处理 PII 必须告知 5 项核心信息。

自动生成机制：
- 各 service 代码用 `@pii_processing` 装饰器标注 PII 处理：
  ```python
  @pii_processing(
      data_types=["phone", "email", "id_card"],
      purpose="user_authentication",
      retention="3_years",
      shared_with=["third_party_sms_provider"],
      legal_basis="contract_performance",
  )
  def register_user(...): ...
  ```
- 启动时扫描装饰器 → 生成《个人信息处理告知书》Markdown
- 注册 / 登录 / 首次访问时强制展示 + 获取明示同意
- 同意记录写 `consent.user_consent` 表（带哈希链，与 audit 联动）

### 5.2 DSAR（Data Subject Access Request）7 项权利

| 权利 | API | SLA |
|---|---|---|
| **访问** Access | `POST /v1/dsar/access` | 30 天（复杂 60） |
| **更正** Rectification | `POST /v1/dsar/rectify` | 30 天 |
| **删除** Erasure ("被遗忘") | `POST /v1/dsar/erase` | 30 天（联动 lifecycle 销毁） |
| **限制** Restriction | `POST /v1/dsar/restrict` | 30 天 |
| **可携带** Portability | `POST /v1/dsar/export` | 30 天（JSON + CSV） |
| **反对** Objection | `POST /v1/dsar/object` | 30 天 |
| **拒绝自动化决策** | `POST /v1/dsar/opt-out-auto` | 即时；触发人工复核 |

### 5.3 DSAR 工作流

```
用户发起请求 (web/email/API)
    ↓
身份验证（强 MFA + 实名匹配）
    ↓
工单生成 (dsar.request 表，SLA 倒计时 30 天)
    ↓
DPO 受理（合规专员）
    ↓
跨服务数据收集（compliance-service 调各 service 的 dsar_collector hook）
    ↓
脱敏 / 整理 (data-protection)
    ↓
审批 (法务 + DPO 双签)
    ↓
交付（加密邮件 / 安全下载链接，7 天有效）
    ↓
关闭工单 + audit
```

### 5.4 删除权特别处理

- 联动 lifecycle.hard_delete + 加密密钥销毁
- 与 Legal Hold 冲突：Legal Hold 优先；通知用户「因 X 法律义务暂不可删，预计 Y 时间可执行」
- 备份中的副本：标记 tombstone，下次备份轮转时实际删除（备份保留期 ≤ 原数据保留期）
- 第三方数据处理者：自动 forward 删除请求（webhook + 7 天确认 SLA）

## 6. 数据模型

> 库 `foundation_data_protection`，RLS 强制 tenant_id。

### 6.1 masking.rule_set

```sql
CREATE TABLE masking.rule_set (
  tenant_id        TEXT NOT NULL,
  rule_set_id      TEXT NOT NULL,
  name             TEXT NOT NULL,
  source_schema    TEXT NOT NULL,
  rules_yaml       TEXT NOT NULL,        -- 原始 DSL
  rules_compiled   JSONB NOT NULL,       -- 编译后规则
  completeness_check_passed BOOLEAN NOT NULL,
  created_by       TEXT NOT NULL,
  approved_by      TEXT,
  approved_at      TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, rule_set_id)
);
```

### 6.2 masking.export_job

```sql
CREATE TABLE masking.export_job (
  tenant_id        TEXT NOT NULL,
  job_id           TEXT NOT NULL,
  rule_set_id      TEXT NOT NULL,
  source_uri       TEXT NOT NULL,
  target_uri       TEXT NOT NULL,
  requested_by     TEXT NOT NULL,
  approval_status  TEXT NOT NULL,        -- 'pending'/'approved'/'rejected'
  approver         TEXT,
  status           TEXT NOT NULL,        -- 'PENDING_APPROVAL'/'APPROVED'/'RUNNING'/'DONE'/'FAILED'（CONVENTIONS §2.8 UPPER_SNAKE_CASE）
  rows_total       BIGINT,
  rows_processed   BIGINT,
  validation_report JSONB,
  started_at       TIMESTAMPTZ,
  finished_at      TIMESTAMPTZ,
  PRIMARY KEY (tenant_id, job_id)
);
```

### 6.3 销毁证书表 → 由 lifecycle 持有（本模块不建表）

> **职责单一化**：销毁证书记录由 `lifecycle.destruction_certificate` 表持有（详见 lifecycle-v1 §10）。
> 本模块仅负责：①生成 PDF 内容（Jinja2 + WeasyPrint 渲染） ②嵌入 PKCS#7 签名 + RFC 3161 TSA ③上传 WORM。
> lifecycle-service 通过 SDK 调本模块的 `render_destruction_certificate(metadata) -> PDFBytes` → 拿到 PDF 后写入 `lifecycle.destruction_certificate` 表 + 上传 WORM。
> 这样**销毁证书的"事实记录"只有一处**（lifecycle），避免双表数据漂移。

### 6.4 cross_border.decision_log

```sql
CREATE TABLE cross_border.decision_log (
  tenant_id        TEXT NOT NULL,
  decision_id      TEXT NOT NULL,
  operation        TEXT NOT NULL,
  data_classes     TEXT[] NOT NULL,
  destination_country TEXT NOT NULL,
  destination_region  TEXT,
  legal_basis      TEXT,
  allowed          BOOLEAN NOT NULL,
  reason           TEXT,
  initiator        TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, decision_id)
);
```

### 6.5 consent.user_consent

```sql
CREATE TABLE consent.user_consent (
  tenant_id        TEXT NOT NULL,
  consent_id       TEXT NOT NULL,
  user_id          TEXT NOT NULL,
  notice_version   TEXT NOT NULL,        -- 告知书版本号
  notice_hash      TEXT NOT NULL,        -- 告知书内容哈希
  consented_items  TEXT[] NOT NULL,      -- 用户明示同意的处理项
  ip_address       INET,
  user_agent       TEXT,
  consented_at     TIMESTAMPTZ NOT NULL,
  withdrawn_at     TIMESTAMPTZ,
  chain_prev_hash  TEXT,
  chain_hash       TEXT NOT NULL,        -- 与 audit 同款哈希链
  PRIMARY KEY (tenant_id, consent_id)
);
```

### 6.6 dsar.request

```sql
CREATE TABLE dsar.request (
  tenant_id        TEXT NOT NULL,
  request_id       TEXT NOT NULL,
  user_id          TEXT NOT NULL,
  right_type       TEXT NOT NULL,        -- 'ACCESS'/'RECTIFY'/'ERASE'/'RESTRICT'/'EXPORT'/'OBJECT'/'OPT_OUT_AUTO'
  details          JSONB,
  status           TEXT NOT NULL,        -- 'RECEIVED'/'VERIFIED'/'PROCESSING'/'AWAITING_APPROVAL'/'DELIVERED'/'REJECTED'
  identity_verified BOOLEAN NOT NULL DEFAULT FALSE,
  sla_due_at       TIMESTAMPTZ NOT NULL,
  delivered_at     TIMESTAMPTZ,
  delivery_uri     TEXT,                  -- 加密下载链接
  rejected_reason  TEXT,
  assigned_dpo     TEXT,
  legal_signoff    TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, request_id)
);
CREATE INDEX idx_dsar_due ON dsar.request(sla_due_at) WHERE status NOT IN ('DELIVERED','REJECTED');
```

## 7. 状态机

### 7.1 export_job

```
PENDING_APPROVAL ──approve──> APPROVED ──worker pick──> RUNNING ──ok──> DONE
                       │                                       └─fail──> FAILED
                       └──reject──> REJECTED
```

### 7.2 dsar.request

```
RECEIVED ──identity check──> VERIFIED ──assign DPO──> PROCESSING
                  │                                       │
                  └─fail──> REJECTED (identity)           ├─collect data
                                                          ├─mask
                                                          ├─AWAITING_APPROVAL (legal + DPO)
                                                          │      │
                                                          │      └─reject──> REJECTED
                                                          ▼
                                                       DELIVERED (7d link expiry)
```

## 8. 与其他模块集成

| 模块 | 集成点 |
|---|---|
| **crypto** | Pseudonymize key from Vault transit; 销毁加密密钥；签销毁证书 |
| **lifecycle** | hard_delete 调本模块销毁证书生成；retention policy 默认值同步 |
| **dlp** | 外发到 test 环境前必须调 masking；脱敏后 sensitivity 自动降 1 级 |
| **audit** | 所有 export_job / DSAR / destruction / cross_border decision 必审 |
| **compliance** | ROPA 自动扫描 → 跨境管控决策的输入；DPIA 工作流编排 |
| **notification** | DSAR SLA 临期告警；销毁证书生成通知；跨境拒绝告警安全管理员 |
| **authz** | DPO / 法务角色定义；DSAR 工作流的审批人 |
| **identity** | DSAR 身份验证（强 MFA + 实名匹配）；订阅 `foundation.identity.user.hard_deleted` → 自动触发销毁证书生成流程（identity-v1 §10.1 已声明 data-protection 为该事件消费者） |

## 9. 部署形态差异

| 形态 | masking worker | DSAR 工作流 | 销毁证书 TSA |
|---|---|---|---|
| small | 1 实例同步降级 | 仅 API，无 UI | 自签名（无 TSA） |
| medium | 3-10 实例 | UI + 工单 | 公网 TSA（FreeTSA） |
| large | 20-100 实例（KEDA） | UI + 工单 + DPO 看板 | 国家授时中心 TSA |

## 10. 合规模式联动

| 模式 | 默认 |
|---|---|
| `pipl` | 启用告知 + 同意 + DSAR；跨境检测强制 |
| `gdpr` | DSAR SLA 30 天；明示同意；可被遗忘联动 lifecycle 销毁 |
| `hipaa` | PHI 脱敏 Safe Harbor 18 字段；销毁强度 ≥ NIST_800_88_PURGE |
| `finance_jrt0071` | 数据出院强制脱敏 + 4 眼审批 |
| `equal_protection_3` 及以上 | 销毁证书强制 + WORM 归档（用 compliance.is_at_least("equal_protection_3") helper 判定，不拼字符串后缀） |

## 11. 错误码

> SERVICE 段 = `DATA_PROTECTION`（与 CONVENTIONS §1.1 服务命名一致；4 段格式 `FOUNDATION.<SVC>.<CAT>.<NAME>` 见 errors.md §3.1）。

| code | HTTP |
|---|---|
| `FOUNDATION.DATA_PROTECTION.VALIDATION.MASKING_RULE_INCOMPLETE` | 400 |
| `FOUNDATION.DATA_PROTECTION.VALIDATION.MASKING_RULE_INVALID` | 400 |
| `FOUNDATION.DATA_PROTECTION.APPROVAL.REQUIRED` | 202 |
| `FOUNDATION.DATA_PROTECTION.POLICY.SOURCE_NOT_ACCESSIBLE` | 403 |
| `FOUNDATION.DATA_PROTECTION.STATE.LEGAL_HOLD_BLOCKING` | 409 |
| `FOUNDATION.DATA_PROTECTION.PRECONDITION.DESTRUCTION_NOT_READY` | 412 |
| `FOUNDATION.DATA_PROTECTION.COMPLIANCE.RESIDENCY_VIOLATION` | 403 |
| `FOUNDATION.DATA_PROTECTION.COMPLIANCE.CROSS_BORDER_NO_LEGAL_BASIS` | 403 |
| `FOUNDATION.DATA_PROTECTION.AUTHN.DSAR_IDENTITY_NOT_VERIFIED` | 401 |
| `FOUNDATION.DATA_PROTECTION.SLA.DSAR_EXPIRED` | 410 |
| `FOUNDATION.DATA_PROTECTION.COMPLIANCE.CONSENT_NOT_GRANTED` | 403 |
| `FOUNDATION.DATA_PROTECTION.COMPLIANCE.CONSENT_WITHDRAWN` | 403 |

> 同意/拒绝场景历史上有人用 HTTP 451 (Unavailable For Legal Reasons)，本项目统一用 403 + 在 RFC 9457 Problem Details 的 `type` URI 指向合规说明页（如 `https://docs.foundation/errors/consent-not-granted`），避免 451 未在 errors.md §4 状态码表覆盖。

## 12. 性能与容量

| 接口 | 目标 |
|---|---|
| mask_value | < 1ms（纯 CPU） |
| pseudonymize | < 5ms（Vault transit HMAC） |
| export_job 1000 万行 | < 30 min（10 并发 worker） |
| check_cross_border | < 10ms |
| DSAR access 数据收集 | < 24h（人工 + 自动混合）|

## 13. 待解决问题

| # | 问题 | 决策 |
|---|---|---|
| 1 | Pseudonymize key 轮换 | 不轮换（一致性需要）；轮换 = 销毁映射；提供「迁移工具」一次性重写 |
| 2 | 差分隐私 ε 选值 | v1 默认 1.0；v1.1 提供 calibrator |
| 3 | 销毁证书 PDF 多语言 | v1 中英双语；v1.1 多语言模板 |
| 4 | DSAR 跨服务数据收集机制 | 各 service 实现 `dsar_collector` hook（Python ABC）；compliance-service 编排 |
| 5 | 跨境检测的「数据流」识别 | v1 依赖 `@pii_processing` 装饰器 + 显式调 `check_cross_border`；v1.1 加运行时网络层探针 |
| 6 | DSAR 假冒身份风险 | 强 MFA + 验证实名 + 可疑请求人工二审；DPO 责任 |
| 7 | 备份中数据的删除 | tombstone + 下轮 backup rotation 实际清；备份保留期 ≤ 原数据保留期 |
| 8 | 第三方处理者（如 SMS 网关）的删除 forward | 注册时声明每个 third-party 的删除 endpoint；自动 webhook + 7d 确认 |
| 9 | 销毁证书 PDF 长期保存格式 | PDF/A-3 + 嵌入字体 + PAdES B-LT；保存 ≥ 10 年 |
| 10 | LLM Gateway 跨境 | 由 llm-gateway-service 调用 check_cross_border；cn-only 租户禁注册海外端点 |

## 14. 验证标准（A-M2 + A-M4）

| # | 验证项 | 通过 |
|---|---|---|
| 1 | mask 9 种方法 | unit test 100% |
| 2 | 一致性脱敏 | 同输入同输出，跨表 join 通过 |
| 3 | export_job 完整性 | 100w 行 source → target 行数一致 + 主键完整 + 抽样脱敏正确 |
| 4 | 审批流 | 未审批不可跑；rule 未覆盖列拒绝 |
| 5 | 销毁证书生成 | PDF/A-3 + 数字签名 + TSA 全部通过外部验证工具校验 |
| 6 | 跨境检测 | cn-only 租户调用海外端点 → deny + 告警 |
| 7 | DSAR 7 项权利 e2e | 7 个 right_type 全部走通 |
| 8 | DSAR SLA 监控 | 30 天倒计时；T-7 天告警 |
| 9 | 删除权与 Legal Hold 冲突 | Hold 优先；用户收到延期通知 |
| 10 | 告知书自动生成 | 扫描装饰器 → MD → 注册页展示 → 同意记录哈希链 |
| 11 | RLS 隔离 | 跨租户访问 export_job / dsar 失败 |
| 12 | 合规模式联动 | hipaa 默认启用 PHI 18 字段脱敏；pipl 默认启用 DSAR |
| 13 | 压测 | 10w/h DSAR 请求队列稳定 |

## 15. 实施排期

| Sprint | 内容 |
|---|---|
| A-M2 W2 | masking 引擎（9 种方法 + DSL 解析） |
| A-M2 W3 | export_job + 审批流（v0） |
| A-M2 W4 | 销毁证书 PDF 生成（v0，自签名） |
| A-M4 W1 | 跨境检测 + 数据驻留约束 |
| A-M4 W2 | DSAR 7 项权利 API + 工作流 |
| A-M4 W3 | 告知同意 + `@pii_processing` 装饰器扫描 |
| A-M4 W4 | TSA 集成 + WORM 归档 + 合规模式联动 |
