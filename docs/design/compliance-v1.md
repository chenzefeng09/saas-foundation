# Compliance 详细设计 v1

> 合规治理中枢：**合规模式注册** + **ROPA 自动扫描** + **DPIA 工作流** + **DSAR 编排** + **合规报表导出**（等保 / SOC 2 / ISO 27001 控制项映射）。

| 字段 | 值 |
|---|---|
| 状态 | Draft v1 |
| Owner | 合规 PM + 安全工程 |
| 实施 milestone | A-M4 |
| 相关文档 | data-protection / audit / identity / authz / cross-border-templates |

## 0. TL;DR

5 个子能力：

| 子能力 | 一句话 | 上下游 |
|---|---|---|
| **合规模式注册** | 7 个合规模式（等保 3/4 / 金融 / PIPL / GDPR / HIPAA / SOC2）的统一标识与联动机制 | 被所有模块订阅；启用模式联动各模块默认值 |
| **ROPA** | 自动扫描代码 `@pii_processing` 装饰器生成 GDPR Art.30 / PIPL §17 同款处理活动登记册 | 输出给 DPO / 审计 / 出境申报 |
| **DPIA** | 高风险场景启动评估工作流，输出报告 | 跨境 / 大规模 PI / 新技术启动 |
| **DSAR 编排** | 7 项权利的工作流编排（具体实现走 data-protection-v1 §5） | 编排器在本模块；数据收集 hook 在各 service |
| **合规报表** | 一键生成等保自评报告、SOC 2 控制项映射、ISO 27001 控制项映射 | 外审提交材料 |

## 1. Context

- 客户驱动：等保 / SOC 2 / ISO 审计经常要求一份「合规清单 + 证据」；散落在 18 个 package 的实现 → 需要 compliance 做编排和证据汇总
- 合规模式联动：客户启用「金融 JR/T 0071」→ 所有模块的密码策略 / 保留期 / 加密 / 审计粒度同步切换，不能让客户去 18 个 service 各自配
- ROPA 是 PIPL + GDPR 法律要求；手工维护 → 一年内必脱节；自动扫描是唯一可持续方案
- DSAR SLA 是硬指标（30 天 / GDPR 60 天），编排错过期 = 行政处罚

## 2. 合规模式注册

### 2.1 标识符（**唯一**真理来源）

```python
# foundation_compliance.modes
class ComplianceMode(str, Enum):
    EQUAL_PROTECTION_3 = "equal_protection_3"      # 等保三级
    EQUAL_PROTECTION_4 = "equal_protection_4"      # 等保四级
    FINANCE_JRT0071    = "finance_jrt0071"         # 金融 JR/T 0071-2020
    PIPL               = "pipl"                    # 中国 PIPL
    GDPR               = "gdpr"                    # 欧盟 GDPR
    HIPAA              = "hipaa"                   # 美国医疗 HIPAA
    SOC2               = "soc2"                    # SOC 2 Type II
    ISO27001           = "iso27001"                # ISO 27001
```

**铁律**：其他文档引用合规模式必须用以上标识符精确字符串；**禁用** `EP3` / `PIPL2021` / `equal_protection_3+` 等变体。

### 2.2 优先级（多模式叠加）

租户可启用多个模式（如「PIPL + finance_jrt0071 + equal_protection_3」）。各模块按「**取最严**」原则计算最终值。

举例：密码策略
| 模式 | 最小长度 | 失败锁定 |
|---|---|---|
| equal_protection_3 | 8 | 5 次 / 30 min |
| finance_jrt0071 | 12 | 3 次 / 30 min |
| gdpr | 推荐而非强制 | - |
| **取最严 → 实际生效** | **12** | **3 次 / 30 min** |

### 2.3 helper SDK

```python
from foundation_compliance import ComplianceClient, ComplianceMode

client = ComplianceClient.from_env()

# 查询租户启用了哪些模式
modes = client.modes.get_active(tenant_id="tnt_a")
# → [PIPL, FINANCE_JRT0071, EQUAL_PROTECTION_3]

# helper: 检查是否启用某模式
if client.modes.is_active(tenant_id, ComplianceMode.PIPL):
    ...

# helper: 是否启用了「至少等保 N」级（语义而非字符串）
if client.modes.is_at_least(tenant_id, ComplianceMode.EQUAL_PROTECTION_3):
    ...
# 内部映射：is_at_least(EP3) 命中条件 = 启用了 EP3 / EP4 任一
# 不要在调用方拼字符串后缀
```

### 2.4 模式联动机制

各模块启动时订阅 `foundation.compliance.mode.changed` 事件 → 重新计算自身默认值。

变更走审批：管理员申请 → 合规委员会审批 → 全审计 → 通知中心广播 → 各模块响应。
**不允许放宽只允许加严**（已启用 EP3 不能改成空；只能升 EP4 或不变）。

## 3. ROPA（处理活动登记册）

### 3.1 法律背景

- GDPR Art.30：控制者 + 处理者必须维护书面记录
- PIPL §17：告知 + 处理目的清单（实质相同）
- 内容：哪个组织 / 处理什么 PI 类型 / 目的 / 法律依据 / 保留期 / 共享对象 / 跨境传输 / 安全措施

### 3.2 数据来源：`@pii_processing` 装饰器

每个 service 代码用装饰器声明 PII 处理：

```python
from foundation_compliance import pii_processing, DataType, LegalBasis

@pii_processing(
    data_types=[DataType.PHONE, DataType.EMAIL, DataType.ID_CARD],
    purpose="user_authentication",
    legal_basis=LegalBasis.CONTRACT_PERFORMANCE,
    retention="3_years",
    shared_with=["third_party_sms_gateway"],
    cross_border=False,
    location="zh-cn",
)
def register_user(phone: str, email: str, id_card: str) -> User:
    ...
```

### 3.3 扫描器

**静态扫描**（CI 跑）：
- 用 `ast` 解析 Python AST 找所有 `@pii_processing` 装饰
- 生成 `ropa-scan-result.json`
- CI 检查：所有处理 PII 的函数必须声明装饰器（漏标 = build 失败）

**运行时探针**（生产辅助）：
- DB query 拦截（SQLAlchemy event）：检测 SELECT 命中 PII 列（用 tag 列标记） → 上报 ROPA
- API gateway 检测：response body 含 PII 字段 → 上报
- 用于发现「装饰器漏标」+ 「装饰器声明 vs 实际行为漂移」

### 3.4 ROPA 数据模型

```sql
CREATE TABLE compliance.processing_activity (
  tenant_id        TEXT NOT NULL,
  activity_id      TEXT NOT NULL,
  service          TEXT NOT NULL,           -- 'identity' / 'billing' / ...
  code_location    TEXT NOT NULL,           -- 'packages/identity/src/foundation_identity/users.py:register_user:42'
  function_name    TEXT NOT NULL,
  data_types       TEXT[] NOT NULL,
  purpose          TEXT NOT NULL,
  legal_basis      TEXT NOT NULL,
  retention_spec   TEXT NOT NULL,
  shared_with      TEXT[],
  cross_border     BOOLEAN NOT NULL DEFAULT FALSE,
  destinations     TEXT[],                  -- 跨境时填
  data_subjects    TEXT[],                  -- 数据主体类别（员工/客户/未成年人）
  security_measures TEXT[],                 -- 安全措施清单
  source           TEXT NOT NULL,           -- 'static_scan' / 'runtime_probe' / 'manual'
  first_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, activity_id)
);

CREATE TABLE compliance.processing_anomaly (
  tenant_id        TEXT NOT NULL,
  anomaly_id       TEXT NOT NULL,
  type             TEXT NOT NULL,           -- 'MISSING_DECORATOR' / 'DRIFT_FROM_DECLARATION' / 'UNAUTHORIZED_CROSS_BORDER'
  details          JSONB NOT NULL,
  resolved         BOOLEAN NOT NULL DEFAULT FALSE,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, anomaly_id)
);
```

### 3.5 ROPA 导出

```python
client.ropa.export(
    tenant_id="tnt_a",
    format="excel",            # 'excel' / 'pdf' / 'json'
    target_modes=[ComplianceMode.GDPR, ComplianceMode.PIPL],
    language="zh-CN",
)
# → 生成符合 GDPR Art.30 模板 + PIPL 同款字段的报告
```

## 4. DPIA（数据保护影响评估）

### 4.1 启动条件（自动检测）

任一即触发：
- 处理敏感 PI（健康 / 生物识别 / 14 岁以下未成年人 / 金融账户）→ ROPA `data_types` 命中
- 大规模处理（数据主体 > 100w）→ 每月统计
- 新技术应用（首次使用 ML / AI 决策）→ 模型注册时触发
- 公共场所大规模监控
- 跨境传输到非充分性认定地区
- 自动化决策对个人有重大影响

### 4.2 评估工作流

```
触发 ─→ 创建 DPIA → 填写表单（自动预填来自 ROPA）
                          ↓
                  风险识别（清单 + 自定义）
                          ↓
                  风险评分（似然 × 影响 = 等级）
                          ↓
                  风险 ≥ 高 → 缓解措施设计
                          ↓
                  DPO + 法务双审批
                          ↓
                  发布报告（PDF + 审计存证）
                          ↓
                  风险仍 > 可接受 → 暂停处理活动 + 监管咨询
```

### 4.3 表结构

```sql
CREATE TABLE compliance.dpia (
  tenant_id        TEXT NOT NULL,
  dpia_id          TEXT NOT NULL,
  trigger          TEXT NOT NULL,
  scope            JSONB NOT NULL,           -- 涉及哪些处理活动
  status           TEXT NOT NULL,            -- 'DRAFT'/'REVIEWING'/'APPROVED'/'PUBLISHED'/'EXPIRED'
  risks            JSONB,                    -- [{risk, likelihood, impact, score, mitigation}]
  residual_risk    TEXT,                     -- 'LOW'/'MEDIUM'/'HIGH'
  approvers        JSONB,                    -- {dpo: ..., legal: ..., approved_at: ...}
  pdf_uri          TEXT,
  effective_from   TIMESTAMPTZ,
  expires_at       TIMESTAMPTZ,              -- DPIA 1 年后失效需重做
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, dpia_id)
);
```

## 5. DSAR 编排（7 项权利）

> 详细 SLA / 7 项权利清单见 data-protection-v1 §5。本模块负责**跨 service 编排**。

### 5.1 各 service 实现 `dsar_collector` hook

```python
from foundation_compliance import dsar_collector, DSARContext, DataExport

@dsar_collector(service="identity")
async def collect_identity_data(ctx: DSARContext) -> DataExport:
    """根据 user_id 拉取本 service 的所有相关数据"""
    user = await get_user(ctx.user_id)
    sessions = await get_sessions(ctx.user_id)
    return DataExport(
        service="identity",
        records=[
            {"type": "profile", "data": user.dict()},
            {"type": "sessions", "data": [s.dict() for s in sessions]},
        ],
    )
```

每个 service 启动时通过 SDK 自注册到 compliance-service。

### 5.2 编排器

```
DSAR 请求 (right=access)
        ↓
compliance.dsar.start_workflow(request_id)
        ↓
1. 身份验证（强 MFA + 实名匹配）
2. 并发调所有 service 的 dsar_collector hook
3. 聚合结果 → data-protection.mask（按收件人 clearance 脱敏）
4. 法务 + DPO 双签
5. 生成加密下载链接（7d 过期）
6. 通知用户
7. 写 audit + 关闭工单
```

### 5.3 SLA 监控

cron 每小时跑：
- 距 sla_due_at < 7 天 → 通知 DPO + 业务负责人
- 距 sla_due_at < 1 天 → 通知 CTO（升级）
- 超期 → 自动写 audit 违规事件 + 通知合规委员会

## 6. 合规报表

### 6.1 等保 2.0 三级自评清单（211 项技术 + 70 项管理）

报表生成器：
- 每项控制项对应「模块 + 证据来源」
- 自动从模块拉证据（如「身份鉴别」从 identity 抽 MFA 启用率；「访问控制」从 authz 抽 RBAC 覆盖率）
- 输出 Excel + PDF + 证据 ZIP（含日志 / 截图 / 配置导出）

```python
client.reports.equal_protection(
    tenant_id="tnt_a",
    level=3,  # 三级
    output_format="zip",
    target_path="/tmp/ep3-report-tnt_a-2026Q2.zip",
)
```

### 6.2 SOC 2 Type II 控制项映射

- 5 个信任原则 × 控制项映射到模块
- Type II 需要 6 个月运行证据 → 自动从 audit 抽连续期内的证据
- 输出 Word 模板（外审公司常用）

### 6.3 ISO 27001 控制项映射

- 14 类 / 93 条控制项映射
- 缺口（管理类）标注「需平台方 ISMS 团队补」

### 6.4 PIPL / GDPR DPO 年度报告

- 自动汇总 ROPA + DSAR + DPIA + 事件统计
- DPO 签字后归档

## 7. SDK 完整接口

```python
client = ComplianceClient.from_env()

# 合规模式
client.modes.get_active(tenant_id)
client.modes.is_active(tenant_id, mode)
client.modes.is_at_least(tenant_id, mode)
client.modes.enable(tenant_id, mode, reason)             # 走审批
client.modes.disable(tenant_id, mode, reason)            # 走审批

# ROPA
client.ropa.register(activity_dict)                       # 手动注册（非装饰器场景）
client.ropa.list(tenant_id, filters)
client.ropa.export(tenant_id, format, target_modes)
client.ropa.anomalies(tenant_id, resolved=False)

# DPIA
client.dpia.create(scope, trigger)
client.dpia.submit_for_review(dpia_id)
client.dpia.approve(dpia_id, approver_role)
client.dpia.publish(dpia_id)
client.dpia.list_due_for_renewal(tenant_id)               # 即将到期需重做的

# DSAR（编排器；data-protection 提供具体能力）
client.dsar.start_workflow(request_id)
client.dsar.get_status(request_id)
client.dsar.list_due_soon(tenant_id, days=7)

# 报表
client.reports.equal_protection(tenant_id, level)
client.reports.soc2(tenant_id, period_start, period_end)
client.reports.iso27001(tenant_id)
client.reports.pipl_dpo_annual(tenant_id, year)
```

## 8. 与其他模块集成

| 模块 | 集成 |
|---|---|
| **identity** | 密码 / MFA / Session 策略读 compliance 模式 |
| **authz** | clearance 策略 / MFA step-up 触发条件读 compliance 模式 |
| **audit** | 保留期 / hash chain 强度按 compliance 模式 |
| **lifecycle** | retention 默认按 compliance 模式 |
| **crypto** | 算法选择（默认 vs 国密）按 compliance 模式 |
| **dlp** | 默认规则集启用按 compliance 模式 |
| **data-protection** | DSAR 实现层；销毁强度按 compliance 模式 |
| **pam** | 4 眼审批 / 录屏触发条件按 compliance 模式 |
| **billing** | 跨境支付场景需查 compliance |
| **llm-gateway** | 数据驻留约束读 compliance 模式 |
| **notification** | DSAR SLA / DPIA 审批 / 模式变更等通知 |
| **search** | 索引内容是否含 PII 字段按 compliance 模式审计 |
| **cross-border-templates**（本批 #23） | 提供 PIPL 标准合同 / 安评申报模板 |

## 9. 错误码

| code | HTTP |
|---|---|
| `FOUNDATION.COMPLIANCE.MODE.UNKNOWN` | 400 |
| `FOUNDATION.COMPLIANCE.MODE.CANNOT_DOWNGRADE` | 403 |
| `FOUNDATION.COMPLIANCE.ROPA.SCAN_FAILED` | 500 |
| `FOUNDATION.COMPLIANCE.ROPA.MISSING_DECORATOR` | 422 |（CI build 用） |
| `FOUNDATION.COMPLIANCE.DPIA.REVIEW_PENDING` | 202 |
| `FOUNDATION.COMPLIANCE.DPIA.HIGH_RISK_BLOCKED` | 403 |
| `FOUNDATION.COMPLIANCE.DSAR.HOOK_TIMEOUT` | 504 |
| `FOUNDATION.COMPLIANCE.DSAR.SLA_BREACH` | 410 |
| `FOUNDATION.COMPLIANCE.REPORT.GENERATION_FAILED` | 500 |

## 10. 部署形态

| 形态 | ROPA 扫描 | DPIA UI | 报表生成 |
|---|---|---|---|
| small | CI only | API only | API only |
| medium | CI + 每日 cron | 控制台 + 工作流 | 控制台 |
| large | + 运行时探针 | + DPO 看板 | + 自动化定期生成 + 邮件发送 |

## 11. 性能与容量

| 指标 | 目标 |
|---|---|
| modes.is_active() | < 1ms（Redis 缓存） |
| ROPA 全租户扫描 | < 5 min |
| 等保报表生成 | < 10 min（含证据抽取） |
| DSAR workflow 编排 | < 24h（人工 + 自动混合） |

## 12. 待解决问题

| # | 问题 | 决策 |
|---|---|---|
| 1 | 装饰器漏标的兜底 | runtime 探针（DB query 拦截 + API response 检测） + CI 强制 |
| 2 | ROPA 多语言报告 | 内置 zh-CN / en-US；其他需第三方翻译 |
| 3 | 合规模式启用是否要审批 | 强制（启用 = 加严 = 不可放弃；禁用 = 放宽 = 需合规委员会审批） |
| 4 | DPIA 模板法律风险 | 模板仅参考；最终风险评估由 DPO + 法务负责 |
| 5 | DSAR 收件人身份冒用 | 强 MFA + 实名匹配 + 可疑请求人工二审 |
| 6 | 等保自评机制是否可代替正式测评 | 不可；自评只是预检 + 内部证据；正式测评需 CNCA 认证机构 |
| 7 | SOC 2 6 月运行证据 | 平台从 v1.0 上线即开始自动采集；用户启用即 enable |
| 8 | 合规咨询机构对接 | 平台提供数据接口；咨询机构外部使用，不入产品 |

## 13. 验证标准（A-M4 出口）

| # | 验证 | 通过 |
|---|---|---|
| 1 | 7 个合规模式 | 全部可启用 / 查询 / 联动各模块 |
| 2 | 模式叠加取最严 | 密码长度 / 保留期 / 加密算法 3 项 e2e |
| 3 | is_at_least 语义 | EP4 启用时 is_at_least(EP3) = true |
| 4 | ROPA 静态扫描 | 18 个 package 全跑通 → 全函数 PII 标注覆盖率 ≥ 80% |
| 5 | ROPA 运行时探针 | 模拟漏标 → 探针检测 + 写 anomaly |
| 6 | ROPA 报告导出 | GDPR + PIPL 双标准 Excel 输出，DPO 验证字段完整 |
| 7 | DPIA 工作流 | 触发 → 审批 → 发布全流程 |
| 8 | DSAR 编排 | 7 种 right_type 全部走通；18 个 service hook 全部响应 |
| 9 | DSAR SLA | 模拟 25 天 → 提醒；30 天 → 升级 |
| 10 | 等保报表 | 211 项控制项 100% 映射；证据抽取成功率 ≥ 90% |
| 11 | SOC 2 报表 | 5 信任原则映射完整；证据 6 月运行期 |
| 12 | 合规模式变更审计 | 启用 / 禁用全审计 + 通知中心广播 |
| 13 | RLS | 跨租户查询 ROPA / DPIA / DSAR 失败 |
| 14 | 性能 | 全租户报告生成 < 10 min |
