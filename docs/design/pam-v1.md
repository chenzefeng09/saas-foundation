# PAM（特权账号管理）详细设计 v1

> Privileged Access Management：管理员日常用普通账号，**特权操作走 JIT 提权**（Just-In-Time）；高敏操作必经**四眼审批**；所有特权会话**全程录屏**；与现有堡垒机集成或部署 Teleport。

| 字段 | 值 |
|---|---|
| 状态 | Draft v1 |
| Owner | 安全工程 + Identity 后端 |
| 实施 milestone | A-M3 |
| 相关文档 | identity / authz / audit / notification / crypto |

## 0. TL;DR

- **三类特权对象**：基础设施（SSH/K8s/DB 主机）、应用（admin 控制台、超管 API）、密钥/凭据（KMS root key、备份密钥）
- **JIT 模型**：默认无任何特权；申请 → 审批 → 临时授予（≤4h）→ 到期自动收回
- **四眼审批**：高敏操作（删除生产数据、修改核心配置、特权账号变更、密钥销毁）≥ 2 人审批，1 人执行 + 1 人在线见证
- **录屏 + 命令日志**：所有 SSH / Web 控制台 / DB 会话录屏（asciinema / 视频）+ 命令日志 WORM 存储
- **集成路径**：① 内置 Teleport（无堡垒机客户） ② 适配客户已有堡垒机（齐治 / JumpServer / 行云）
- **高危命令实时阻断**：`rm -rf /`、`DROP DATABASE`、`DELETE FROM users WHERE 1=1` 等命中即 kill session + 告警
- **特权账号清单**：每季度审计，僵尸账号自动禁用；密码 30 天自动轮换

## 1. Context

- 等保三级要求：「应严格限制具有特权账号的人员」「应建立特权账号操作过程的安全审计与告警机制」
- 金融 JR/T 0071：「数据库 root、操作系统 root 不允许日常使用，必须 JIT 申请」
- PCI DSS 7.x：「按需授予最小权限 + 完整审计」
- 行业事故：80%+ 内部威胁来自滥用特权账号；零信任的关键控制点
- 客户多有自有堡垒机：底座要**适配而非取代**

## 2. 特权对象分类

| 类别 | 示例 | 接入方式 |
|---|---|---|
| **Infra-SSH** | 生产环境 Linux 主机 | Teleport SSH proxy / 客户堡垒机 SSH 代理 |
| **Infra-K8s** | K8s cluster-admin / namespace-admin | Teleport K8s proxy / kubectl 包裹层 |
| **Infra-DB** | Postgres super、ClickHouse default、MongoDB root | Teleport DB proxy / 客户堡垒机 |
| **App-Admin** | 底座 admin console、Keycloak admin、Vault root | OAuth + RBAC（不需要堡垒机，但需 JIT）|
| **Secret-Mgmt** | KMS root key 解封、备份密钥销毁、TLS root CA | 强 MFA + 四眼 + 物理隔离（部分） |
| **Cloud-Console**（SaaS only） | AWS root、阿里云主账号 | AWS IAM Identity Center / 阿里云 RAM + JIT |

## 3. JIT 提权流程

```
[User: alice]                   [PAM-svc]              [Approver: bob, carol]
     │                              │                          │
     │── request_elevation ────────→│                          │
     │  {target: prod-db-01,        │                          │
     │   role: postgres-admin,      │── notification ─────────→│
     │   duration: 30min,           │                          │
     │   reason: "incident-1234"}   │                          │
     │                              │                          │
     │                              │←──── approve (bob) ──────│
     │                              │←──── approve (carol) ────│
     │                              │ (满足 4 眼，2/2)         │
     │                              │                          │
     │← grant {credential, expiry}──│                          │
     │                              │                          │
     │── access (with cred) ────→ [Teleport / 堡垒机]           │
     │                                ↓                         │
     │                            录屏 + 命令日志               │
     │                                ↓                         │
     │                            实时告警引擎                  │
     │                                ↓                         │
     │── (T+30min)                ←自动 revoke──────             │
     │                              │                          │
     │   ←  notification: 会话结束 ←                            │
```

### 3.1 申请 API

```python
from foundation_pam import PAMClient, ElevationRequest

client = PAMClient.from_env()

req = client.elevations.request(
    target_type="db",
    target_id="prod-pg-cluster-01",
    role_id="postgres-admin",
    duration_min=30,
    reason="incident-1234: investigate slow query",
    ticket_id="INC-1234",       # 关联工单
)
# → {request_id, status="pending_approval", required_approvals=2, expiry=...}
```

### 3.2 审批 API

```python
# 审批人收到通知后调用
client.elevations.approve(
    request_id="elv_01J7XYZ",
    approver_id="usr_bob",
    decision="approve",          # 'approve' / 'reject'
    note="同意，但限 30min",
)

# 审批通过自动签发 credential
cred = client.elevations.get_credential(request_id="elv_01J7XYZ")
# → 临时 cert / token，duration 内有效
```

### 3.3 临时凭据签发

**Infra-SSH/K8s/DB**：
- Teleport 集成时，PAM-svc 调 `tctl auth sign` 签发短时 cert（30min-4h）
- 客户堡垒机集成时，PAM-svc 调堡垒机 API 创建临时账号 + 临时密码

**App-Admin**：
- 临时角色绑定（authz `role_binding` 表带 `expires_at` 字段，authz-v1 §3.5 已存在）
- 通过 authz SDK：`authz.role_bindings.create(user_id, role_id, expires_at, granted_by="pam-svc", reason=...)`
  - 该 SDK 入口需 authz-v1 §6 补充暴露（**driven by PAM**：authz-v1 v1.0.1 加 changelog）
  - authz-service 后台 cron 每分钟扫 `expires_at < now()` 的 binding → 自动 revoke + 发事件 `foundation.authz.role.expired`
- 用户重新走 step-up MFA + 拿到临时 token
- 不签发新凭据，复用现有 session

**Secret-Mgmt**：
- Vault root token 不签发；改为「unseal 流程」（Shamir secret sharing）
- 临时授予 `policy:write` Vault policy → 操作 → 解除

### 3.4 自动收回（到期）

- PAM-svc 后台 cron 每 30s 扫到期 elevation
- 触发 revoke：
  - Teleport: 撤销 cert（加入 CRL）
  - 客户堡垒机: 删除临时账号
  - App-Admin: 移除 role_binding
- 通知用户「特权已收回」
- 写 audit

### 3.5 提前撤销

- 用户主动 release（任务完成早）
- 安全管理员强制撤销（异常行为检测）
- 自动撤销（高危命令命中、异常 IP 接入）

## 4. 四眼审批（Two-Person Rule）

### 4.1 强制四眼场景

| 操作 | 审批人数 | 备注 |
|---|---|---|
| 生产 DB DELETE/DROP/TRUNCATE | 2 | 第二人在线见证 |
| 删除生产 K8s namespace | 2 | |
| 修改 OPA bundle production channel | 2 | |
| 销毁加密密钥（lifecycle CRYPTO_KEY_DESTROY）| 2 + DPO | 3 人 |
| 修改特权账号清单 | 2 | |
| Vault unseal / root token 使用 | 2 | Shamir 3/5 |
| 跨境数据传输生效 | 2 + 法务 | 3 人 |
| L5 绝密资源访问 | 2 | + 录屏 |
| 备份恢复到生产 | 2 | |
| 修改租户合规模式 | 2 | |

### 4.2 见证人在线检测

「在线见证」≠ 只是审批：
- 审批人收到通知 → 在 PAM 控制台进入「见证模式」
- 实时观看操作者的录屏 + 命令日志
- 见证人可一键 kill session
- 会话结束时见证人签字（电子签名）

实现：WebSocket 实时推送录屏帧 + 命令；见证人前端展示。

### 4.3 审批超时

- 默认审批窗口 30 min
- 超时未审批 → 申请自动 expire
- 紧急通道：1 人审批 + 事后 4 眼复盘（仅 incident severity=critical 允许）

## 5. 录屏与命令日志

### 5.1 SSH 会话

- Teleport 原生录屏（asciinema-like，可回放命令）
- 客户堡垒机：调用其录像导出 API，每会话结束拉取 .mp4 / .cast 文件
- 存储：MinIO/S3 `worm` bucket，retention 同审计（≥6 月，金融 1 年）

### 5.2 Web 控制台

- 浏览器录屏：rrweb 注入到 admin console
- 服务端 capture：每页操作的 DOM snapshot + 用户事件
- 优势：可搜索（不是视频）

### 5.3 命令日志（结构化）

每条命令一条 row：
```json
{
  "session_id": "ses_01J7XYZ",
  "user_id": "usr_alice",
  "target": "prod-db-01",
  "command": "SELECT * FROM users WHERE id=1",
  "timestamp": "...",
  "duration_ms": 23,
  "rows_affected": 1,
  "risk_score": 5,
  "flagged_rules": []
}
```

写 ClickHouse，索引 `(tenant_id, user_id, timestamp)`。

## 6. 高危命令实时阻断

### 6.1 规则库

```yaml
rules:
  - id: rm-rf-root
    pattern: "^rm\\s+-rf\\s+/"
    severity: critical
    action: kill_session
    notify: [security-admin, on-call]

  - id: drop-database
    pattern: "(?i)^DROP\\s+(DATABASE|SCHEMA|TABLE)\\s+"
    targets: [db]
    severity: critical
    action: kill_session
    require_4eye: true     # 即使在 4 眼模式也再次确认

  - id: delete-no-where
    pattern: "(?i)^DELETE\\s+FROM\\s+\\w+\\s*(?:;|$)"   # 无 WHERE
    severity: critical
    action: kill_session

  - id: chmod-777
    pattern: "chmod\\s+777"
    severity: high
    action: alert_only

  - id: curl-pipe-sh
    pattern: "curl.*\\|\\s*(sh|bash)"
    severity: high
    action: kill_session
```

### 6.2 执行架构

- Teleport: 通过 audit log streaming 实时分析
- 客户堡垒机: 接入 syslog / API 实时获取命令
- 规则引擎：Python regex pool；命中即调 PAM-svc kill API + 通知

**注意**：阻断的是「再下一条命令」；当前命令可能已部分执行。需 transactional / dry-run preview 作为补充控制。

### 6.3 DB 命令拦截深化

对 DB 命令做语义分析（v1.1）：
- 解析 SQL AST
- 检测「UPDATE 无 WHERE」「DELETE 影响行数 > 阈值」
- 改写为 `EXPLAIN` 预跑评估影响

## 7. 特权账号清单管理

### 7.1 清单维护

```sql
CREATE TABLE pam.privileged_account (
  tenant_id        TEXT NOT NULL,
  account_id       TEXT NOT NULL,
  account_name     TEXT NOT NULL,           -- postgres / root / admin
  target_type      TEXT NOT NULL,           -- 'db'/'host'/'k8s'/'app'/'cloud'
  target_id        TEXT NOT NULL,
  account_type     TEXT NOT NULL,           -- 'shared'/'individual'/'service'
  owner_user_id    TEXT,                    -- individual / service 必填
  rotation_policy  JSONB NOT NULL,          -- {auto_rotate: true, interval_days: 30}
  last_rotated_at  TIMESTAMPTZ,
  last_audit_at    TIMESTAMPTZ,
  status           TEXT NOT NULL,           -- 'active'/'suspended'/'deprecated'
  notes            TEXT,
  PRIMARY KEY (tenant_id, account_id)
);
```

### 7.2 季度审计

- cron 每季度生成「特权账号清单审计报告」
- 内容：账号清单 + 最后使用时间 + 轮换情况 + 异常事件
- 自动检测：
  - 90 天未使用 → 标 `inactive` → 通知 owner 确认 → 30 天后 auto-suspend
  - 未按 rotation_policy 轮换 → 高优告警
  - shared 账号无 4 眼审计记录 → 违规告警

### 7.3 密码轮换

- service account 密码 30 天自动轮换（默认）
- 轮换前 7 天通知 owner（如果是人持有的）
- 新密码加密存 Vault；旧密码 24h 后销毁

### 7.4 独立账号原则

- 禁止「张三 = postgres = vault-admin = backup-operator」一人多账号
- 同一职能用独立账号，提权审批 + 录屏 + 撤销分别走
- shared 账号（如 `postgres`）原则上禁用；不可避免时强制 4 眼 + 录屏

## 8. 集成路径

### 8.1 内置 Teleport（默认，无堡垒机客户）

- Teleport Open Source（Apache 2.0）部署
- PAM-svc 调 Teleport API：
  - `tctl users add` 创建 user
  - `tctl auth sign` 签发临时 cert
  - `tctl get sessions` 查会话
  - `tctl rm` 销毁
- Teleport audit log → ClickHouse audit pipeline

部署形态：
- small: Teleport single-node
- medium: Teleport HA（3 auth + 3 proxy）
- large: + DR cluster

### 8.2 适配客户堡垒机

通用适配层 + 厂商适配器：

```python
class BastionAdapter(ABC):
    @abstractmethod
    def create_temp_account(self, user_id, target_id, role, duration_min) -> Credential: ...
    @abstractmethod
    def revoke_account(self, credential_id) -> None: ...
    @abstractmethod
    def stream_session_log(self, session_id) -> AsyncIterator[CommandEntry]: ...
    @abstractmethod
    def export_recording(self, session_id) -> bytes: ...
    @abstractmethod
    def kill_session(self, session_id) -> None: ...
```

适配器实现（v1）：
- `TeleportAdapter`（默认）
- `JumpServerAdapter`（开源堡垒机，国内常见）
- `QiZhiAdapter`（齐治堡垒机，金融常见）
- `XingYunAdapter`（行云堡垒机，政务常见）

v1.1 + v1.2 按客户需求增。

### 8.3 客户堡垒机不暴露 API 的兜底

- 让客户在堡垒机配 syslog → PAM-svc
- 录像通过 SFTP 定期拉取
- 牺牲实时性，但保证审计可用

## 9. 数据模型

```sql
-- 提权请求
CREATE TABLE pam.elevation_request (
  tenant_id        TEXT NOT NULL,
  request_id       TEXT NOT NULL,
  user_id          TEXT NOT NULL,
  target_type      TEXT NOT NULL,
  target_id        TEXT NOT NULL,
  role_id          TEXT NOT NULL,
  reason           TEXT NOT NULL,
  ticket_id        TEXT,
  duration_min     INT NOT NULL,
  required_approvals INT NOT NULL,
  current_approvals INT NOT NULL DEFAULT 0,
  status           TEXT NOT NULL,    -- 'pending_approval'/'approved'/'rejected'/'granted'/'revoked'/'expired'
  granted_at       TIMESTAMPTZ,
  expires_at       TIMESTAMPTZ,
  revoked_at       TIMESTAMPTZ,
  revoke_reason    TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, request_id)
);

-- 审批记录
CREATE TABLE pam.approval (
  tenant_id        TEXT NOT NULL,
  approval_id      TEXT NOT NULL,
  request_id       TEXT NOT NULL,
  approver_id      TEXT NOT NULL,
  decision         TEXT NOT NULL,    -- 'approve'/'reject'
  note             TEXT,
  decided_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, approval_id)
);

-- 会话
CREATE TABLE pam.session (
  tenant_id        TEXT NOT NULL,
  session_id       TEXT NOT NULL,
  request_id       TEXT NOT NULL,
  user_id          TEXT NOT NULL,
  target_type      TEXT NOT NULL,
  target_id        TEXT NOT NULL,
  started_at       TIMESTAMPTZ NOT NULL,
  ended_at         TIMESTAMPTZ,
  ended_reason     TEXT,    -- 'normal'/'killed_by_rule'/'killed_by_admin'/'timeout'
  recording_uri    TEXT,
  command_count    INT,
  flagged_count    INT,
  witness_user_ids TEXT[],
  PRIMARY KEY (tenant_id, session_id)
);

-- 命令日志（高频，写 ClickHouse 主表；PG 只存 flagged 的）
CREATE TABLE pam.flagged_command (
  tenant_id        TEXT NOT NULL,
  flag_id          TEXT NOT NULL,
  session_id       TEXT NOT NULL,
  command          TEXT NOT NULL,
  rule_id          TEXT NOT NULL,
  severity         TEXT NOT NULL,
  action_taken     TEXT NOT NULL,
  timestamp        TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, flag_id)
);
```

## 10. 与其他模块集成

| 模块 | 集成点 |
|---|---|
| **identity** | 用户身份；申请人/审批人/见证人来源 |
| **authz** | role 定义；JIT 临时 role_binding |
| **audit** | 所有 elevation/approval/session/flagged 必审 |
| **notification** | 审批通知、见证邀请、撤销通知、高危告警 |
| **crypto** | 临时凭据存 Vault；secret rotation |
| **lifecycle** | 销毁密钥 → 4 眼审批入口在本模块 |
| **dlp** | L5 资源访问入本模块（4 眼） |
| **compliance** | 季度审计报告归档 |
| **security-ops** | 应急响应触发的特权操作（事故 runbook） |

## 11. 错误码

| code | HTTP |
|---|---|
| `FOUNDATION.PAM.ELEVATION.INSUFFICIENT_APPROVAL` | 403 |
| `FOUNDATION.PAM.ELEVATION.EXPIRED` | 410 |
| `FOUNDATION.PAM.ELEVATION.ALREADY_GRANTED` | 409 |
| `FOUNDATION.PAM.APPROVAL.SELF_APPROVAL_FORBIDDEN` | 403 |
| `FOUNDATION.PAM.APPROVAL.WINDOW_EXPIRED` | 410 |
| `FOUNDATION.PAM.SESSION.KILLED_BY_RULE` | 403 |
| `FOUNDATION.PAM.SESSION.WITNESS_REQUIRED` | 412 |
| `FOUNDATION.PAM.ACCOUNT.ROTATION_OVERDUE` | 503 |
| `FOUNDATION.PAM.BASTION.UNREACHABLE` | 503 |

## 12. 部署形态

| 形态 | Teleport | Bastion adapter | 录屏存储 |
|---|---|---|---|
| small | 单节点 | 仅 Teleport | local disk |
| medium | HA (3+3) | + JumpServer | MinIO WORM |
| large | HA + DR | + 齐治/行云适配 | MinIO 分布式 EC + 跨 AZ |

## 13. 性能与容量

| 指标 | 目标 |
|---|---|
| elevation request → grant | P95 < 5min（人工审批时间不算） |
| 自动 revoke 延迟 | < 30s |
| 高危命令检测延迟 | < 200ms |
| kill_session 延迟 | < 1s |
| 录屏存储 | 1 小时 SSH = 5MB；1 小时 Web = 50MB |

## 14. 待解决问题

| # | 问题 | 决策 |
|---|---|---|
| 1 | 见证人不在线时怎么办 | 申请阶段强制选 ≥3 个候选人；至少 1 在线才能 grant |
| 2 | 录屏存储成本爆炸 | 视频压缩 + cold tier 30 天后归档；命令日志单独存（更可搜） |
| 3 | 紧急 incident 通道 | 1 人审批 + 强制 critical 等级 + 事后 24h 内 4 眼复盘签字 |
| 4 | 自我审批 | 严禁；同一人不能既是 requester 也是 approver |
| 5 | 客户堡垒机不接 syslog | 兜底方案：用户日志 SFTP 定期拉；牺牲实时但保审计 |
| 6 | Teleport license（开源版限制） | OSS 版功能够用；Enterprise license 仅大客户按需 |
| 7 | DB 命令语义分析 | v1 regex；v1.1 接入 SQL parser |
| 8 | 跨 AZ 提权 propagation 延迟 | Teleport 多 AZ 自动同步；客户堡垒机视厂商 |
| 9 | 季度审计自动化深度 | v1 生成报告 + 关键异常自动通知；v1.1 自动 suspend 决策 |
| 10 | 用户对录屏的合规告知 | 登录前明示「特权会话录屏并保存 N 月」+ 用户签字同意 |

## 15. 验证标准（A-M3 出口）

| # | 验证 | 通过 |
|---|---|---|
| 1 | JIT 提权 e2e | 申请 → 审批 → 拿凭据 → 操作 → 到期自动撤销 |
| 2 | 4 眼审批 | 1 人审批不能 grant；2 人审批后才生效 |
| 3 | 自我审批拒绝 | requester=approver 时拒绝 |
| 4 | 见证模式 | 实时录屏推送 + 一键 kill 测试通过 |
| 5 | 高危命令阻断 | `rm -rf /` / `DROP DATABASE` 命中即 kill + 告警 |
| 6 | 录屏存储 | 1 小时 SSH session 录屏可回放 |
| 7 | Teleport 集成 | OSS 版 SSH + K8s + DB 三类目标接入 |
| 8 | JumpServer 适配 | 创建临时账号 + 撤销 + syslog 命令日志 |
| 9 | 自动收回 | T+1h 到期 cert 失效 + role_binding 移除 |
| 10 | 季度审计 | 自动生成报告；inactive 账号检测 |
| 11 | 密码轮换 | 30 天到期自动轮换 + 通知 owner |
| 12 | 与 lifecycle 集成 | 销毁密钥流程必走 4 眼 PAM 申请 |
| 13 | RLS | 跨租户查询 elevation/session 失败 |
| 14 | 审计完整 | 申请/审批/grant/revoke/session/flag 全在 audit |
| 15 | 紧急通道 | critical 1 人审批生效；24h 内复盘签字否则锁账户 |
