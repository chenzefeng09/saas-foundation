# Identity Service — 设计文档 v0.1

> P0 #4 产出。覆盖 A-M1 范围。配套：
> - [CONVENTIONS.md](../CONVENTIONS.md)
> - [errors.md](../errors.md)
> - [multi-tenancy.md](../multi-tenancy.md)
>
> 后续 ADR 决议会回写本文档。重大改动需 ≥2 架构师 sign-off。

---

## 1. Context（为什么做）

`identity-service` 是底座所有能力的"前门"——任何调用 foundation 任何 service 的请求都要先经它认证、由它颁发可被网关验证的 JWT。它必须：

1. 把 Keycloak 这个"功能极多但复杂"的开源组件**封装成稳定窄接口**，让业务永远不直接打 Keycloak
2. 提供企业 SSO（OIDC / SAML / AD / LDAP / 钉钉企业版 / 飞书企业版 / 企业微信）
3. 提供**可被租户管理员开关**的社交登录（Google / GitHub / 微信 / QQ / Apple / 微软个人版 / 钉钉个人版 / 飞书个人版）
4. 实现合规模式驱动的密码策略 / MFA 强制策略 / 会话超时与并发限制
5. 实现 SCIM 2.0 server 让企业 HR 系统（含**适配钉钉企业版非标准 API**）能自动同步用户和离职信号
6. 支持紧急冻结：1 小时内禁用全部 token + 终止活跃会话
7. 让租户管理员**不接触 Keycloak Admin Console** 也能完成所有日常运营

### 关键技术决定（已定型）

| 维度 | 决定 | 理由 |
|---|---|---|
| Keycloak 多租户模型 | **单 realm + Organizations**（Keycloak 26 GA 特性） | 抛弃 realm-per-tenant；用户跨租户共享、组织级 IdP / 主题、性能不随租户数下降 |
| Keycloak 版本 | 26.x LTS | Organizations GA、Organization Groups（26.6+）支持部门层级 |
| 与组织 service 的关系 | Keycloak Organization ↔ `org.tenant` **1:1 强绑定** | 双写在 identity-service 内统一管理；防 Keycloak 与 DB 漂移 |
| 部门/团队/用户 | Postgres `org.*` 是事实源；Keycloak Organization Groups 仅做认证侧缓存 | 业务侧四层结构（CONVENTIONS）由 `org-service` 主导 |
| JWT | RS256 / 国密 SM2（合规模式时） | Keycloak realm key + 国密 provider（v1.1） |
| 钉钉 SCIM | **自研反向适配器**（轮询通讯录 API + 订阅离职事件） | 钉钉不提供标准 SCIM server |
| MFA | TOTP / WebAuthn / 短信 OTP / 推送 | TOTP+WebAuthn 首版必选；短信走通知中心 |
| 密码哈希 | Argon2id（默认）/ SM3-HMAC（合规模式） | 通过 `crypto-service` 抽象层 |
| 会话存储 | Keycloak 自管 + Redis cache | Keycloak 内置 Infinispan + 外置 Redis 提速 |
| 紧急冻结 | Keycloak admin event + 直推 Redis 黑名单 | 网关 JWT 校验时 ≤1s 内生效 |

---

## 2. 职责边界

### identity-service 负责

- 用户身份相关：注册（仅管理员邀请 / SaaS 自助）/ 登录 / 登出 / 会话刷新
- 多因素：MFA 注册 / 校验 / 重置 / 设备管理
- SSO：企业 IdP（OIDC / SAML / AD / LDAP）配置 + 联合登录
- 社交登录：管理员可见的 provider 池 + 租户级开关 + 首次登录企业域绑定
- SCIM 2.0 server：被 Azure AD / Okta 推送 / 拉取
- 钉钉企业版反向适配器：定时拉取通讯录 + 订阅离职 webhook
- 密码策略 / 会话超时 / 并发限制 / 失败锁定的执行
- 紧急冻结 + 离职 + 软删除 + 硬删除生命周期
- 用户档案核心字段（**业务扩展字段不在这里**，归 `org-service`）

### identity-service 不负责

- 角色与权限定义、权限检查 → `authz-service`
- 部门 / 团队 / 用户业务属性 / 上下级关系 → `org-service`
- 套餐 / 配额 / 用户席位计数 → `billing-service`
- 操作录屏 / JIT 提权 → `pam-service`
- 个人信息处理告知 / DSAR → `compliance-service` + `data-protection-service`
- 通知（验证邮件、邀请邮件等） → 调 `notification-service`

### 与其他 service 的交互

```
       ┌────────────────────────────────────┐
       │ Browser / Client                   │
       └───┬────────────────────────────────┘
           │ /api/identity/v1/sessions（登录）
           ▼
       ┌────────────────────────────────────┐
       │ API Gateway (Envoy)                │
       │  ↳ 校验 JWT (Keycloak JWKS)         │
       │  ↳ 命中黑名单 → 401                 │
       │  ↳ 注入 X-Tenant-Id / X-User-Id    │
       └───┬────────────────────────────────┘
           ▼
       ┌────────────────────────────────────┐
       │ identity-service (FastAPI)         │
       │  ↳ Keycloak Admin API 调用         │
       │  ↳ Postgres identity.* 写入         │
       │  ↳ 发事件 foundation.identity.*    │
       └───┬─┬─┬─────┬───────┬──────────────┘
           │ │ │     │       │
           ▼ ▼ ▼     ▼       ▼
   Keycloak Vault  authz   audit   notification
                    (角色) (审计)   (邮件)
```

---

## 3. 数据模型

> 完整 schema 在 `packages/identity/migrations/`。这里给关键表的字段、索引、RLS policy。
> 所有表遵循 [multi-tenancy.md §6](../multi-tenancy.md#6-schema-约定)。

### 3.1 表清单

| 表 | 用途 | RLS | 备注 |
|---|---|---|---|
| `identity.user` | 用户档案 | ✅ | 与 Keycloak user 1:1，Keycloak 是事实源，本表是缓存 + 业务字段补充 |
| `identity.session_ref` | 会话引用 | ✅ | 不存 token，仅做审计与"杀会话"索引 |
| `identity.mfa_credential` | MFA 凭据元数据 | ✅ | TOTP secret / WebAuthn public key 存在 Keycloak / Vault，这里存元 |
| `identity.tenant_sso_config` | 租户级 SSO 配置 | ✅ | 哪个租户启用 OIDC/SAML/AD 等，凭据走 Vault |
| `identity.tenant_social_login_config` | 租户级社交登录开关 | ✅ | provider 启用列表 |
| `identity.scim_external_ref` | SCIM 外部系统 → user_id 映射 | ✅ | 解决幂等 + 反查 |
| `identity.password_policy_override` | 租户级密码策略覆盖 | ✅ | 在合规模式基线上加严 |
| `identity.account_event` | 账号关键事件本地副本 | ✅ | 与 audit 解耦的快速查询入口 |
| `identity.frozen_token_blacklist` | 紧急冻结的 token / user / session | ✅ | Redis mirror，DB 是兜底 |
| `identity.invite` | 邀请记录 | ✅ | 管理员邀请的待激活用户 |

### 3.2 `identity.user`（核心表示例）

```sql
CREATE TABLE identity.user (
    id                 TEXT PRIMARY KEY CHECK (id ~ '^usr_[0-9A-Z]{26}$'),
    tenant_id          TEXT NOT NULL REFERENCES tenant.tenant(id),
    keycloak_user_id   TEXT NOT NULL UNIQUE,                        -- KC 内部 UUID
    email              TEXT NOT NULL,
    email_verified     BOOLEAN NOT NULL DEFAULT false,
    phone              TEXT,
    phone_verified     BOOLEAN NOT NULL DEFAULT false,
    display_name       TEXT,
    locale             TEXT NOT NULL DEFAULT 'zh-CN',
    status             TEXT NOT NULL DEFAULT 'INVITED'
                       CHECK (status IN ('INVITED', 'ACTIVE', 'SUSPENDED', 'LOCKED', 'DEACTIVATED')),
    mfa_enabled        BOOLEAN NOT NULL DEFAULT false,
    last_login_at      TIMESTAMPTZ,
    last_login_ip      INET,
    failed_attempts    INT NOT NULL DEFAULT 0,
    locked_until       TIMESTAMPTZ,
    password_changed_at TIMESTAMPTZ,
    must_change_password BOOLEAN NOT NULL DEFAULT false,
    -- SCIM 同步关联
    scim_provisioned_by TEXT,                                       -- 'azure-ad' / 'okta' / 'dingtalk' / NULL
    scim_external_id    TEXT,
    -- 元
    metadata           JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at         TIMESTAMPTZ,                                 -- 软删
    created_by         TEXT,
    updated_by         TEXT
);

CREATE INDEX user_tenant_id_idx        ON identity.user (tenant_id);
CREATE UNIQUE INDEX user_tenant_email_idx
    ON identity.user (tenant_id, lower(email)) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX user_tenant_phone_idx
    ON identity.user (tenant_id, phone) WHERE deleted_at IS NULL AND phone IS NOT NULL;
CREATE INDEX user_status_idx           ON identity.user (tenant_id, status) WHERE deleted_at IS NULL;
CREATE INDEX user_keycloak_idx         ON identity.user (keycloak_user_id);
CREATE INDEX user_scim_external_idx
    ON identity.user (scim_provisioned_by, scim_external_id) WHERE scim_external_id IS NOT NULL;

ALTER TABLE identity.user ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.user FORCE ROW LEVEL SECURITY;
-- 4 个标准 policy 由 standard_tenant_policies('identity.user') 生成
```

### 3.3 `identity.session_ref`（不存 token）

```sql
CREATE TABLE identity.session_ref (
    id                 TEXT PRIMARY KEY CHECK (id ~ '^sess_[0-9A-Z]{26}$'),
    tenant_id          TEXT NOT NULL REFERENCES tenant.tenant(id),
    user_id            TEXT NOT NULL REFERENCES identity.user(id),
    keycloak_session_id TEXT NOT NULL,
    issued_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL,
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at         TIMESTAMPTZ,
    revoked_reason     TEXT,                  -- 'LOGOUT' / 'IDLE_TIMEOUT' / 'ADMIN_REVOKE' / 'PASSWORD_CHANGED' / 'EMERGENCY_FREEZE'
    -- 设备 / 客户端
    user_agent         TEXT,
    ip                 INET,
    device_fingerprint TEXT,
    -- 认证方式记录
    auth_methods       TEXT[] NOT NULL,        -- ['PASSWORD', 'TOTP'] / ['OIDC:keycloak-x']
    mfa_satisfied      BOOLEAN NOT NULL DEFAULT false,
    -- 元
    metadata           JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX session_ref_tenant_user_idx ON identity.session_ref (tenant_id, user_id, revoked_at);
CREATE INDEX session_ref_active_idx
    ON identity.session_ref (tenant_id, user_id)
    WHERE revoked_at IS NULL AND expires_at > now();
-- RLS 同上
```

### 3.4 `identity.tenant_sso_config` 与 social_login_config

```sql
CREATE TABLE identity.tenant_sso_config (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenant.tenant(id),
    provider_kind TEXT NOT NULL CHECK (provider_kind IN
        ('OIDC', 'SAML', 'LDAP', 'AD', 'DINGTALK_ENTERPRISE', 'FEISHU_ENTERPRISE', 'WECOM')),
    alias        TEXT NOT NULL,                         -- KC IdP alias，租户内唯一
    display_name TEXT NOT NULL,
    enabled      BOOLEAN NOT NULL DEFAULT true,
    is_primary   BOOLEAN NOT NULL DEFAULT false,        -- 唯一 primary IdP，登录页默认强制走
    secret_ref   TEXT NOT NULL,                         -- Vault 路径：foundation/identity/<tenant>/sso/<alias>
    auto_provision BOOLEAN NOT NULL DEFAULT true,       -- 首次 SSO 登录自动建用户
    require_admin_approval BOOLEAN NOT NULL DEFAULT false, -- 即使自动 provision 也要管理员审批激活
    attribute_mapping JSONB NOT NULL DEFAULT '{}'::jsonb,  -- 远端字段 → user 字段
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, alias)
);

CREATE TABLE identity.tenant_social_login_config (
    tenant_id    TEXT PRIMARY KEY REFERENCES tenant.tenant(id),
    enabled_providers TEXT[] NOT NULL DEFAULT '{}',     -- ['google', 'github', 'wechat', ...]
    first_login_requires_email_binding BOOLEAN NOT NULL DEFAULT true,
    first_login_requires_admin_approval BOOLEAN NOT NULL DEFAULT true,
    allowed_email_domains TEXT[],                       -- 仅这些域可绑定
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by   TEXT
);
```

### 3.5 `identity.frozen_token_blacklist`

```sql
CREATE TABLE identity.frozen_token_blacklist (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenant.tenant(id),
    target_kind  TEXT NOT NULL CHECK (target_kind IN ('USER', 'SESSION', 'JTI')),
    target_id    TEXT NOT NULL,                          -- user_id / session_id / jti
    reason       TEXT NOT NULL,                          -- 'EMERGENCY_FREEZE' / 'OFFBOARDING' / 'COMPROMISED'
    frozen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ,                            -- NULL = 永久；通常 = max(jwt exp)
    frozen_by    TEXT NOT NULL,
    audit_event_id TEXT NOT NULL                         -- 关联审计
);

CREATE INDEX frozen_target_idx ON identity.frozen_token_blacklist (target_kind, target_id);
CREATE INDEX frozen_expires_idx ON identity.frozen_token_blacklist (expires_at);
```

DB 是兜底；网关实际查 Redis `foundation:identity:blacklist:{kind}:{id}`，TTL = `expires_at - now()`。

---

## 4. Keycloak 配置（realm 设计）

### 4.1 realm 数量

- **single realm**: `foundation`
- **abandon realm-per-tenant**：旧方案在 100+ 租户时管理崩坏；用 Organizations 替代
- 备用 realm `foundation-admin`：仅给平台 SRE / 安全管理员，与业务隔离

### 4.2 Organizations ↔ tenant

- 每个 `tenant.tenant(id)` 在 Keycloak 创建 1 个 Organization
- `Organization.name = tenant.id`
- `Organization.alias = tenant.id`（小写，KC 要求）
- `Organization.attributes.tier = tenant.tier`
- **创建/更新/删除全由 identity-service 同步**；禁止人手在 KC 管理台改 Organization

### 4.3 Identity Providers (IdP) 配置策略

| Provider | 注册方式 | 启用粒度 | 凭据来源 |
|---|---|---|---|
| 内置 (`local`) | realm 自带 | 永远启用 | KC 自管 |
| 企业 SSO（OIDC / SAML / AD / LDAP） | identity-service 调 KC Admin API 注册，**linked to Organization** | 该 Organization 的成员可见 | Vault 注入 |
| 钉钉 / 飞书 / 企业微信 企业版 | 同上 | 同上 | Vault 注入 |
| 社交登录（Google / GitHub / 微信 / ...） | identity-service 全部预注册到 realm 级别（无 Organization 绑定） | 由 `tenant_social_login_config.enabled_providers` 过滤显示 | 平台共享凭据（Vault） |

**社交登录的关键约束**：
- IdP 预注册时设置 `Login Flow` 包含 `Account Linking First Login Flow` 强制企业邮箱绑定
- `Trust Email = false`，第一次必须验证企业域邮箱
- 配置 `Sync Mode = IMPORT`（首次 import），后续修改不覆盖本地

### 4.4 Authentication Flows（自定义）

新建以下 flow（覆盖 KC 默认）：

#### `foundation-browser-flow`（浏览器登录主流程）
```
Cookie [ALTERNATIVE]
Kerberos [DISABLED]
Identity Provider Redirector [ALTERNATIVE]
foundation-forms (子 flow) [ALTERNATIVE]
    ├ Username Password Form [REQUIRED]
    ├ foundation-password-policy-check [REQUIRED]   # 自定义 SPI
    ├ foundation-conditional-mfa (子 flow) [CONDITIONAL]  # 条件 MFA
    │   ├ Condition: Tenant requires MFA OR admin role OR sensitive action [REQUIRED]
    │   ├ MFA Subflow [REQUIRED]
    │   │   ├ TOTP [ALTERNATIVE]
    │   │   ├ WebAuthn [ALTERNATIVE]
    │   │   └ SMS OTP (自定义 SPI) [ALTERNATIVE]
    └ foundation-session-cap-check [REQUIRED]       # 并发会话数检查
```

#### `foundation-first-social-login-flow`（社交登录首次登录）
```
Review Profile [REQUIRED]
foundation-require-corporate-email [REQUIRED]    # 自定义 SPI：检查 email 在 allowed_domains
foundation-require-admin-approval [REQUIRED]     # 自定义 SPI：标 status=INVITED，发审批
Create User If Unique [REQUIRED]
```

### 4.5 自定义 SPI 一览

| SPI | 类型 | 用途 |
|---|---|---|
| `foundation-password-policy-check` | Authenticator | 在 KC 自带 password policy 之上叠加合规模式策略（金融需 12 位等） |
| `foundation-conditional-mfa-condition` | ConditionalAuthenticator | "管理员 / 敏感操作 / 异常 IP / 跨境" 触发 MFA |
| `foundation-sms-otp` | Authenticator | 调 `notification-service` 下发短信 |
| `foundation-session-cap-check` | Authenticator | 并发会话超 cap 时按"挤掉最老"或"拒绝新登录"配置 |
| `foundation-require-corporate-email` | Authenticator | 社交登录首次绑定企业邮箱 |
| `foundation-require-admin-approval` | Authenticator | 标记 INVITED + 发管理员通知 |
| `foundation-blacklist-jwt-mapper` | ProtocolMapper | JWT 颁发前查 Redis 黑名单，命中则拒发 |

SPI 用 Java 写（KC 限制），打成 jar 部署到 KC `providers/`。源码放在 `packages/identity-keycloak-spi/`（独立子项目，Maven 构建）。

### 4.6 Realm 关键设置

```
Tokens:
  Access Token Lifespan: 5 min（短，配合 refresh）
  Refresh Token Lifespan: 8 h（默认）/ 1 h（敏感模式）
  SSO Session Idle: 30 min（默认）/ 15 min（金融/医疗）
  SSO Session Max: 8 h
  Revoke Refresh Token: true
  Refresh Token Max Reuse: 0

Login:
  Forgot Password: ON
  Remember Me: OFF（强制每次重新认证）
  Verify Email: ON
  Login With Email: ON
  Email As Username: OFF（用 username + email 双轨）

Security Defenses:
  Brute Force Detection: ON
    Max Login Failures: 5
    Wait Increment: 60s
    Max Wait: 900s
    Quick Login Check Milli Seconds: 1000
  Headers:
    X-Frame-Options: DENY
    Content-Security-Policy: default-src 'self'; ...
    Strict-Transport-Security: max-age=31536000; includeSubDomains

Keys:
  Active: RS256 (RSA 2048 / 自动轮换 90 天)
  + ES256 (备用)
  + SM2（v1.1 金融/政务模式）
```

---

## 5. API 表面

> 完整 OpenAPI 在 `contracts/openapi/identity.yaml`。本节给出端点清单 + 关键语义。

### 5.1 端点清单

| 端点 | 方法 | 权限 | 用途 |
|---|---|---|---|
| `/sessions` | POST | public | 登录（密码 / OIDC code / SAML / ...） |
| `/sessions/{id}/mfa-verify` | POST | partial | MFA 二次校验 |
| `/sessions/current` | GET | bearer | 当前会话信息 |
| `/sessions/current/refresh` | POST | bearer | 刷新 token |
| `/sessions/current` | DELETE | bearer | 登出 |
| `/sessions` | GET | admin | 列表所有会话（按 user/IP 查） |
| `/sessions/{id}` | DELETE | admin | 杀指定会话 |
| `/users/me` | GET | bearer | 当前用户档案 |
| `/users/me` | PATCH | bearer | 改自己（限白名单字段） |
| `/users/me/mfa` | GET | bearer | 列已绑定 MFA |
| `/users/me/mfa/totp` | POST | bearer | 注册 TOTP |
| `/users/me/mfa/webauthn` | POST | bearer | 注册 WebAuthn |
| `/users/me/mfa/{credId}` | DELETE | bearer | 解绑 MFA |
| `/users/me/password` | PUT | bearer | 改密码（需旧密码） |
| `/users` | GET | admin | 列租户用户（详见 OpenAPI template） |
| `/users` | POST | admin | 邀请新用户 |
| `/users/{id}` | GET / PATCH / DELETE | admin | 用户管理 |
| `/users/{id}/freeze` | POST | admin | 紧急冻结 |
| `/users/{id}/unfreeze` | POST | admin | 解冻 |
| `/users/{id}/sessions` | GET / DELETE | admin | 看 / 杀该用户所有会话 |
| `/users/{id}/password-reset` | POST | admin | 触发重置邮件 |
| `/invites` | POST | admin | 创建邀请（邮件发送） |
| `/invites/{token}/accept` | POST | public | 邀请激活 |
| `/tenant/sso-configs` | GET / POST | tenant_admin | 配 SSO IdP |
| `/tenant/sso-configs/{alias}` | GET / PATCH / DELETE | tenant_admin | 改 SSO |
| `/tenant/sso-configs/{alias}/test` | POST | tenant_admin | 探测连通性 |
| `/tenant/social-login-config` | GET / PUT | tenant_admin | 社交登录开关 |
| `/tenant/password-policy` | GET / PUT | tenant_admin | 密码策略覆盖（仅可加严） |
| `/scim/v2/Users` | * | scim-token | SCIM 2.0 user 端点 |
| `/scim/v2/Groups` | * | scim-token | SCIM 2.0 group 端点 |
| `/scim/v2/Schemas` | GET | scim-token | schema 元 |
| `/scim/v2/ResourceTypes` | GET | scim-token | resource types |
| `/scim/v2/ServiceProviderConfig` | GET | scim-token | SCIM 能力声明 |
| `/internal/dingtalk-events` | POST | sign-verified | 钉钉离职/变更回调 |

### 5.2 关键语义

**`POST /sessions`** —— 已在 OpenAPI template 详细给出。三种登录方式（EMAIL_PASSWORD / OIDC / SAML）走 oneOf discriminator。

返回值的关键：
- `201` + Session：登录成功
- `202` + MfaChallengeResponse：需要 MFA（含 `challenge_id` 给二次校验）
- `401 FOUNDATION.IDENTITY.AUTH.INVALID_CREDENTIALS`：账密错
- `401 FOUNDATION.IDENTITY.AUTH.ACCOUNT_LOCKED`：失败锁定中
- `403 FOUNDATION.IDENTITY.POLICY.PASSWORD_EXPIRED`：必须先改密
- `403 FOUNDATION.IDENTITY.POLICY.PROVIDER_DISABLED`：该租户未开此 SSO/social provider

**`POST /users/{id}/freeze`** —— 紧急冻结：
1. 写 `identity.frozen_token_blacklist`：`target_kind=USER, target_id=user_id, expires_at=max session exp`
2. 推 Redis 黑名单（TTL 同上）
3. 调 Keycloak Admin API `logout-all`
4. 调 `audit-service` 写关键事件
5. 调 `notification-service` 通知用户邮件 + 安全管理员

SLA：**≤1 小时**（PIPL 离职流程要求），实际目标 ≤30 秒。

**`/scim/v2/*`** —— 标准 SCIM 2.0；用 Python `scim2-server` 或自写 routers。所有写操作内部转 Keycloak Admin + `identity.user` 双写。

**`/internal/dingtalk-events`** —— 钉钉**不走 SCIM**：
- 钉钉企业版后台配置回调到此端点
- payload 含 `EventType=user_leave_org` / `user_modify_org` 等
- 签名校验（HMAC + token），失败 401
- 收到 `user_leave_org` → 触发 `freeze(user) + offboarding workflow`

---

## 6. 关键状态机

### 6.1 用户生命周期

```
                       ┌──────────────┐
                       │   INVITED    │  ← 管理员邀请；邮件未点击
                       └──────┬───────┘
              点击邀请 / 接受  │
                              ▼
                       ┌──────────────┐
        密码过期 / 长期 │   ACTIVE     │  ← 正常使用
        不登录           └──┬─────┬───┘
                          │     │
              管理员手动 │     │ 失败锁定 / 异常
              暂停        ▼     ▼
                  ┌──────────┐  ┌──────────┐
                  │ SUSPENDED│  │  LOCKED  │
                  └─────┬────┘  └────┬─────┘
                        │            │
                        │ 解除 / 解锁
                        ▼            ▼
                       ┌──────────────┐
                       │   ACTIVE     │
                       └──────┬───────┘
            离职 / 销户        │
                              ▼
                       ┌──────────────┐
                       │ DEACTIVATED  │ ← soft delete (90 天)
                       └──────┬───────┘
            硬删除 (180 天)   │
                              ▼
                          [hard delete]
                          + 销毁证明 PDF
```

转换规则：

| 从 | 到 | 触发 | 副作用 |
|---|---|---|---|
| INVITED | ACTIVE | 用户接受邀请并验证邮箱 | 发欢迎通知 |
| ACTIVE | SUSPENDED | 管理员暂停 | logout-all + 加入黑名单 |
| ACTIVE | LOCKED | 5 次失败 / 异常风险 | 自动 30 分钟解锁 |
| LOCKED | ACTIVE | 时限到 / 管理员手动 | — |
| * | DEACTIVATED | 离职 / 自助销户 / SCIM remove | freeze + 90 天 lifecycle 启动 |
| DEACTIVATED | [hard] | 180 天后 cron 触发 | 销毁证明 + 审计 |

### 6.2 登录状态机

```
[Anonymous]
  │ POST /sessions {EMAIL_PASSWORD}
  ▼
[Authenticating]
  │ 密码正确
  ▼
[Need MFA?] ──── No ───→ [Session Issued]
  │ Yes
  ▼
[Awaiting MFA] (challenge_id 有效 5 min)
  │ POST /sessions/{id}/mfa-verify
  ▼
[Session Issued]
  │
  ▼
[Active] ─── idle 30 min / max 8 h / admin revoke / logout ─→ [Revoked]
```

### 6.3 SCIM 同步状态机

```
[Provisioned by Azure AD / Okta]
  │ SCIM POST /Users
  ▼
[Created in identity.user] (status=ACTIVE, scim_provisioned_by=azure-ad)
  │
  │ SCIM PATCH /Users/{id} (改属性)
  ▼
[Updated]
  │
  │ SCIM PATCH active=false / DELETE
  ▼
[Deactivated] → freeze + 90 天 lifecycle
```

钉钉反向适配器同状态机，但触发是 webhook + 定时拉取，不是被动接 SCIM。

---

## 7. 合规模式联动

`identity-service` 启动时读 `compliance-service` 拿到当前租户启用的合规模式，应用对应默认值（详见 [compliance 设计 - 待 P2 #compliance]）：

| 模式 | 密码长度 | 轮换 | MFA 强制 | 会话 idle | 并发 |
|---|---|---|---|---|---|
| `pipl` 基线 | ≥8 | ≤90d | 管理员 / 敏感操作 | 30 min | ≤2 |
| `equal_protection_3` | ≥8 + 复杂度 | ≤90d | + 异常 IP | 30 min | ≤2 |
| `equal_protection_4` | ≥12 + 复杂度 | ≤60d | 全员 | 15 min | ≤1 |
| `finance_jrt0071` | ≥12 | ≤60d | 全员 + 跨境 | 15 min | ≤1 |
| `hipaa` | ≥12 | ≤90d | 全员 | 15 min | ≤2 |
| `soc2` | 跟 PIPL | ≤90d | 管理员 | 30 min | ≤2 |

租户管理员可在基线之上加严，**不可放宽**。基线变更经 `compliance-service` 推事件 `foundation.compliance.mode_changed`，identity-service 消费后更新 Keycloak realm settings + DB override。

---

## 8. 紧急冻结的端到端路径

> 这是 identity-service 最敏感的能力，必须 ≤1h 见效（PIPL 强制）。

```
[Trigger]
  - 管理员控制台手动 POST /users/{id}/freeze
  - SCIM PATCH active=false
  - 钉钉离职 webhook EventType=user_leave_org
  - 安全监控规则触发（多次跨租户访问尝试 / 异常登录）
  - HR 系统通过 SCIM 推送

[identity-service]
  1. 写 identity.frozen_token_blacklist + identity.user.status=SUSPENDED
  2. Redis SET foundation:identity:blacklist:user:{user_id} 1 EX <ttl>
  3. Keycloak Admin: realms/foundation/users/{kc_user_id}/logout
  4. 发 event foundation.identity.user.frozen → audit + notification
  5. 调 authz-service 把所有 active session 的 role binding 暂停（防 token 残留期内提权）

[Gateway (Envoy + custom Lua / WASM)]
  - 每次 JWT 校验后查 Redis 黑名单
  - 命中 → 401 FOUNDATION.IDENTITY.AUTH.TOKEN_REVOKED
  - 兜底：Redis 不可达时回查 identity-service /internal/check-blacklist（高延迟容忍）

[审计]
  事件 foundation.identity.user.frozen 写入 audit
  + WORM 归档
  + 短信/邮件/钉钉通知用户与安全管理员

[SLA]
  P50 ≤ 5 秒
  P99 ≤ 60 秒
  外部承诺：≤ 1 小时
```

测试覆盖（必跑）：
- 冻结后立即用旧 token 调任意 service → 401
- 冻结后用旧 refresh token 刷新 → 拒绝
- Redis 挂掉时通过 DB 兜底校验
- 跨 5 个 service 并发请求时冻结，所有未完成请求继续走完但下一请求立刻拒绝

---

## 9. SCIM 2.0 实现要点

### 9.1 标准实现（Azure AD / Okta）

- 用 [scim2-server](https://github.com/python-scim/scim2-server) 或自写 FastAPI routers
- 端点：`/scim/v2/Users` / `/scim/v2/Groups` / `/scim/v2/Schemas` / `/scim/v2/ResourceTypes` / `/scim/v2/ServiceProviderConfig`
- 认证：bearer SCIM token（租户独立，可在 admin 控制台生成）
- ETag 支持乐观锁
- Bulk 支持（Azure AD 强烈推荐）

### 9.2 字段映射

| SCIM 标准字段 | identity.user 字段 | 备注 |
|---|---|---|
| `userName` | `email` 或租户配置的字段 | 唯一性走 `(tenant_id, email)` 索引 |
| `name.formatted` | `display_name` | |
| `emails[primary].value` | `email` | |
| `active` | `status` ('ACTIVE' / 'DEACTIVATED') | active=false → 走 freeze + 90 天 lifecycle |
| `phoneNumbers` | `phone` | E.164 |
| `locale` | `locale` | |
| `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.department` | 关联 `org.org_unit` | identity 不直接写，发事件给 `org-service` 处理 |
| `roles` | 不直接存；发事件给 `authz-service` | |

### 9.3 钉钉反向适配器

钉钉企业版**没有标准 SCIM server**，但提供：
- [获取员工列表 API](https://open.dingtalk.com/document/orgapp/queries-the-complete-information-of-a-department-user)
- [离职员工查询 API](https://open.dingtalk.com/document/development/obtain-resignation-information-of-employees-new-version)
- [企业内部应用状态变更回调](https://open.dingtalk.com/document/development/enterprise-self-built-application-status-change)（webhook，含 user_leave_org 等）

适配器设计：
- 一个独立 worker（`packages/identity/dingtalk-adapter/`）
- **定时拉取** 15 分钟一次全量 diff（加 ETag），新增/修改触发 SCIM 内部调用
- **webhook 订阅** `user_leave_org` / `user_modify_org` / `org_user_remove`，实时 freeze
- 凭据 (`AccessToken` / `AppKey` / `AppSecret`) 在 Vault，租户配置时填
- 失败重试：指数退避 + 死信队列；告警通知中心
- 测试用 [钉钉沙盒](https://open-dev.dingtalk.com/)

字段映射比标准 SCIM 多写适配代码：钉钉 `userid` ↔ `scim_external_id`，钉钉 `dept_id_list` 走 `org-service` 部门匹配。

---

## 10. 与其他 service 的事件与 SDK

### 10.1 发出的事件（`foundation.identity.*`）

| 事件 | 时机 | 主要 consumer |
|---|---|---|
| `foundation.identity.user.invited` | 邀请创建 | notification（发邮件）/ audit |
| `foundation.identity.user.activated` | 邀请激活 / SCIM 入职 | org / billing（席位 +1）/ audit |
| `foundation.identity.user.updated` | 档案改 | search（重建索引）/ audit |
| `foundation.identity.user.frozen` | 紧急冻结 | authz / audit / notification / billing |
| `foundation.identity.user.unfrozen` | 解冻 | 同上 |
| `foundation.identity.user.deactivated` | 离职 / SCIM remove | lifecycle / billing（席位 -1）/ audit |
| `foundation.identity.user.hard_deleted` | 180 天后清除 | data-protection（销毁证明）/ audit |
| `foundation.identity.session.created` | 登录 | audit |
| `foundation.identity.session.revoked` | 登出 / 杀会话 | audit |
| `foundation.identity.mfa.registered` | 绑定 MFA | audit / notification |
| `foundation.identity.password.changed` | 改密 / 重置 | audit / notification / 所有其他 session revoke |
| `foundation.identity.sso.configured` | 租户配 SSO | audit |
| `foundation.identity.scim.provisioned` | SCIM 进入 | audit / billing |
| `foundation.identity.auth.failed` | 登录失败（5 次 / 5 min 触发） | security-ops（攻击检测） |

事件 schema 入 `contracts/events/identity/*.json`，CloudEvents 1.0。

### 10.2 消费的事件

| 事件 | 行为 |
|---|---|
| `foundation.compliance.mode_changed` | 重算密码策略 / MFA 触发条件 / 会话超时 |
| `foundation.org.tenant.created` | 创建 Keycloak Organization + 默认 admin user |
| `foundation.org.tenant.deleted` | 排程销毁该租户全部用户（90 天 lifecycle） |
| `foundation.billing.subscription.suspended` | 把租户全部用户改 SUSPENDED |
| `foundation.billing.subscription.resumed` | 恢复 |

### 10.3 SDK（`foundation_identity`）

跟随 [SDK template](../../sdks/python/_template/) 模板。客户端方法（业务层调用）：

```python
from foundation_identity import IdentityClient

client = IdentityClient.from_env()

# 服务侧解析 JWT 拿到用户档案（带本地 cache + JWKS 验签）
user = client.users.get_me()

# 撤销自己的会话
client.sessions.logout_current()

# 管理员场景（在 tenant_context 内）
client.users.freeze(user_id="usr_01J...", reason="OFFBOARDING")
client.users.invite(email="alice@example.com", roles=["MEMBER"])
```

**SDK 不允许传 `tenant_id` 参数**（CONVENTIONS §3）。所有方法从 contextvars 取。

---

## 11. 安全设计要点

### 11.1 密码学

- 密码哈希：Argon2id（默认）或 SM3-HMAC（合规模式）。**禁止 bcrypt < 12 rounds / MD5 / SHA1**
- JWT 签名：RS256 / SM2（合规）。Keycloak realm key 由 `crypto-service` 管理，启用自动轮换 90 天
- TOTP secret：存在 Keycloak（加密）+ 备份在 Vault
- WebAuthn：标准实现，KC 26 原生支持
- Vault 路径：所有 SSO/SCIM/钉钉凭据放 `foundation/identity/<tenant>/...`，租户 ACL 隔离

### 11.2 防御

- **暴力破解**：KC Brute Force Detection + 自定义"指数退避"（5 次锁 30 min，10 次锁 24 h）
- **凭据填充**（credential stuffing）：检测同 IP 高频不同账号失败 → 触发 reCAPTCHA / 临时禁 IP
- **会话固定攻击**（session fixation）：登录后强制 rotate session id
- **CSRF**：所有 mutation 端点要求 Origin/Referer 校验 + SameSite cookie
- **SSO 重放**：state nonce + max 5 min 有效期
- **SAML 攻击**：用 KC 内置防御 + 强制签名

### 11.3 隐私

- 邮箱/手机在审计日志中默认掩码（`a***@example.com` / `+86-138****1234`）
- 失败登录的 IP 不在响应中暴露
- 用户档案 PII 字段（phone / IP / 设备指纹）在 DB 字段级加密（用 `crypto-service`）
- DSAR 删除请求 → 调 `compliance-service` 协调，identity-service 提供"用户全部数据导出 + 删除"接口

---

## 12. 部署形态差异

| 维度 | small | medium | large |
|---|---|---|---|
| Keycloak 副本 | 1（dev mode） | 2（HA） | 3+（HA + cache cluster） |
| Keycloak Cache | local Infinispan | distributed Infinispan | 同左 + Redis backing |
| identity-service 副本 | 1 | 3 | 5-10（HPA） |
| Realm key 轮换 | 手动 | 自动 30/60/90 天 | 同 + 国密 |
| SCIM bulk batch size | 100 | 500 | 1000 |
| 钉钉 worker | inline | sidecar | 独立 Deployment + KEDA |
| Brute force store | Keycloak DB | Keycloak DB | + Redis backing |

---

## 13. 关键技术风险

| 风险 | 缓解 |
|---|---|
| Organizations 在 100+ 组织场景的性能未知 | 压测目标 5000 组织 / 50 IdP / 100k 用户；预留迁回 multi-realm 方案为兜底 ADR |
| 自定义 SPI 跟随 KC 版本升级要重新编译 | Maven CI 跑各 KC 版本兼容矩阵；锁 KC 升级周期与 SPI 同步 |
| 钉钉 API 限流 / 接口变更 | 全局令牌池 + 退避；适配器版本化；钉钉变更 14 天内适配 |
| 紧急冻结依赖 Redis；Redis 故障即冻结失效 | DB 兜底 + 网关 fail-closed 模式（Redis 不可达时拒绝所有请求 5 秒）+ 告警 |
| Keycloak 26 升级到 27/28 时 Organization API 变化 | 通过 identity-service 收口；breaking change 时只改 service 不动业务 |
| 社交登录被滥用批量注册 | 默认全关 + 管理员审批 + IP 风控 + Feature Flag 紧急 kill switch（详见 plan 风险 14） |
| SCIM 客户端不规范导致脏数据 | 严格 schema 校验 + 拒绝非法 patch + 详细错误响应（详见 [Microsoft Entra ID SCIM 兼容性已知问题](https://learn.microsoft.com/zh-cn/entra/identity/app-provisioning/application-provisioning-config-problem-scim-compatibility)） |
| 钉钉 webhook 重放 | HMAC + nonce + timestamp 校验；24h 内 nonce 去重 |
| TOTP 时间漂移 | 容忍 ±1 个窗口（30s × 2）+ 监控漂移率 |

---

## 14. 测试策略

### 14.1 单元（≥85%）
- 密码策略 / MFA 判定 / 失败锁定 / 会话生命周期 / SCIM patch 解析

### 14.2 集成（依赖 docker-compose 起的 KC）
- 登录全流程 / OIDC 联合登录 / SAML POST binding / refresh / logout
- SCIM CRUD（用 [scim-tester](https://github.com/jeremyjamesperez/scim-tester) 跑标准合规套件）
- MFA enroll → verify → reset

### 14.3 安全 fuzz（强制）
- RLS 越权（按 multi-tenancy.md §10.2 1000 次参数化）
- JWT 篡改：改 claim / 用过期 key / algorithm none
- 暴力破解防御：5 次失败必锁
- 紧急冻结端到端：trigger → 黑名单 → 网关拒绝（P99 < 60s）
- 社交登录绑定攻击：构造其他企业邮箱尝试绑定，必须被拒

### 14.4 兼容性
- KC 26.0 / 26.6 / 27.x（最新）三档矩阵
- SCIM 兼容性：Azure AD / Okta / Onelogin 各跑一遍真实推送

---

## 15. 待解决问题（写实，不藏）

| # | 问题 | 决策机制 | 截止 |
|---|---|---|---|
| Q1 | Keycloak Organizations 在我们 5000+ 租户量级是否扛得住？ | 起一个性能压测项目，2 周内出结论；如不行则评估 fallback 到 group-per-tenant | M1 第 2 周 |
| Q2 | 钉钉企业版 SCIM 适配器是否要走"双向同步"（identity 也能改钉钉）？ | 与首批 POC 客户访谈决定；默认单向（钉钉→我们） | M3 启动前 |
| Q3 | SAML 强制签名 vs 与老 IdP 兼容 | 默认强制签名；提供"不签名但日志告警"的 Feature Flag | A-M3 |
| Q4 | 社交登录的 IP 风控用什么数据源？商业服务（Recaptcha v3 / 阿里云风控）还是自建？ | 看预算和合规偏好 | A-M4 |
| Q5 | TOTP secret 该不该完全外置到 Vault？KC 自管 vs Vault 拉外 | Vault 外置安全但每次校验加延迟；当前定 KC 自管 + Vault 备份 | A-M2 |
| Q6 | 是否要支持"管理员代为登录"（impersonation）？ | 风险高；初版不做；客户驱动再上 | v1.1 |
| Q7 | WebAuthn 与国密 USB Key 兼容性 | 调研期；v1.1 国密模式时再决 | v1.1 |
| Q8 | 钉钉 webhook 签名机制具体怎么走 | 实施期看官方文档定 | A-M3 |
| Q9 | 紧急冻结时是否一起冻结 refresh token（短期内仍可换 access token）？ | 必须；refresh token 也走黑名单 | 已定，写入此文档 |
| Q10 | KC custom SPI 是否要做 zh-CN 本地化的错误消息 | 是；A-M1 内完成 | A-M1 |

---

## 16. 验证标准（M1 出口）

- [ ] OpenAPI `contracts/openapi/identity.yaml` 通过 spectral lint
- [ ] 所有端点单元测试 ≥85% 覆盖
- [ ] Keycloak 26 在 docker-compose 起得来 + realm config 自动导入
- [ ] 自定义 SPI 编译 + 部署到 KC + 自动化测试覆盖 5 个 flow
- [ ] OIDC / SAML / AD / LDAP 各跑通至少一个真实 IdP（用 KC 自身做 mock IdP 即可）
- [ ] SCIM 跑过 [scim-tester](https://github.com/jeremyjamesperez/scim-tester) 标准合规套件
- [ ] 钉钉企业版适配器：webhook 收 user_leave_org → 5 秒内冻结
- [ ] 紧急冻结 P99 < 60s（fuzz 测试 1000 次）
- [ ] RLS fuzz 测试 1000 次跨租户访问 0 越权
- [ ] 三档 helm profile 都能跑（small/medium 起 keycloak 副本数不同）
- [ ] PR 走完 service-ci.yml + security-scan.yml + helm-validate.yml

---

## 17. 参考资料

- [Keycloak 26 Organizations 介绍](https://www.keycloak.org/2024/06/announcement-keycloak-organizations)
- [Keycloak Organizations 多租户完整指南 - KeycloakPro](https://keycloakpro.com/blog/keycloak-multi-tenancy-organizations-guide)
- [Organization Groups（26.6+）](https://www.keycloak.org/2026/04/org-groups)
- [Keycloak SPI 开发](https://www.keycloak.org/docs/latest/server_development/)
- [SCIM 2.0 RFC 7642/7643/7644](https://datatracker.ietf.org/doc/html/rfc7644)
- [scim2-server (Python)](https://github.com/python-scim/scim2-server)
- [钉钉企业内部应用状态变更](https://open.dingtalk.com/document/development/enterprise-self-built-application-status-change)
- [钉钉离职员工查询](https://open.dingtalk.com/document/development/obtain-resignation-information-of-employees-new-version)
- [Microsoft Entra SCIM 兼容性已知问题](https://learn.microsoft.com/zh-cn/entra/identity/app-provisioning/application-provisioning-config-problem-scim-compatibility)
- [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/)
- [OAuth 2.0 安全最佳实践 RFC 9700](https://datatracker.ietf.org/doc/html/rfc9700)

---

## 18. 变更记录

| 日期 | 版本 | 变更 |
|---|---|---|
| 2026-05-22 | 0.1.0 | 初版（P0 #4） |
