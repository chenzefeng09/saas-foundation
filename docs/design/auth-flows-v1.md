# 密码 / MFA / Session 详细策略 — v0.1

> P1 #8 产出。覆盖 A-M1 范围。配套：
> - [identity-v1.md](./identity-v1.md)
> - [crypto-v1.md](./crypto-v1.md)
> - [authz-v1.md](./authz-v1.md)
> - [errors.md](../errors.md)
>
> 本文档把 identity 内部"密码 / MFA / Session"三大块铺开到可直接编码的程度。
> Keycloak 自定义 SPI 的接口签名、配置矩阵、状态机、错误码都在这。

---

## 0. TL;DR

```
密码策略（NIST 800-63-4 + 等保 / 金融加严）：
  - 仅密码登录：≥15 字符
  - 密码 + MFA：≥8 字符（合规模式可再加严）
  - 禁止强制复杂度（NIST 已废）
  - 强制 blocklist（已泄漏密码字典）
  - Argon2id  m=64MB t=3 p=4（高于 OWASP 最低）
  - 国密模式：SM3-HMAC pre-hash + Argon2id

MFA：
  - 默认：TOTP + WebAuthn/Passkey（Keycloak 26.4+ 原生）
  - 可选：SMS OTP / 推送通知
  - 强制场景：管理员 / 敏感操作 / 异常登录
  - 恢复：8 个一次性 recovery code

Session：
  - access token 5 min；refresh 8h（合规 1h）
  - idle 超时 30 min（金融/医疗 15 min）
  - 绝对超时 8h
  - 单账号并发 ≤2（合规 1）
  - 失败锁定：5 次锁 30 min；指数退避
```

---

## 1. 密码策略

### 1.1 基线（NIST 800-63-4 Rev 4 + 等保对齐）

| 维度 | NIST 800-63-4 基线 | 等保三级 | 等保四级 / 金融 JR/T 0071 |
|---|---|---|---|
| **仅密码最低长度** | ≥15 | ≥15 | **≥20** |
| **密码 + MFA 最低长度** | ≥8 | ≥8 | **≥12** |
| **最大长度** | ≥64（不可限短） | ≥64 | ≥64 |
| **允许字符** | 所有可打印 + Unicode + 空格 | 同 | 同 |
| **强制复杂度** | ❌ **禁止**（NIST 明令） | ❌ | ❌ |
| **轮换周期** | 仅泄漏时强制改 | ≤90 天 | ≤60 天 |
| **重用限制** | 不可与前 N 个相同 | N=3 | N=6 |
| **失败锁定** | 触发节流 | 5 次锁 30 min | 3 次锁 30 min |
| **泄漏字典 (blocklist)** | **必须** | 必须 | 必须 |
| **盐长度** | ≥32 bits | ≥128 bits | ≥128 bits |
| **哈希** | 批准 KDF | Argon2id | Argon2id + 国密 SM3 pre-hash |

> NIST 800-63-4（2025-08 发布）相较 Rev 3 的最大变化：**仅密码登录最低 15 字符；禁止强制复杂度**。我们采纳 NIST 同时保留"管理员可加严"的覆盖能力。
>
> 详见 [NIST SP 800-63B Rev 4](https://pages.nist.gov/800-63-4/sp800-63b.html) 与 [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)。

### 1.2 配置 schema

```python
# foundation_identity.policy.password
class PasswordPolicy(BaseModel):
    # 长度
    min_length: int = 15                       # 仅密码登录时
    min_length_with_mfa: int = 8               # 与 MFA 组合时降低
    max_length: int = 256

    # 复杂度（默认全 false，符合 NIST）
    require_uppercase: bool = False
    require_lowercase: bool = False
    require_digit: bool = False
    require_special: bool = False
    # 合规模式可置 true（虽然 NIST 不建议，但等保 / 客户合规要求可能要）

    # 黑名单
    blocklist_enabled: bool = True             # 必须开
    blocklist_sources: list[Literal["have-i-been-pwned-k-anonymity",
                                     "rockyou", "tenant-custom"]] = \
                       ["have-i-been-pwned-k-anonymity"]
    block_personal_info: bool = True           # 含 email/username/displayName 的禁止
    block_company_name: bool = True
    block_common_patterns: bool = True         # "Password123" 之类

    # 轮换
    max_age_days: int | None = 90              # None = 不强制
    history_count: int = 3                     # 最近 N 个不可重用
    min_change_interval_minutes: int = 1440    # 防 N 次连改绕过历史

    # 失败锁定
    max_failed_attempts: int = 5
    initial_lockout_minutes: int = 30
    exponential_backoff: bool = True           # 二次锁 60min、三次 120min、封顶 1440min
    backoff_reset_after_hours: int = 24        # 24h 无失败重置计数

    # 哈希
    hash_algorithm: Literal["argon2id", "sm3-argon2id"] = "argon2id"
    argon2_memory_kib: int = 65536             # 64 MiB
    argon2_time_cost: int = 3
    argon2_parallelism: int = 4

    @classmethod
    def for_compliance_modes(cls, modes: list[str]) -> "PasswordPolicy":
        """合规模式联动 — 详见 §1.3 矩阵"""
        ...
```

### 1.3 合规模式联动矩阵

| 字段 | `pipl` | `equal_protection_3` | `equal_protection_4` | `finance_jrt0071` | `hipaa` |
|---|---|---|---|---|---|
| min_length | 15 | 15 | 20 | 20 | 15 |
| min_length_with_mfa | 8 | 8 | 12 | 12 | 12 |
| max_age_days | 90 | 90 | 60 | 60 | 90 |
| history_count | 3 | 3 | 6 | 6 | 4 |
| max_failed_attempts | 5 | 5 | 3 | 3 | 5 |
| hash_algorithm | argon2id | argon2id | sm3-argon2id | sm3-argon2id | argon2id |
| blocklist_sources | hibp | hibp + rockyou | hibp + rockyou + tenant-custom | 同 + 行业字典 | hibp + rockyou |

租户管理员可在合规基线之上**加严**，不可放宽。代码层强制：

```python
def merged(*policies: PasswordPolicy) -> PasswordPolicy:
    """多个 policy 合并，每字段取最严"""
    return PasswordPolicy(
        min_length=max(p.min_length for p in policies),
        max_age_days=min((p.max_age_days for p in policies if p.max_age_days), default=None),
        ...
    )
```

### 1.4 强度校验器（`PasswordStrengthChecker`）

```python
class StrengthResult(BaseModel):
    accepted: bool
    score: int                                 # 0-4，仅参考
    violations: list[StrengthViolation]
    suggestions: list[str]

class StrengthViolation(BaseModel):
    code: str                                  # "TOO_SHORT" / "PWNED" / "PERSONAL_INFO" / ...
    field: str | None = None                   # "length" / "blocklist"
    user_message: str                          # 本地化


class PasswordStrengthChecker:
    def __init__(self, policy: PasswordPolicy,
                 hibp_client: HibpKAnonymityClient,
                 custom_blocklist: BloomFilter | None = None): ...

    async def check(
        self,
        password: str,
        *,
        user_context: UserContext,             # email/username/displayName 防 personal_info
        tenant_context: TenantContext,         # company name
        will_have_mfa: bool = False,
    ) -> StrengthResult: ...
```

实现要点：
- **HIBP k-anonymity**：调用 `https://api.pwnedpasswords.com/range/{first5hash}` 返回带计数列表，本地比对后 5 hash；不上传原密码
- **离线 blocklist**：`rockyou.txt` 等 → Bloom Filter 加载（节省内存，假阳率 0.1%）
- **个人信息**：分词 + Levenshtein 距离 ≥80% 视为命中
- **常见模式**：正则黑名单 `^password\d*$` / `qwerty.*` / `^\d{6,12}$`（纯数字）
- **i18n 错误消息**：通过 errors.md SDK 翻译

### 1.5 密码哈希集成

通过 `crypto-service` SDK，identity **不直接调** Argon2id：

```python
# identity-service
from foundation_crypto import crypto

hash_b64 = await crypto.password_hash(password)            # 自动按租户 policy 选 algorithm + 参数
ok = await crypto.password_verify(password, hash_b64)
```

`crypto.password_hash` 输出 PHC 格式串：`$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`，verify 时自动识别参数。

升级路径：以后增大参数（如 m=128MB），verify 仍兼容旧哈希；登录成功后透明 re-hash。

### 1.6 错误码

| code | 何时 | HTTP |
|---|---|---|
| `FOUNDATION.IDENTITY.AUTH.INVALID_CREDENTIALS` | 账密错 | 401 |
| `FOUNDATION.IDENTITY.AUTH.ACCOUNT_LOCKED` | 锁定中 | 401 |
| `FOUNDATION.IDENTITY.AUTH.PASSWORD_EXPIRED` | 过期需改 | 403 |
| `FOUNDATION.IDENTITY.AUTH.PASSWORD_REQUIRES_RESET` | 管理员强制 | 403 |
| `FOUNDATION.IDENTITY.AUTH.WEAK_PASSWORD` | 改密 / 注册时强度不足 | 422（含 violations） |
| `FOUNDATION.IDENTITY.AUTH.PASSWORD_REUSED` | 命中历史 | 422 |
| `FOUNDATION.IDENTITY.AUTH.PASSWORD_PWNED` | HIBP 命中 | 422 |
| `FOUNDATION.IDENTITY.AUTH.PASSWORD_CHANGED_RECENTLY` | min_change_interval 未到 | 429 |

---

## 2. MFA

### 2.1 通道与对应能力

| 通道 | 注册成本 | 钓鱼抵抗 | 备注 |
|---|---|---|---|
| **WebAuthn / Passkey** | 浏览器 / 系统原生（生物或硬件 key） | ✅ 强 | Keycloak **26.4+** 原生集成，默认推荐 |
| **TOTP** | 扫码 + 手输 6 位 | ⚠️ 中（可钓鱼） | 兼容 Google/Microsoft/1Password Authenticator |
| **SMS OTP** | 短信 | ❌ 弱（SIM swap） | 兜底通道，仅在无 WebAuthn/TOTP 时 |
| **推送通知** | 安装客户端 | ⚠️ 中 | v1.1 待业务定 |
| **Recovery codes** | 注册任一 MFA 时自动生成 | — | 8 个一次性码，离线打印 |

> NIST 800-63B Rev 4 把 SMS 列为 RESTRICTED authenticator；可用但需明确告知用户风险。

### 2.2 强制矩阵

| 场景 | 默认 | 等保三级 | 等保四级 / 金融 | HIPAA |
|---|---|---|---|---|
| 管理员登录 | ✅ | ✅ | ✅ | ✅ |
| 敏感操作（权限变更 / 数据导出 / 计费 / 配置） | ✅ | ✅ | ✅ | ✅ |
| 异常 IP / 时段 / 地点 | ✅ | ✅ | ✅ | ✅ |
| 跨境访问 | — | ✅ | ✅ | ✅ |
| 全员日常登录 | — | — | ✅ | ✅ |

判定逻辑封装在 Keycloak 自定义 SPI `foundation-conditional-mfa-condition`（identity-v1.md §4.5 已列），输入：

```json
{
  "user": { "id": "...", "roles": [...] },
  "request": {
    "ip": "...", "country": "CN", "ip_reputation_score": 0.1,
    "user_agent": "...", "device_fingerprint": "...",
    "time_of_day_local": "23:15", "day_of_week": "Sat"
  },
  "tenant": { "compliance_modes": [...], "business_hours_start": 9, "business_hours_end": 19 },
  "action": "LOGIN" | "PERMISSION_GRANT" | "DATA_EXPORT" | "BILLING_CHANGE"
}
```

输出：`{ "mfa_required": true, "reasons": ["ADMIN_ROLE", "ABNORMAL_IP"] }`

reasons 进审计 + 解释给用户。

### 2.3 注册流程（enroll）

#### 2.3.1 TOTP enroll

```
POST /users/me/mfa/totp                    （需已登录 + 可能需 step-up 验密）
  ↓ identity-service:
  ↓   生成 20 byte secret（crypto.random）
  ↓   存 KC（加密）+ identity.mfa_credential 元数据
  ↓   返 { secret_b32, qrcode_uri, recovery_codes }
client 扫码 → 输入 6 位
POST /users/me/mfa/totp/confirm  { code: "123456" }
  ↓ identity-service:
  ↓   verify TOTP（容忍 ±1 个 30s 窗口）
  ↓   confirmed=true；emit foundation.identity.mfa.registered
```

#### 2.3.2 WebAuthn / Passkey enroll

走 Keycloak 26.4+ 内建流程，identity-service 只做：
1. 调 KC `/realms/foundation/users/{id}/credentials` 创建 challenge
2. 浏览器 navigator.credentials.create()
3. POST attestation 到 KC
4. identity-service 写 `mfa_credential(kind=WEBAUTHN, attestation_meta)` 副本，用于"杀某 device"
5. emit `foundation.identity.mfa.registered`

#### 2.3.3 Recovery codes

注册任一 MFA 时一次性生成 8 个 8 字符 base32 码：

- 用 `crypto-service` 哈希存（与密码同款 Argon2id，但参数轻：m=8MB t=2）
- 一次性，verify 成功立刻 invalidate
- 用完前 ≤2 时 UI 提示生成新批
- 重置 MFA 后旧 codes 全失效

### 2.4 验证流程（verify）

```
POST /sessions { method: EMAIL_PASSWORD, ... }
  ↓ identity-service:
  ↓   密码 OK
  ↓   evaluate MFA condition → required=true
  ↓   找该用户已注册的 MFA credentials
  ↓   201 → 202 MfaChallengeResponse:
{
  "challenge_id": "chl_01J...",
  "methods": ["WEBAUTHN", "TOTP", "SMS_OTP", "RECOVERY_CODE"],   // 用户实际有的
  "expires_at": "2026-...T+5min",
  "preferred_method": "WEBAUTHN"
}
client 选 method
POST /sessions/{partial_session_id}/mfa-verify
  { challenge_id, method: "WEBAUTHN", credential_id, ... }
  ↓ identity-service:
  ↓   match challenge_id（5 min TTL，单次）
  ↓   按 method 验签
  ↓   success → 颁正式 token + Session
  ↓   failure → 计入失败计数；3 次失败本 challenge 作废
  ↓   emit foundation.identity.mfa.verified / .failed
```

challenge 存 Redis `mfa:challenge:{id}` TTL 5 min；不存 plaintext，仅存 hash + metadata。

### 2.5 MFA credential 数据模型（identity.mfa_credential）

已在 [identity-v1.md §3.1](./identity-v1.md) 列。补关键字段：

```sql
CREATE TABLE identity.mfa_credential (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    user_id         TEXT NOT NULL REFERENCES identity.user(id),
    kind            TEXT NOT NULL CHECK (kind IN ('TOTP','WEBAUTHN','SMS','PUSH','RECOVERY_CODE')),
    keycloak_credential_id TEXT,                 -- KC 内部 id；recovery 不写
    label           TEXT,                        -- 用户取名 "iPhone 15" / "Yubikey 主"
    -- WebAuthn 元
    aaguid          TEXT,
    transport       TEXT[],
    -- 状态
    confirmed       BOOLEAN NOT NULL DEFAULT false,
    last_used_at    TIMESTAMPTZ,
    use_count       INT NOT NULL DEFAULT 0,
    revoked_at      TIMESTAMPTZ,
    revoked_reason  TEXT,
    -- 元
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

`recovery_code` 哈希存独立表 `identity.recovery_code`（多行 / user）。

### 2.6 MFA 重置 / 解绑

| 场景 | 流程 |
|---|---|
| 用户主动解绑某 credential | step-up 验当前 MFA + 二次确认 |
| 全部 MFA 丢失 → 用 recovery code 登录 | 登录后强制重新注册 ≥1 个 MFA |
| Recovery code 也丢 → 走管理员人工 reset | 管理员 POST `/users/{id}/mfa/reset`；需 4 眼 + 审计；通知用户邮件 |

防误删：禁止删最后一个 MFA（如该用户租户已强制 MFA）。

---

## 3. Session

### 3.1 生命周期参数

| 参数 | 默认 | 金融 / 医疗 | 说明 |
|---|---|---|---|
| Access token lifespan | 5 min | 5 min | 短，配合 refresh |
| Refresh token lifespan | 8h | 1h | 与 SSO Session Max 对齐 |
| SSO Session Idle | 30 min | 15 min | 无活动多久踢 |
| SSO Session Max | 8h | 8h | 绝对上限 |
| Concurrent sessions per user | ≤2 | ≤1 | 超 cap 走§3.4 |
| Refresh token rotation | 强制 | 强制 | 每次刷新换 refresh token |
| Refresh token reuse window | 0 | 0 | 重放即视为攻击 |

### 3.2 token 流转

```
[Login OK]
  ↓ 颁 access (5min) + refresh (8h) + 记 session_ref
[Active]
  ├── 每次请求带 access；网关查 JWT 签名 + Redis 黑名单
  ├── 临近过期：client 调 POST /sessions/current/refresh
  │   ↓ identity 校验 refresh（未被用过 / 未撤销 / 未过期）
  │   ↓ 旋转：颁新 access + 新 refresh；旧 refresh 立即作废
  │   ↓ 更新 session_ref.last_seen_at
  └── 超 idle / 超 max / refresh 重放 / 紧急冻结 → 强制 logout
```

### 3.3 refresh token rotation 攻击检测

如果旧 refresh token 被使用第二次 → 强信号"refresh 已泄漏"：
1. 立即作废该 user 的**所有** active session（不仅是此 session）
2. emit `foundation.identity.session.refresh_reuse_detected`（severity=SECURITY）
3. 通知用户邮件 + 安全管理员
4. 下次登录强制 step-up MFA + 风险提示

实现：Redis `refresh_token:used:{jti}` 标位 TTL = refresh 原寿命；命中已用 → 触发上述流程。

### 3.4 并发会话限制

新登录达到 cap 时两种策略（租户管理员配置）：

| 策略 | 行为 |
|---|---|
| `REJECT_NEW`（默认） | 拒绝新登录，提示"已在其他设备登录" |
| `KICK_OLDEST` | 踢最早的；通知被踢端 "您已被强制下线（异地登录）" |

实现：登录前查 `session_ref` 该 user 的 active count；超 cap 走配置策略；KICK 时 logout 旧 session + Redis 黑名单。

### 3.5 idle / absolute 检查

- access token 的 `exp` 已含 max 检查
- idle 检查不在 token 内（避免每次都续 token）：每次请求经网关时查 `session_ref.last_seen_at`，超 idle 时 401 + `IDLE_TIMEOUT`
- 业务每 N 次请求一次更新 `last_seen_at`（节流，避免 DB 写爆）

### 3.6 失败锁定（指数退避）

```python
def lockout_minutes(attempt_count: int, policy: PasswordPolicy) -> int:
    if attempt_count < policy.max_failed_attempts:
        return 0
    if not policy.exponential_backoff:
        return policy.initial_lockout_minutes
    # 5,6,7,... 次失败 → 30, 60, 120, 240, 480, 1440 (cap)
    excess = attempt_count - policy.max_failed_attempts
    minutes = min(policy.initial_lockout_minutes * (2 ** excess), 1440)
    return minutes
```

24h 无新失败 → 计数重置（防"昨晚 5 次错今晨被永久锁"）。

实现层：Keycloak Brute Force Detection 已有基础能力，但策略写在 SPI `foundation-password-policy-check` 内（与 password policy 同来源）。

### 3.7 设备指纹与异常检测

每个 session 记录：
- `user_agent`
- `ip`
- `device_fingerprint`（前端 [FingerprintJS](https://fingerprintjs.com/) 或自家轻量实现）
- `geoip_country`
- `asn`

异常判定（任一命中 → 触发 MFA / 通知 / 风险提示）：
1. 首次出现的 country
2. 不同 country 间 < 1h（"不可能旅行")
3. 不同 ASN 间 < 5 min
4. user_agent 在过去 90 天从未出现
5. ip_reputation < 阈值（[AbuseIPDB](https://www.abuseipdb.com/) / 阿里云风控）

判定模块 `RiskEvaluator`：

```python
class RiskScore(BaseModel):
    score: float                              # 0.0 - 1.0
    factors: list[RiskFactor]                 # 每条规则贡献

class RiskEvaluator:
    async def evaluate(self, *, user: User, request: LoginRequest,
                       history: list[SessionRef]) -> RiskScore: ...
```

阈值：≥0.5 触发 MFA；≥0.8 拒登 + 通知；< 0.3 通过。具体阈值合规模式可调。

---

## 4. Keycloak 自定义 SPI 接口

[identity-v1.md §4.5](./identity-v1.md) 已列 7 个 SPI。这里给关键 SPI 的 Java 接口签名（实现见 `packages/identity-keycloak-spi/`）。

### 4.1 `foundation-password-policy-check`

```java
public class FoundationPasswordPolicyCheck implements Authenticator {
    @Override
    public void authenticate(AuthenticationFlowContext ctx) {
        String password = ctx.getHttpRequest().getDecodedFormParameters().getFirst("password");
        UserModel user = ctx.getUser();
        String tenantId = user.getFirstAttribute("tenant_id");
        // 走 HTTP 调 identity-service /internal/password-policy/check
        // 含强度 + 历史 + 失败计数 + lockout 判定
        PolicyCheckResult result = client.checkPasswordPolicy(tenantId, user.getId(), password);
        if (!result.isAccepted()) {
            ctx.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
                       challenge(ctx, result.toErrorPage()));
            return;
        }
        ctx.success();
    }
}
```

### 4.2 `foundation-conditional-mfa-condition`

```java
public class FoundationConditionalMfaCondition implements ConditionalAuthenticator {
    @Override
    public boolean matchCondition(AuthenticationFlowContext ctx) {
        MfaDecision d = client.evaluateMfaCondition(buildContext(ctx));
        ctx.getAuthenticationSession().setAuthNote("mfa_reasons", String.join(",", d.getReasons()));
        return d.isRequired();
    }
}
```

### 4.3 `foundation-blacklist-jwt-mapper`

```java
public class FoundationBlacklistJwtMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper {
    @Override
    public AccessToken transformAccessToken(AccessToken token, ...) {
        if (client.isBlacklisted(token.getSubject(), token.getId())) {
            throw new AuthenticationException("token_revoked");
        }
        return token;
    }
}
```

> 出于 KC 颁 token 这一步直接拒发，比"颁了后网关再查 Redis 黑名单"更彻底，但增加 KC 出口延迟。两层都做，深度防御。

### 4.4 SPI 与 identity-service 的通信

- 都通过 HTTP 调 identity-service `/internal/keycloak-spi/*` 端点
- 走 mTLS + token（KC 启动时由 identity 注入）
- 超时 200ms；失败 fail-closed（拒绝认证）

---

## 5. 状态机集成

把 §1-3 的状态机串起来：

```
[Anonymous]
   │ POST /sessions {EMAIL_PASSWORD}
   ▼
[Auth: password check]                     ← foundation-password-policy-check SPI
   │   pass: 密码正确 + blocklist OK + 未过期
   │   fail: WEAK / PWNED / EXPIRED / LOCKED → 错误页 / 失败计数
   ▼
[Risk evaluate]                            ← RiskEvaluator
   │   score ≥0.8 → 拒登 + 通知 + 加入 risk_log
   │   score 0.5-0.8 → MFA required regardless of policy
   │   score <0.5 → MFA per policy
   ▼
[MFA condition check]                      ← foundation-conditional-mfa-condition SPI
   │   required → 202 MfaChallengeResponse
   │   not required → skip
   ▼
[MFA verify]
   │   pass: 验签 OK
   │   fail: 3 次 challenge 作废
   ▼
[Concurrent session check]                 ← foundation-session-cap-check SPI
   │   超 cap → REJECT_NEW 或 KICK_OLDEST
   ▼
[Issue tokens]
   │   颁 access (5min) + refresh (8h) + session_ref
   │   blacklist mapper 检查 → emit session.created
   ▼
[Active]
   │   ├── refresh rotation
   │   ├── idle timeout
   │   ├── absolute timeout
   │   ├── admin revoke
   │   ├── 紧急冻结
   │   └── refresh reuse → 杀该 user 所有 session
   ▼
[Revoked]
   │   写 frozen_token_blacklist + emit session.revoked
```

---

## 6. 配置面（管理控制台）

租户管理员可在控制台调整（在合规基线之上加严）：

| 分组 | 字段 |
|---|---|
| 密码策略 | min_length / min_length_with_mfa / max_age_days / history_count / max_failed_attempts / blocklist_sources |
| MFA 强制 | always_for_admins / always_for_all / IP-CIDR 白名单（白内不要求） / 异常 risk_score 阈值 |
| Session | idle_minutes / absolute_hours / refresh_minutes / concurrent_cap / concurrent_policy |
| Risk | risk_evaluator_enabled / ip_reputation_provider / impossible_travel_threshold |

所有修改：写 `tenant_auth_policy_override` 表 → 触发 KC realm settings 同步 → 写审计。

---

## 7. 错误码（补充 identity 的）

| code | 何时 | HTTP |
|---|---|---|
| `FOUNDATION.IDENTITY.AUTH.MFA_REQUIRED` | 需 MFA 但未提供 | 401 |
| `FOUNDATION.IDENTITY.AUTH.MFA_CHALLENGE_EXPIRED` | 5 min 过期 | 401 |
| `FOUNDATION.IDENTITY.AUTH.MFA_CHALLENGE_FAILED` | 3 次校验错 | 401 |
| `FOUNDATION.IDENTITY.AUTH.MFA_METHOD_NOT_REGISTERED` | 选了未绑通道 | 422 |
| `FOUNDATION.IDENTITY.AUTH.MFA_LAST_CREDENTIAL_PROTECTED` | 删最后一个 | 409 |
| `FOUNDATION.IDENTITY.AUTH.SESSION_IDLE_TIMEOUT` | 闲置超时 | 401 |
| `FOUNDATION.IDENTITY.AUTH.SESSION_ABSOLUTE_TIMEOUT` | 绝对超时 | 401 |
| `FOUNDATION.IDENTITY.AUTH.SESSION_REFRESH_REUSE_DETECTED` | 重放 | 401（特殊：触发杀全 session） |
| `FOUNDATION.IDENTITY.AUTH.SESSION_CONCURRENT_LIMIT` | 超并发 cap | 429 |
| `FOUNDATION.IDENTITY.AUTH.RISK_TOO_HIGH` | risk≥0.8 拒登 | 403 |
| `FOUNDATION.IDENTITY.AUTH.RECOVERY_CODE_INVALID` | 校验错 | 401 |
| `FOUNDATION.IDENTITY.AUTH.RECOVERY_CODE_EXHAUSTED` | 全用完 | 422 |

---

## 8. 部署形态差异

| 维度 | small | medium | large |
|---|---|---|---|
| HIBP 查询 | 实时调公开 API | 实时 + 缓存 Redis | 离线 mirror（每周更新）+ Redis |
| Blocklist (rockyou) | 内存 100MB Bloom Filter | 同 | Redis cluster 共享 |
| Recovery code 哈希 | Argon2id m=8M | 同 | 同 |
| Risk evaluator | 关或基线规则 | 基线规则 | + ip_reputation 商业 API |
| Refresh reuse 检测 | Redis 单实例 | Redis Sentinel | Redis cluster |
| Session 表写吞吐 | 直 DB | + LRU 节流 last_seen_at | 同 |
| MFA challenge 存 | Redis 单 | Redis Sentinel | Redis cluster |

---

## 9. 测试策略

### 9.1 单元（≥90%）
- PasswordPolicy.merged() 取最严
- StrengthChecker：100+ 用例（弱密码/强密码/HIPB hash 命中/personal info）
- lockout_minutes 指数退避边界
- TOTP 容忍窗口
- recovery code 一次性
- RiskEvaluator 各 factor 独立 + 综合

### 9.2 集成（依赖 KC + Redis）
- 完整登录 → MFA → token → refresh → logout
- 失败 5 次锁定 + 30 min 解锁
- refresh 重放检测 → 杀全 session
- 并发 cap 两种策略
- MFA 各 method enroll/verify
- 异常 IP / impossible travel 触发 MFA

### 9.3 安全 fuzz
- 暴力破解：脚本跑 1000 次失败登录 → 锁定按预期触发
- TOTP 重放：同 code 用第二次必失败
- challenge 跨用户 / 跨 session：拒绝
- recovery code 暴力：每秒 100 次猜 8 字符 base32（理论 ~32^8 = 10^12，应稳）
- timing attack：verify TOTP 时间应恒定
- HIBP API 失联：fail-open 不拦截（避免拒服务）但记 warning

### 9.4 兼容性
- TOTP 客户端矩阵：Google / Microsoft / Authy / 1Password / Aegis
- WebAuthn 浏览器矩阵：Chrome / Safari / Firefox / Edge 各 latest 2 个版本
- WebAuthn 硬件：YubiKey 5 / Token2 / TouchID / Face ID / Windows Hello

---

## 10. 待解决问题

| # | 问题 | 决策机制 | 截止 |
|---|---|---|---|
| Q1 | HIBP 商业版（含完整 SHA1 列表）vs k-anonymity API | small profile 用 API；medium+ 评估商业版 | A-M2 |
| Q2 | RiskEvaluator 阈值是否租户自定义 | 是；提供 3 档预设（宽松/默认/严格）+ 高级模式 | A-M3 |
| Q3 | "impossible travel" 时区与 VPN 误判 | VPN exit node 数据库 + 用户行为基线学习；初版宽松 + 仅触发 MFA 不直接拒登 | A-M3 |
| Q4 | SMS OTP 是否首版交付 | 是（钉钉企业版客户期望）；走 notification-service 短信通道 | A-M1 |
| Q5 | Push 通知通道（如自家 App） | v1.1；首版不交付 | v1.1 |
| Q6 | Passkey 跨设备同步（iCloud/Google）vs 仅本机 | 默认允许同步（用户便利）；金融模式可禁同步（要求 device-bound） | A-M3 |
| Q7 | recovery code 数量与字符数 | 默认 8 个 × 8 字符 base32；剩 ≤2 提示生成新批 | 已定 |
| Q8 | refresh reuse 拒绝时是否给用户友好提示 | 是；专门错误页 + 安全说明 + 重新登录引导 | A-M2 |
| Q9 | Argon2id 参数硬件随发展加大 | 每年 review；登录成功后透明 re-hash | A-M2 |
| Q10 | step-up 验证（已登录但敏感操作需重验密 / MFA）的 UX | 模态对话框 + 5 min 内复用结果；详细 UI 待 P3 | v1.1 |

---

## 11. 验证标准（M1 出口）

- [ ] PasswordPolicy 合规模式矩阵单元测试覆盖（5 模式 × 10 字段）
- [ ] StrengthChecker 100+ 用例通过；HIBP 集成端到端
- [ ] 失败锁定 / 指数退避按预期触发
- [ ] TOTP / WebAuthn / Recovery code 端到端 enroll + verify
- [ ] refresh token rotation + reuse detection 验证
- [ ] 并发 cap 两种策略验证
- [ ] RiskEvaluator 5 规则单测 + 综合阈值
- [ ] 自定义 SPI 3 个 Java 单测 + KC 集成 e2e
- [ ] 错误码与 i18n 文案
- [ ] 三档 helm profile 都能跑

---

## 12. 参考资料

- [NIST SP 800-63B Rev 4 (2025-08)](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [NIST Password Guidelines 2026 explainer — Enzoic](https://www.enzoic.com/blog/nist-sp-800-63b-rev4/)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Keycloak 26.4 Passkeys 公告](https://www.keycloak.org/2025/09/passkeys-support-26-4)
- [Keycloak WebAuthn + Passkeys — phasetwo](https://phasetwo.io/blog/webauthn-keycloak/)
- [Have I Been Pwned k-anonymity API](https://haveibeenpwned.com/API/v3#PwnedPasswords)
- [W3C WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/)
- [RFC 6238 — TOTP](https://datatracker.ietf.org/doc/html/rfc6238)
- [RFC 9106 — Argon2](https://datatracker.ietf.org/doc/html/rfc9106)
- [OAuth 2.1 BCP — refresh token rotation](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)

---

## 13. 变更记录

| 日期 | 版本 | 变更 |
|---|---|---|
| 2026-05-22 | 0.1.0 | 初版（P1 #8） |
