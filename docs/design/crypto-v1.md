# Crypto Service — 设计文档 v0.1

> P1 #7 产出。覆盖 A-M1 范围 + v1.1 国密扩展点。配套：
> - [CONVENTIONS.md](../CONVENTIONS.md)
> - [errors.md](../errors.md)
> - [multi-tenancy.md](../multi-tenancy.md)
> - [identity-v1.md](./identity-v1.md)

---

## 1. Context

`crypto-service` 是底座**唯一的密码学边界**。所有业务代码不允许直接调 OpenSSL / cryptography / hashlib 做敏感操作；必须经它的 SDK：
- 字段加密 / 解密
- 数字签名 / 验签
- 密码哈希（用户密码 / 审计 hash chain）
- 密钥生成 / 派生 / 销毁
- TLS 证书材料管理

这样做的收益是：
1. **算法一处切换**：今天 AES，明天合规要求国密 SM4 → 改 crypto-service 一处，业务零改动
2. **密钥不出 HSM/KMS**：业务进程拿不到原始 KEK，只能调"加密 / 解密"动作
3. **审计**：所有 crypto 操作走统一 log，关键操作（导出私钥、销毁密钥）强审计
4. **合规**：密评 / 等保 / 国密改造的影响半径降到 1 个服务

### 关键技术决定（已定型）

| 维度 | 决定 | 理由 |
|---|---|---|
| 主架构 | **envelope encryption**（KEK in HSM/Vault，DEK 应用本地） | 性能（业务本地 AES）+ 安全（KEK 不出 HSM）；Vault transit P99 ~0.63ms 实测 |
| 默认后端 | **HashiCorp Vault transit secrets engine** | 开源、Apache 2.0、多 provider 一致接口、支持 derived key + 自动轮换 |
| HSM 抽象 | **PKCS#11 标准接口** | TASS / 江南天安 / AWS CloudHSM / Azure Dedicated HSM 一致接入 |
| 算法套件 | **国际（OpenSSL）+ 国密（Tongsuo / GmSSL-Python）双轨** | 通过 algorithm registry 切换，业务无感知 |
| 国密实现 | 优先 **Tongsuo（铜锁，蚂蚁开源）**；备选 GmSSL-Python（成熟稳定） | Tongsuo 与 OpenSSL API 兼容性好；GmSSL 作为 fallback |
| 密钥层级 | **MasterKey → KEK → DEK** 三层 | 行业标准；MasterKey 在 HSM 永不出库 |
| 字段加密粒度 | **per-field KEK + per-record DEK** | 一个字段轮换不影响其他；DEK 跟密文一起存（加密后） |
| TLS 终端 | mTLS 默认 OpenSSL；合规模式切 **GMTLS（Tongsuo）** | service mesh 层切换；业务无感 |
| Postgres TDE | **不依赖 DB 内建 TDE**；走应用层字段加密 | DB TDE 在多云一致性差；字段加密能选哪些字段 |
| 密钥轮换 | KEK 90 天自动；DEK 无需轮换（rewrap 即可） | Vault 内置版本管理；旧 ciphertext 仍可解 |
| 密钥销毁 | **min_decryption_version + delete 双步** | 防误删；销毁前必须显式 "永久标记" |
| 紧急销毁 | 走 PAM JIT + 四眼 + 审计 | 数据销毁的快速通道（密钥销毁 ≡ 数据销毁） |

---

## 2. 职责边界

### crypto-service 负责
- algorithm registry（声明可用算法 + 当前默认）
- KEK 生命周期管理（创建 / 轮换 / 归档 / 销毁）
- envelope encrypt/decrypt API
- 数字签名 / 验签 API（hash chain / 文件 / JWT 国密签名）
- 密码哈希 API（Argon2id / SM3-HMAC，业务调，不自存密码）
- TLS 证书材料管理（issued from `crypto-service` → cert-manager 接走部署）
- 与 HSM/KMS provider 的所有交互（Vault / AWS KMS / TASS / 江南天安）
- 密钥使用审计（每次 op 一条记录）

### crypto-service 不负责
- 业务密钥的"该不该解密"判定 → `authz-service`
- 用户密码存储 → `identity-service`（仅借 crypto 做哈希）
- mTLS 证书的 K8s 部署 → cert-manager
- 用户数据本身的销毁流程 → `lifecycle-service` + `data-protection-service`（crypto 提供"密钥销毁 = 数据销毁"快速通道）
- 合规策略本身定义 → `compliance-service` 告诉 crypto "当前租户用国际还是国密"

### 与其他 service 的交互

```
                ┌────────────────────────────────┐
                │ Other Services (业务)          │
                │ identity / audit / billing / ..│
                └───────────┬────────────────────┘
                            │ foundation_crypto SDK
                            │  ↳ encrypt(plaintext, key_label, context)
                            │  ↳ decrypt(envelope)
                            │  ↳ sign(data, key_label)
                            │  ↳ hash_password(password)
                            ▼
                ┌────────────────────────────────┐
                │ crypto-service                 │
                │  ↳ algorithm registry          │
                │  ↳ KEK metadata 表             │
                │  ↳ envelope orchestration       │
                └───┬──────────────┬─────────────┘
                    │              │
                    ▼              ▼
            ┌──────────────┐  ┌──────────────────┐
            │ Vault transit│  │ HSM (PKCS#11)    │
            │ (主)         │  │ TASS / 江南天安   │
            └──────────────┘  └──────────────────┘
                    │              │
                    ▼              ▼
            ┌──────────────────────────────┐
            │ MasterKey (永不出库)          │
            └──────────────────────────────┘

  并行：所有操作 → audit-service（关键操作 → WORM）
```

---

## 3. 算法 Registry

### 3.1 算法清单

| 类别 | 国际默认 | 国密 | 合规模式触发切换 |
|---|---|---|---|
| 对称加密 | AES-256-GCM | SM4-GCM | `equal_protection_4` / `finance_jrt0071` |
| 非对称（签名） | Ed25519 / ECDSA-P256 | SM2 | 同上 |
| 非对称（加密） | RSA-OAEP-4096 | SM2 | 同上 |
| 哈希 | SHA-256 | SM3 | 同上 |
| HMAC | HMAC-SHA-256 | HMAC-SM3 | 同上 |
| KDF | HKDF-SHA-256 | KDF-SM3 | 同上 |
| 密码哈希 | Argon2id (m=64MB, t=3, p=4) | Argon2id（暂无国密对应；可加 SM3 预 hash） | 默认两者均用 Argon2id |
| TLS | TLS 1.3 + AEAD ciphers | GMTLS（GB/T 38636） | 同上 |
| 随机数 | OpenSSL DRBG | HSM RNG / Tongsuo DRBG | 默认 OpenSSL；HSM 可用时优先 |

### 3.2 Registry 数据模型

```sql
CREATE TABLE crypto.algorithm (
    id              TEXT PRIMARY KEY,                 -- "AES-256-GCM" / "SM4-GCM"
    kind            TEXT NOT NULL CHECK (kind IN
                    ('SYMMETRIC','ASYMMETRIC_SIGN','ASYMMETRIC_ENCRYPT',
                     'HASH','HMAC','KDF','PASSWORD_HASH','TLS_SUITE','RNG')),
    family          TEXT NOT NULL,                    -- "AES" / "SM4" / "RSA" / "SM2"
    provider        TEXT NOT NULL CHECK (provider IN
                    ('openssl','tongsuo','gmssl','hsm','vault')),
    key_size_bits   INT,
    fips_140        BOOLEAN NOT NULL DEFAULT false,
    gm_certified    BOOLEAN NOT NULL DEFAULT false,    -- 国密合规
    deprecated      BOOLEAN NOT NULL DEFAULT false,
    description     TEXT,
    -- 政策
    min_compliance_modes TEXT[] DEFAULT '{}',         -- 哪些合规模式启用此算法
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE crypto.tenant_algorithm_policy (
    tenant_id    TEXT PRIMARY KEY REFERENCES tenant.tenant(id),
    -- 各 kind 的默认算法（覆盖系统 default）
    symmetric_default      TEXT REFERENCES crypto.algorithm(id),
    sign_default           TEXT,
    hash_default           TEXT,
    password_hash_default  TEXT,
    -- 合规模式锁定（合规模式启用时强制此算法）
    locked_by_compliance   TEXT[] DEFAULT '{}',
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by             TEXT
);
```

业务 SDK 调用时：

```python
from foundation_crypto import crypto

# 业务不指定算法；crypto 根据当前租户的 policy + compliance mode 选
envelope = crypto.encrypt(plaintext, key_label="pii.phone", context={"user_id": "usr_..."})
```

返回的 envelope **自带算法元**，解密时不用业务记得用了哪个算法：

```python
plaintext = crypto.decrypt(envelope)  # envelope 含 algorithm + key_version
```

---

## 4. 密钥层级

```
                ┌────────────────────┐
                │ MasterKey          │ ← HSM-only，永不离开
                │ (SM2/Ed25519 + AES-256)
                └────────┬───────────┘
                         │ unseal Vault / 直接 PKCS#11
                         ▼
                ┌────────────────────┐
                │ KEK (Key Encryption Key)
                │ 每租户 / 每用途一把
                │ 在 Vault transit
                └────────┬───────────┘
                         │ wrap (DEK) → ciphertext
                         ▼
                ┌────────────────────┐
                │ DEK (Data Encryption Key)
                │ 每次加密随机生成
                │ 与密文同存（wrapped）
                └────────────────────┘
```

### 4.1 MasterKey
- 物理形式：HSM 自存的根密钥（不可导出）
- 数量：1（生产环境）；备份 HSM 同步副本
- 销毁：仅退役 HSM 时；流程级动作

### 4.2 KEK
- 命名 `<tenant>/<purpose>` 例 `tnt_01J.../audit-hashchain` / `tnt_01J.../pii-phone`
- 在 Vault 是 transit key，启用 derived key + auto-rotate
- 轮换周期：默认 90 天；合规模式可改 30/60 天
- 旧版本保留 ≥ retention period（解旧密文用）
- 元数据存 `crypto.kek` 表

### 4.3 DEK
- 每次 encrypt 由 Vault 通过 `transit/datakey/plaintext/<kek>` 生成
- 应用本地 AES-256-GCM 加密 plaintext
- DEK 同时返 wrapped 版本（用 KEK 加密的），与密文同存
- 解密：Vault `transit/decrypt/<kek>` unwrap DEK → 本地解密

### 4.4 KEK 元数据表

```sql
CREATE TABLE crypto.kek (
    id              TEXT PRIMARY KEY,                          -- "kek_pii_phone_tnt_01J..."
    tenant_id       TEXT NOT NULL REFERENCES tenant.tenant(id),
    label           TEXT NOT NULL,                             -- "pii.phone"
    purpose         TEXT NOT NULL,                             -- "FIELD_ENCRYPT" / "AUDIT_HMAC" / "JWT_SIGN"
    algorithm_id    TEXT NOT NULL REFERENCES crypto.algorithm(id),
    vault_path      TEXT NOT NULL,                             -- "transit/keys/pii_phone_tnt_01J"
    pkcs11_label    TEXT,                                      -- 走 HSM 时
    current_version INT NOT NULL DEFAULT 1,
    min_decryption_version INT NOT NULL DEFAULT 1,             -- 销毁旧版本前的安全门
    auto_rotate_days INT NOT NULL DEFAULT 90,
    last_rotated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    status          TEXT NOT NULL DEFAULT 'ACTIVE'
                    CHECK (status IN ('ACTIVE','SUSPENDED','MARKED_FOR_DESTRUCTION','DESTROYED')),
    destruction_scheduled_at TIMESTAMPTZ,                      -- 销毁排程
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by      TEXT,
    UNIQUE (tenant_id, label)
);

CREATE INDEX kek_tenant_idx ON crypto.kek (tenant_id);
CREATE INDEX kek_status_idx ON crypto.kek (status) WHERE status != 'ACTIVE';
-- RLS 同上
```

---

## 5. PKCS#11 抽象接口（HSM 厂商解耦）

### 5.1 为什么 PKCS#11

不同厂商 HSM SDK 不同（TASS C SDK / 江南天安 Java SDK / AWS CloudHSM 自有 SDK）。PKCS#11 是事实标准，绝大多数厂商兼容。这样：
- 业务通过 crypto-service 用统一接口
- crypto-service 通过 PKCS#11 库（如 `python-pkcs11` 或 `pyhsm`）调任何兼容 HSM
- 切厂商只改 `pkcs11_provider_lib` 配置

### 5.2 抽象层

```python
# foundation_crypto.providers.pkcs11
class PKCS11Provider:
    def __init__(self, lib_path: str, slot_id: int, pin: str): ...

    async def generate_key(self, *, label: str, algorithm: str, length: int) -> KeyHandle: ...
    async def wrap_key(self, kek_label: str, dek_bytes: bytes) -> bytes: ...
    async def unwrap_key(self, kek_label: str, wrapped: bytes) -> bytes: ...
    async def sign(self, key_label: str, mechanism: str, data: bytes) -> bytes: ...
    async def verify(self, key_label: str, mechanism: str, data: bytes, sig: bytes) -> bool: ...
    async def destroy_key(self, label: str) -> None: ...   # PKCS#11 底层 API（HSM 内）
    async def list_keys(self) -> list[KeyInfo]: ...
```

> **公共 SDK 命名约定**（被 lifecycle / dlp / data-protection 等模块调用，必须稳定）：
> - `crypto.kek_mark_for_destruction(kek_id, reason)` → 标记 KEK 进入冷静期
> - `crypto.kek_destroy(kek_id)` → 冷静期结束后执行实际销毁（调用 PKCS#11 `destroy_key`）
> - `crypto.kek_abort_destruction(kek_id, reason)` → 冷静期内撤销标记
>
> SDK 名以上为准；其他文档（lifecycle / dlp / data-protection / pam）统一引用这些名字，**禁用** `destroy_key(...)` / `delete_key(...)` 等变体。

### 5.3 已规划支持的 HSM

| 厂商 | 驱动 | 国密 | 备注 |
|---|---|---|---|
| HashiCorp Vault | transit secrets engine（默认） | ❌ 不原生支持 SM | 默认；非国密场景 |
| Tongsuo + softhsm2 | softhsm2 dev | ✅ | 开发环境模拟 HSM |
| TASS HSM | 厂商 PKCS#11 库 `libtass-pkcs11.so` | ✅ | 金融政务首选 |
| 江南天安 HSM | 厂商 PKCS#11 库 | ✅ | 同上 |
| AWS CloudHSM | `libcloudhsm_pkcs11.so` | ❌ | 海外 |
| 阿里云 KMS | 阿里云 SDK（独立 adapter，非 PKCS#11） | ✅ 凭据托管模式 | 阿里云客户 |
| Azure Dedicated HSM | PKCS#11 | ❌ | 海外 Azure 客户 |

---

## 6. API 表面

完整 OpenAPI 在 `contracts/openapi/crypto.yaml`。端点清单：

### 6.1 加密 / 解密
| 端点 | 方法 | 权限 | 说明 |
|---|---|---|---|
| `/envelope:encrypt` | POST | `crypto.envelope.encrypt` | 应用层加密；返 envelope（含 wrapped DEK + ciphertext） |
| `/envelope:decrypt` | POST | `crypto.envelope.decrypt` | 解 envelope |
| `/envelope:batch-encrypt` | POST | `crypto.envelope.encrypt` | 批量（高吞吐场景） |
| `/envelope:rewrap` | POST | `crypto.envelope.rewrap` | KEK 轮换后重新包 DEK（不动 ciphertext） |

### 6.2 签名 / 验签
| 端点 | 方法 | 权限 |
|---|---|---|
| `/sign` | POST | `crypto.sign` |
| `/verify` | POST | `crypto.verify` |
| `/sign-detached` | POST | `crypto.sign` |（用于审计 hash chain） |

### 6.3 密码哈希
| 端点 | 方法 | 权限 |
|---|---|---|
| `/password-hash` | POST | `crypto.password.hash` |
| `/password-verify` | POST | `crypto.password.verify` |

### 6.4 KEK 管理
| 端点 | 方法 | 权限 |
|---|---|---|
| `/keks` | GET / POST | `crypto.kek.list` / `crypto.kek.create` |
| `/keks/{id}` | GET | `crypto.kek.read` |
| `/keks/{id}/rotate` | POST | `crypto.kek.rotate` |
| `/keks/{id}/mark-for-destruction` | POST | `crypto.kek.destroy_mark`（HIGH，requires_mfa） |
| `/keks/{id}/destroy` | POST | `crypto.kek.destroy_execute`（CRITICAL，requires_4eyes + JIT） |
| `/keks/{id}/usage` | GET | `crypto.kek.read` |（看哪些 service 在用） |

### 6.5 算法 / 策略
| 端点 | 方法 | 权限 |
|---|---|---|
| `/algorithms` | GET | bearer |（公开） |
| `/tenant/algorithm-policy` | GET / PUT | `crypto.policy.update` |

### 6.6 证书材料（与 cert-manager 协作）
| 端点 | 方法 | 权限 |
|---|---|---|
| `/csr` | POST | `crypto.csr.create` |（生成 CSR + 私钥仅在 HSM 内） |
| `/certificates` | GET / POST | `crypto.cert.*` |
| `/tls-suites` | GET | bearer |（当前可用 TLS suite） |

### 6.7 内部
| 端点 | 方法 | 用途 |
|---|---|---|
| `/internal/health/hsm` | GET | 探测 HSM/Vault 可达 |
| `/internal/audit-decisions` | POST | 收 audit 反向通知（密钥访问后置审计） |

---

## 7. 关键操作时序

### 7.1 字段加密

```
service A
  ↓ crypto.encrypt(plaintext, key_label="pii.phone", context={user_id})
foundation_crypto SDK
  ↓ HTTP POST /envelope:encrypt
crypto-service
  ↓ 查 KEK by (tenant_id, label) → 路径
  ↓ Vault POST transit/datakey/plaintext/<kek>  (or HSM PKCS#11 generate_key)
  ↓ 返 (plaintext_DEK, wrapped_DEK)
  ↓ AES-GCM 加密 plaintext with plaintext_DEK
  ↓ 销毁内存中的 plaintext_DEK
  ↓ envelope = {algorithm, kek_id, kek_version, wrapped_dek, nonce, ciphertext, aad=context}
  ↓ 异步审计：emit foundation.crypto.field.encrypted (含 key_label, no plaintext)
return envelope (b64) → service A
service A → 存 DB
```

性能预算：
- Vault transit datakey: ~0.6ms P99
- AES-GCM 加密 1KB: ~0.01ms
- 总端到端 P99 < 5ms（含 RPC）

### 7.2 字段解密

```
service A
  ↓ crypto.decrypt(envelope)
foundation_crypto SDK
  ↓ HTTP POST /envelope:decrypt
crypto-service
  ↓ 解析 envelope，识别 algorithm + kek_id + kek_version
  ↓ Vault POST transit/decrypt/<kek>?version=<v>   (or HSM unwrap)
  ↓ 返 plaintext_DEK
  ↓ AES-GCM 解密 ciphertext with plaintext_DEK
  ↓ 销毁 plaintext_DEK
  ↓ 异步审计 (允许采样：99% 不写，1% 写；deny 100% 写)
return plaintext → service A
```

### 7.3 KEK 轮换

```
管理员触发 / 自动 cron (每 90 天)
  ↓ POST /keks/{id}/rotate
crypto-service
  ↓ Vault POST transit/keys/<kek>/rotate
  ↓ 更新 crypto.kek.current_version
  ↓ emit foundation.crypto.kek.rotated
  ↓ （可选）排队 rewrap job：把所有旧 ciphertext 的 DEK 重新包到新版本
背景 rewrap worker
  ↓ scan business 表（按 label 标记）
  ↓ POST /envelope:rewrap 每条
  ↓ 全部 rewrap 完成后：可执行 min_decryption_version += 1 （限制只能用新版本解）
```

注：业务**不必**立即 rewrap。旧版本 KEK 会保留 N 个版本（可配），旧 ciphertext 仍能解。rewrap 是为了"将来安全删除旧版本"准备。

### 7.4 紧急密钥销毁（= 数据销毁的快速通道）

```
合规事件：客户撤销同意 / 法律要求 / 数据泄露应急
  ↓ 管理员 POST /keks/{id}/mark-for-destruction
crypto-service
  ↓ kek.status = MARKED_FOR_DESTRUCTION
  ↓ 30 天冷静期（可缩短至 0，要 4 眼）
  ↓ emit foundation.crypto.kek.marked_for_destruction
  ↓ 通知中心：告警安全管理员
... 30 天后
  ↓ 自动 / 手动 POST /keks/{id}/destroy
  ↓ 校验：requires_4eyes 通过 + PAM JIT 通过 + reason 非空
  ↓ Vault DELETE transit/keys/<kek> (allow_deletion=true 必须先 update key 配置)
  ↓ HSM PKCS#11 destroy_object (如适用)
  ↓ kek.status = DESTROYED
  ↓ 生成销毁证明 PDF（含 audit + 4 眼签字 + hash 存证）
  ↓ 落 audit + WORM
  ↓ 通知 lifecycle / data-protection 写销毁证明记录
```

效果：该 KEK 加密的全部 ciphertext **永远无法解密**，等同物理销毁。这是 GDPR/PIPL "被遗忘权" 最干净的实现。

---

## 8. 字段级加密的业务集成

业务 service 在 schema 上声明哪些字段加密：

```python
# packages/identity/src/foundation_identity/models/user.py
from foundation_crypto.orm import EncryptedField

class User(Base):
    __tablename__ = "user"
    __table_args__ = {"schema": "identity"}

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False)
    email = Column(String, nullable=False)

    # 加密字段：DB 里存 envelope，ORM 透明解密
    phone = EncryptedField(key_label="pii.phone", classification="L3")
    id_card = EncryptedField(key_label="pii.id_card", classification="L4")
    bank_account = EncryptedField(key_label="pii.bank_account", classification="L4")
```

机制：
- `EncryptedField` 在 SQLAlchemy 的 set/get 自动调 `crypto.encrypt/decrypt`
- DB 列类型 `TEXT`（存 b64 envelope）
- 自动加 `classification` 元数据 → DLP 知道这字段是 L4 不该裸下载
- 查询：`WHERE phone = '13800000000'` 不能直接做（密文）→ 业务需用 `find_by_phone_hash()` 走专门的 `HMAC(phone, key)` 反查列

---

## 9. 密码哈希

```python
# 业务调
hash_b64 = crypto.password_hash(plaintext_password)        # → Argon2id 默认
ok = crypto.password_verify(plaintext_password, hash_b64)
```

实现：
- 默认 Argon2id (m=64MB, t=3, p=4)，OWASP 推荐参数
- crypto-service 内部根据 tenant policy 选 hash 算法
- hash 串自带算法 + 参数（PHC string format），verify 时自动识别
- 国密模式下额外：先 `SM3(password + per-tenant salt)` 再 Argon2id（兼容性 + 国密合规）

**不存密码**：业务存的是 hash；verify 是无状态的。Identity 用此 SDK 而不自实现。

---

## 10. TLS 与 mTLS

### 10.1 mTLS（service 间）

- 默认 cert-manager + 自签 CA
- crypto-service 提供 CA 私钥保管（在 HSM）
- cert-manager 通过 `crypto-service /csr` 签发短期证书（24h，自动续）
- 国密模式：CA 用 SM2，证书用 SM2，TLS 握手走 GMTLS（GB/T 38636）

### 10.2 外部入站 TLS

- Envoy / Nginx 终止 TLS
- 证书可由 crypto-service 签或 ACME（Let's Encrypt）签
- 国密模式：Envoy 需用 Tongsuo 编译版本（或 GMTLS 反代）

### 10.3 TLS suite policy

```yaml
# 通过 foundation_crypto SDK 暴露给 service mesh
tls_policy:
  international:
    min_version: TLSv1.3
    cipher_suites:
      - TLS_AES_256_GCM_SHA384
      - TLS_AES_128_GCM_SHA256
  gm:
    min_version: GMTLSv1.1
    cipher_suites:
      - ECC-SM2-WITH-SM4-SM3
      - ECDHE-SM2-WITH-SM4-SM3
```

---

## 11. Postgres TDE 的取舍

**不依赖 DB 内建 TDE**，理由：
- 多云一致性差（RDS / Aurora / 阿里云 PolarDB / 国产 openGauss / KingbaseES 各自一套）
- 粒度粗（整库 / 整表，不是字段）
- 密钥仍在 DB host 进程内存，未真正分离

替代方案：
- **静态加密**：依赖底层云盘加密（AWS EBS encryption / 阿里云盘加密）—— 防"物理盘被偷"
- **字段加密**：crypto-service 提供，由业务声明哪些字段加密 —— 防"DB query 越权"
- 两者叠加，覆盖威胁更全面

---

## 12. 部署形态差异

| 维度 | small | medium | large |
|---|---|---|---|
| Vault 模式 | dev mode（root token 明文） | Raft 3 节点 + Shamir | 同 + HSM unseal |
| HSM | softhsm2（开发用） | softhsm2 或 Vault transit | TASS / 江南天安 / Cloud HSM |
| crypto-service 副本 | 1 | 3 HPA | 5-10 HPA |
| KEK 自动轮换 | 手动 | 90 天 | 60/30 天（合规） |
| 审计采样 | 100% | encrypt 100%, decrypt 50% | decrypt 1% + 全 deny |

---

## 13. 合规模式联动

| 模式 | 默认算法切换 | 其他影响 |
|---|---|---|
| `pipl` | 保持国际算法 | KEK 轮换 ≤90d；销毁有 4 眼 |
| `equal_protection_3` | 同上 | 加 TLS 1.3 强制；审计全采 |
| `equal_protection_4` | **切国密 SM2/3/4** | KEK ≤60d；GMTLS；HSM 必选（不能仅 Vault） |
| `finance_jrt0071` | 国密 + HSM 必选 | KEK ≤30d；密评年度执行；KEK 销毁必须监管报备 |
| `hipaa` | 国际算法 + FIPS-140-2 库 | 审计 6 年；密钥 PHI 字段独立 KEK |
| `soc2` | 默认 | 密钥生命周期审计 |

---

## 14. 性能与容量

实测基线（参考 [Ariso.ai Vault 案例](https://www.hashicorp.com/en/blog/adopting-hashicorp-vaults-transit-engine-high-performance-envelope-encryption-ariso-ai)）：

| 操作 | P50 | P99 |
|---|---|---|
| Vault transit encrypt (1KB) | 0.47ms | 0.63ms |
| envelope encrypt 完整端到端 | 2ms | 5ms |
| envelope decrypt 完整端到端 | 2ms | 5ms |
| sign (Ed25519) | 1ms | 3ms |
| password hash (Argon2id 默认参数) | 50ms | 100ms |
| KEK rotate | 100ms | 500ms |
| HSM PKCS#11 sign (SM2) | 5ms | 15ms |（厂商而异）|

容量：
- Vault transit 单实例：≥ 10k ops/sec
- HSM：典型 1k-5k ops/sec（厂商而异，常为瓶颈，需评估）
- crypto-service 单 pod：5k req/sec（瓶颈在 RPC + JSON 序列化）

---

## 15. 关键技术风险

| 风险 | 缓解 |
|---|---|
| Vault 单点 → 所有加密不可用 | Raft 3 节点 + HSM unseal；备机房热备；business critical service 缓存 plaintext 短时（< 5s） |
| HSM 性能瓶颈（1k ops/sec） | 仅 KEK ops 走 HSM；DEK 在应用本地，吞吐不靠 HSM |
| KEK 误销毁 → 数据永久失访 | 双步销毁（mark + destroy）+ 30 天冷静期 + 4 眼 + 离线备份 N 天 |
| Tongsuo / GmSSL 与 Python 集成 bug | 跑 NIST CAVP + 国密 GMVT 标准测试套件；Tongsuo 主、GmSSL 备 |
| KEK 轮换后 rewrap 漏 → 旧 KEK 永远不能删 | rewrap worker checkpoint + 进度 metric；超时告警 |
| HSM 厂商升级破坏 PKCS#11 兼容 | 锁厂商 SDK 版本；升级前在 staging 完整回归 |
| Vault transit 版本上限（默认 100） | 监控；超 80 时告警；正常 90 天 / 版本，10 年内不会触顶 |
| 密钥审计日志量大 | 采样 + ClickHouse 列存；deny 与销毁 100%，encrypt/decrypt 按合规模式采样 |
| 业务绕过 crypto-service 直调 openssl | CI Semgrep 规则禁止；只允许 `import foundation_crypto` |
| envelope 跨版本兼容 | envelope JSON 含 `schema_version`；解码兼容 ≥ N 个旧版 |

---

## 16. 测试策略

### 16.1 单元（≥90%）
- algorithm registry 切换
- envelope schema 序列化 / 反序列化
- 密钥 metadata CRUD
- 状态机（KEK ACTIVE → MARKED → DESTROYED）

### 16.2 集成
- 起 Vault dev + softhsm2，跑 encrypt/decrypt/sign/verify/rotate/destroy 全套
- 国密：起 Tongsuo + GmSSL，跑 SM2/3/4 互操作
- 大批量（10 万次 encrypt）性能 + 内存稳定性

### 16.3 安全
- **CAVP 标准测试向量**（AES/SHA/HMAC/ECDSA/Ed25519）
- **GMVT 国密向量**（SM2/3/4）—— 厂商提供
- envelope 篡改：改 ciphertext / nonce / wrapped_dek → 解密必失败
- envelope 重放：跨 context 解密 → 必失败
- 旁路：Argon2id 参数错误（m 太小） → 拒绝
- 密钥泄漏：grep 进程内存找 plaintext key bytes（使用前清零，限制 dump）

### 16.4 故障注入
- Vault 不可达 → crypto-service 返 503 + fail-closed
- HSM 不可达 → 同上
- 误删 KEK → 校验门必拦截
- 双 HSM 主备切换：< 30s

---

## 17. 待解决问题

| # | 问题 | 决策机制 | 截止 |
|---|---|---|---|
| Q1 | Tongsuo vs GmSSL 谁是首选？ | benchmark + 兼容性矩阵；当前定 Tongsuo（OpenSSL API 接近） | A-M1 第 3 周 |
| Q2 | softhsm2 在 large profile 是否可作为低端 HSM 替代？ | 仅 dev/staging；prod 必须真 HSM | 已定 |
| Q3 | 阿里云 KMS / 腾讯云 KMS 是否纳入 v1.0？ | 客户驱动；预留 adapter 接口，v1.1 实现 | v1.1 |
| Q4 | 密钥操作的 audit 采样率 | encrypt 100%, decrypt 1%, sign 100%, destroy 100%，合规模式可调 | A-M2 |
| Q5 | KEK 销毁的"30 天冷静期"是否可配？ | 是；最短 24h（要 4 眼 + 平台 super admin 双批准） | A-M2 |
| Q6 | 国密 TLS 在 Envoy 的实现路径 | Tongsuo 编译 Envoy 或 GMTLS 反代；首选前者 | v1.1 |
| Q7 | Argon2id 之外的密码哈希算法是否提供？（bcrypt / scrypt） | 不；统一 Argon2id（业界共识） | 已定 |
| Q8 | 密钥销毁证明 PDF 模板 | data-protection 配合产出 | A-M2 |
| Q9 | crypto-service 是否需要自带 HA cache（避免 Vault 抖动） | 不缓存 KEK；缓存 algorithm registry + tenant policy | 已定 |
| Q10 | 跨租户密钥租户 ID 隔离强度（同 Vault 不同 path） | path 含 tenant_id + Vault ACL policy 限定 | A-M2 |

---

## 18. 验证标准（M1 出口）

- [ ] OpenAPI `contracts/openapi/crypto.yaml` spectral lint 通过
- [ ] 单元 / 集成测试 ≥90% 覆盖
- [ ] CAVP 国际向量全过；GMVT 国密向量全过
- [ ] envelope encrypt P99 < 5ms（含 Vault RPC）
- [ ] KEK 轮换流程跑通（含 rewrap worker）
- [ ] KEK 双步销毁跑通（mark + 30 天 + destroy + 证明 PDF）
- [ ] softhsm2 PKCS#11 与 Vault 双 provider 切换 e2e
- [ ] 业务绕过 crypto 直调 OpenSSL 被 Semgrep 拦截
- [ ] Vault 故障注入 → service fail-closed + 告警
- [ ] 三档 helm profile 都能跑

---

## 19. 参考资料

- [HashiCorp Vault transit secrets engine](https://developer.hashicorp.com/vault/docs/secrets/transit)
- [Vault envelope encryption](https://developer.hashicorp.com/vault/docs/secrets/transit/envelope-encryption)
- [Ariso.ai high-performance envelope encryption case](https://www.hashicorp.com/en/blog/adopting-hashicorp-vaults-transit-engine-high-performance-envelope-encryption-ariso-ai)
- [Tongsuo 铜锁项目](https://github.com/Tongsuo-Project/Tongsuo)
- [GmSSL 官网](http://gmssl.org/english.html)
- [GmSSL-Python](https://github.com/GmSSL/GmSSL-Python)
- [PKCS#11 v3.0 标准](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.0/os/pkcs11-spec-v3.0-os.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [GB/T 38636-2020 GMTLS 国密 TLS 协议](https://www.chinesestandard.net/PDF.aspx/GBT38636-2020)
- [GM/T 0054 商用密码应用安全性评估通用要求](https://www.sca.gov.cn/sca/c100061/2018-09/30/content_1059811.shtml)

---

## 20. 变更记录

| 日期 | 版本 | 变更 |
|---|---|---|
| 2026-05-22 | 0.1.0 | 初版（P1 #7） |
