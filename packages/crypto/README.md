# foundation-crypto

> SaaS Foundation 密码学服务：envelope encryption + KEK 生命周期 + 数字签名 + 密码哈希。
>
> 详见 [docs/design/crypto-v1.md](../../docs/design/crypto-v1.md)
> + [contracts/openapi/crypto.yaml](../../contracts/openapi/crypto.yaml)。

## M1 范围

- **envelope encryption**：业务调 `/envelope:encrypt`、`/envelope:decrypt`，KEK 不出 Vault
- **签名 / 验签**：Ed25519 / ECDSA-P256；为 audit hash chain 提供 detached sign
- **密码哈希**：Argon2id（OWASP 默认参数）；identity 通过 SDK 调
- **KEK 生命周期**：create / list / rotate / mark-for-destruction / destroy（双步 + 冷静期）
- **算法 registry**：国际算法（AES-256-GCM / SHA-256 / HMAC-SHA-256 / Ed25519 / RSA-OAEP-4096）；国密 SM2/3/4 留作 v1.1

## 启动

```bash
# 1. 起底座栈（包含 Vault dev）
make -C ../.. up-full

# 2. 装依赖 + 迁移
poetry install
poetry run alembic upgrade head

# 3. 启动
poetry run foundation-crypto       # → http://localhost:8004
```

## 关键端点

| 路径 | 用途 |
|---|---|
| `POST /api/crypto/v1/envelope:encrypt` | 字段加密；返 envelope（含 wrapped DEK + ciphertext） |
| `POST /api/crypto/v1/envelope:decrypt` | 解 envelope |
| `POST /api/crypto/v1/envelope:rewrap` | KEK 轮换后重新包 DEK |
| `POST /api/crypto/v1/sign` | 签名（Ed25519 默认） |
| `POST /api/crypto/v1/verify` | 验签 |
| `POST /api/crypto/v1/password-hash` | Argon2id 哈希 |
| `POST /api/crypto/v1/password-verify` | 校验密码 |
| `GET/POST /api/crypto/v1/keks` | KEK 管理 |
| `POST /api/crypto/v1/keks/{id}/rotate` | 轮换 |
| `POST /api/crypto/v1/keks/{id}/mark-for-destruction` | 标记销毁（冷静期开始） |
| `POST /api/crypto/v1/keks/{id}/destroy` | 执行销毁（需冷静期满 + 4 眼） |
| `GET /api/crypto/v1/algorithms` | 算法清单 |

## 测试

```bash
poetry run pytest                # 全部
poetry run pytest -m unit        # 仅单元
```

## 关键设计

- **后端**：HashiCorp Vault transit secrets engine（M1）；softhsm2 + Tongsuo（v1.1）
- **密钥层级**：MasterKey → KEK → DEK；MasterKey 在 Vault unseal/HSM；KEK 在 Vault transit；DEK 应用本地随机
- **双步销毁**：mark-for-destruction → 30 天冷静期 → destroy；destroy 需 4 眼审批 + PAM JIT
- **envelope schema**：JSON `{schema_version, algorithm, kek_id, kek_version, wrapped_dek, nonce, ciphertext, aad}`，跨版本兼容
- **审计**：encrypt 100% / decrypt 1% 采样 / sign 100% / destroy 100%（合规模式可调）
- **fail-closed**：Vault 不可达 → 503 `FOUNDATION.CRYPTO.DEPENDENCY.VAULT_UNAVAILABLE`
