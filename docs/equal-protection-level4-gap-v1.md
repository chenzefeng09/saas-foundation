# 等保 2.0 四级差距分析与升级方案

> **版本**: v1.1-pre  
> **当前等级**: 等保 2.0 三级（GB/T 22239-2019）  
> **目标等级**: 等保 2.0 四级  
> **评估日期**: 2026-05-27

---

## 一、三级 vs 四级核心差异

等保四级（S4/A4/G4）在三级基础上新增**强制访问控制**、**形式化安全策略模型**、**可信计算**三项核心技术要求。总体新增/加强约 **25 项控制点**。

| 安全层面 | 三级要求数 | 四级新增/加强 | 关键差异 |
|----------|----------|--------------|---------|
| 物理安全 | 10 | +3 | 独立密码设备区域、电磁屏蔽 |
| 通信网络 | 8 | +4 | 通信双方硬件级鉴别、全网加密 |
| 区域边界 | 20 | +5 | 动态访问控制、APT 检测 |
| 计算环境 | 76 | +8 | 强制访问控制（MAC）、可信计算、形式化模型 |
| 管理中心 | 12 | +3 | 三权分立硬件隔离、冗余热备 |
| 管理制度 | 70 | +2 | 专职安全团队、外部审计半年一次 |
| **合计** | **196** | **+25** | — |

---

## 二、差距分析详情

### 2.1 新增控制项（四级特有，三级无要求）

| # | 控制点 | 四级要求 | 当前状态 | 差距 | 优先级 |
|---|--------|---------|---------|------|--------|
| MAC-01 | **强制访问控制（MAC）** | 主体和客体分配安全属性（安全标记）；基于 BLP/Biba 模型强制实施 | ❌ 未实现 | authz-service 需支持 SELinux/AppArmor 标签 + 安全标记 | **P0** |
| MAC-02 | **形式化安全策略模型** | 用形式化方法（如 Z/Event-B）定义和验证安全策略 | ❌ 未实现 | OPA rego 策略非形式化；需补充形式化模型文档 | **P0** |
| TC-01 | **可信计算环境** | 基于 TPM/TCM 的可信启动、可信度量、远程证明 | ❌ 未实现 | 需集成 TPM 2.0 远程证明 | **P0** |
| TC-02 | **可信路径** | 用户与安全功能间建立可信路径（防中间人） | ⚠️ 部分 | GMTLS 提供信道加密，但缺少 TPM 硬件根 | P1 |
| COM-01 | **通信双方硬件级鉴别** | 基于密码模块（HSM/TPM）的硬件身份鉴别 | ❌ 未实现 | 目前为软件证书；需 HSM 绑定 | **P0** |
| COM-02 | **全网通信加密** | 所有内部通信必须加密（包括东西向流量） | ⚠️ 部分 | GMTLS 覆盖了南北向；东西向 mTLS 未全覆盖 | P1 |
| BND-01 | **动态访问控制** | 基于主体/客体安全属性的动态策略决策 | ⚠️ 部分 | OPA ABAC 支持属性决策，但缺少实时威胁情报输入 | P1 |
| BND-02 | **APT 攻击检测** | 高级持续性威胁检测能力 | ❌ 未实现 | 无专用 APT 检测模块 | P2 |
| MGT-01 | **三权分立硬件隔离** | 系统管理员/安全管理员/审计管理员在不同物理/虚拟设备上操作 | ⚠️ 部分 | 角色分离已有；硬件隔离待实施 | P2 |
| MGT-02 | **管理平台冗余热备** | 管理中心双活或主备切换 | ⚠️ 部分 | K8s HA 提供服务级冗余；管理平台自身无热备 | P2 |

### 2.2 加强控制项（三级有要求，四级加严）

| # | 控制点 | 三级要求 | 四级加严 | 当前差距 |
|---|--------|---------|---------|---------|
| AUTH-01 | 身份鉴别 | 口令+密码技术 | 硬件级（HSM/智能卡）+ 多因子强制 | 需加 HSM-based client cert + 强制 MFA |
| AUTH-02 | 访问控制粒度 | 用户/角色级 | 进程/服务级 + 安全标记 | authz 需支持服务级主体 |
| AUD-01 | 审计日志保护 | 防篡改 + 签名 | 硬件级防篡改（WORM 介质 + TPM 签名） | 目前 S3 Object Lock + hash chain；需加 TPM |
| ENC-01 | 数据加密 | 应用层/数据库 | 硬件级加密（HSM/自加密硬盘） | PII 字段 KEK 在 HSM；普通数据未全覆盖 |
| MON-01 | 入侵检测 | 基于特征 | 基于行为 + AI 分析 | 需集成 UEBA |
| RES-01 | 资源控制 | 静态限制 | 动态 + 预测性资源控制 | K8s ResourceQuota 已有；预测性未实现 |

---

## 三、升级方案

### 阶段 1: 强制访问控制（MAC）— P0

```
目标: 构建基于安全标记的强制访问控制体系
时间: 4-6 周
```

**实施计划**:

1. **安全标记（Security Label）体系**
   - 为主体（用户/服务/进程）和客体（数据/文件/API）分配安全标记
   - 标记格式: `{classification}:{compartment}:{owner}`
   - 示例: `TS:CRYPTO,FIN:admin` (绝密、密码+金融隔离舱、管理员)
   - 标记存储在 `tenant_user.security_labels` 和资源的 `security_label` 字段

2. **authz-service 升级**
   - 新增 `MACEnforcer` 模块，基于 BLP（Bell-LaPadula）和 Biba 模型
   - BLP 规则（保密性）：
     - no-read-up: 主体不可读高于自身安全等级的对象
     - no-write-down: 主体不可写低于自身安全等级的对象（防泄露）
   - Biba 规则（完整性）：
     - no-write-up: 低完整性主体不可修改高完整性对象
     - no-read-down: 高完整性主体不可读低完整性对象

3. **SELinux 集成**（操作系统层兜底）
   - 每个 Foundation 服务运行在独立的 SELinux domain
   - `foundation_crypto_t`, `foundation_authz_t`, etc.
   - 策略: 仅允许声明的 domain 间通信

4. **安全标记 API**
   ```
   POST /api/authz/v1/security-labels/assign
   {
     "principal_type": "user",
     "principal_id": "usr_001",
     "label": {"classification": "S", "compartments": ["CRYPTO"]}
   }
   
   POST /api/authz/v1/mac/check
   {
     "action": "read",
     "resource_label": {"classification": "TS", "compartments": ["CRYPTO"]}
   }
   // → { "allowed": false, "reason": "no-read-up: S < TS" }
   ```

### 阶段 2: 形式化安全模型 — P0

```
目标: 用形式化方法定义核心安全属性
时间: 2-4 周
```

**实施计划**:

1. **访问控制形式化**
   - 使用 Alloy 或 TLA+ 定义 RBAC + MAC 模型
   - 自动化模型检查（CI 中运行 Alloy Analyzer）
   - 验证属性: "任何非特权用户不能访问其他租户的数据"

2. **密钥生命周期形式化**
   - 定义 KEK 状态机（ACTIVE → MARKED → DESTROYED）的形式化规约
   - 验证: "KEK 一旦 DESTROYED 就永远不可恢复"

3. **形式化文档**
   ```
   docs/formal-models/
   ├── access-control.als         # Alloy 模型
   ├── kek-lifecycle.tla          # TLA+ 规约
   └── README.md                  # 形式化方法使用指南
   ```

### 阶段 3: 可信计算 — P0

```
目标: 基于 TPM 2.0 的可信启动 + 远程证明
时间: 6-8 周
```

**实施计划**:

1. **可信启动链**
   - UEFI Secure Boot → Shim → GRUB → Linux kernel (IMA appraisal) → Foundation services
   - 每层度量值写入 TPM PCR（Platform Configuration Registers）
   - 预期 PCR 值存储为 known-good-values.json

2. **远程证明（Remote Attestation）**
   - 服务启动时产生 TPM Quote（签名 PCR 值 + 随机数）
   - 证明服务（attestation-service）验证 Quote 后签发访问令牌
   - 未通过证明的节点不能接收生产流量

3. **TPM 密钥保护**
   - crypto-service 的 KEK wrapping key 存储在 TPM 内
   - TPM 密封（seal）: 密钥仅在特定 PCR 值下才释放
   - 如果 BIOS/kernel 被篡改（PCR 值变化），TPM 拒不解封密钥

4. **组件清单**
   - `packages/attestation/` — 远程证明服务
   - 每个服务的 TPM Quote agent（sidecar 容器）
   - TPM 软件栈: `tpm2-tss`, `tpm2-tools`, `tpm2-pkcs11`

### 阶段 4: 硬件级鉴别 — P0

```
目标: 通信双方基于 HSM 的硬件身份
时间: 4-6 周（依赖 HSM 硬件到位）
```

**实施计划**:

1. **HSM 绑定证书**
   - 每个 Foundation 服务实例持有唯一的 HSM 生成 SM2 密钥对
   - 私钥永不出 HSM，公钥以 X.509 证书形式发布
   - GMTLS 使用该证书做 mTLS

2. **SPIFFE/SPIRE 集成**
   - 使用 SPIFFE 标准为每个 workload 颁发身份: `spiffe://foundation.example.com/ns/production/sa/crypto`
   - SPIRE agent 验证节点 TPM Quote 后才签发 SVID

3. **服务间认证升级**
   - 从 Bearer token → mTLS client cert + SPIFFE SVID
   - authz-service 基于 SPIFFE ID 而非 API token 做访问决策

---

## 四、新增包与代码变更

| 新增/变更 | 说明 | 预计工作量 |
|-----------|------|----------|
| `packages/attestation/` | TPM 远程证明服务 | 4 周 |
| `packages/authz/src/.../mac_enforcer.py` | BLP/Biba 强制访问控制模块 | 3 周 |
| `packages/crypto/src/.../tpm_provider.py` | TPM 2.0 KeyProvider 适配器 | 3 周 |
| `packages/crypto/src/.../sm3.py` | SM3 哈希（已有纯 Python 实现） | ✅ Done |
| `packages/crypto/src/.../pkcs11_provider.py` | PKCS#11 HSM 适配器 | ✅ Done |
| `packages/crypto/src/.../gmtls.py` | GMTLS 配置 | ✅ Done |
| `docs/formal-models/` | Alloy/TLA+ 形式化模型文档 | 2 周 |
| `deploy/helm/.../tpm-attestation.yaml` | TPM sidecar 部署配置 | 1 周 |
| `deploy/helm/.../spire/` | SPIFFE/SPIRE 部署配置 | 2 周 |

---

## 五、评估通过标准

| 评估项 | 通过标准 | 验证方法 |
|--------|---------|---------|
| 强制访问控制 | BLP/Biba 正确实施，100+ 测试用例通过 | 单元测试 + 渗透测试 |
| 形式化模型 | Alloy 模型检查 zero counterexample | CI 自动运行 Alloy Analyzer |
| 可信计算 | TPM Quote 验证流程 e2e 通过 | 模拟篡改后证明失败 |
| 硬件鉴别 | 所有服务间通信使用 mTLS + SPIFFE SVID | 网络包抓取验证 |
| 全网加密 | 东西向 + 南北向流量全加密 | tcpdump 验证无明文 |
| 审计四级 | 所有四级新增事件写入审计日志 | audit query 验证 |

---

## 六、时间线

```
v1.1 当前（2026-05-27）
├── Phase 1: MAC + 形式化模型（6 周）→ 2026-07-10
├── Phase 2: 可信计算 + TPM（8 周）  → 2026-09-05
├── Phase 3: HSM 硬件鉴别（6 周）     → 2026-10-17
└── Phase 4: 全网加密 + 渗透测试（4 周） → 2026-11-15

v1.1 GA: 2026-11-15 → 提交第三方等保四级测评
```

---

**文档维护人**: 安全架构师  
**审核日期**: 2026-05-27  
**下次复审**: 每个 Phase 结束时
