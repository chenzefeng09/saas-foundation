# 渗透测试范围文档 v1

> 版本：v1.0 | 日期：2026-05-27 | 密级：L4 机密

## 1. 测试目标

对 `saas-foundation` 底座 v1.0 进行外部渗透测试，验证：
1. 多租户隔离边界不可逾越
2. 认证与授权不可绕过
3. 加密与密钥管理的正确性
4. 审计日志的完整性与不可篡改性
5. API 层面的 OWASP Top 10 覆盖

## 2. 测试范围

### 2.1 在范围内（In-Scope）

| 组件 | 端口 | 测试重点 |
|---|---|---|
| identity-service | 8001 | OIDC 流程注入、token 伪造、密码策略绕过、MFA 绕过 |
| authz-service | 8002 | RBAC 越权、OPA 策略注入、permission 伪造 |
| org-service | 8003 | org tree 遍历越权、跨租户成员查看 |
| crypto-service | 8004 | 密钥泄露、envelope 篡改、签名绕过、Argon2id 弱参数 |
| audit-service | 8005 | 审计日志篡改、hash chain 断裂、WORM 绕过 |
| lifecycle-service | 8006 | Legal Hold 绕过、销毁证明伪造、回收站越权恢复 |
| dlp-service | 8007 | 敏感度降级、下载拦截绕过、扫描规则注入 |
| Keycloak | 8080 | 默认凭据、realm 配置错误、token 泄露 |
| Postgres (PgBouncer) | 6432 | SQL 注入、RLS 绕过、直接连接越权 |
| Vault | 8200 | token 泄露、transit key 未授权访问 |

### 2.2 不在范围内（Out-of-Scope）

- DDoS 攻击（客户 WAF 层防护）
- 社会工程学攻击
- 物理安全（客户机房）
- 第三方 SaaS 服务（Stripe、阿里云 KMS 等）
- 前端 XSS/CSRF（B 阶段业务层负责）

## 3. 测试方法

### 3.1 自动化扫描

| 工具 | 用途 | 频率 |
|---|---|---|
| OWASP ZAP | DAST 全扫描（API spider + active scan） | 每次发版 |
| Semgrep | SAST 源码扫描（自定义规则） | 每次 PR |
| gitleaks | Secret 扫描 | 每次 commit |
| Trivy | 容器镜像 CVE 扫描 | 每次构建 |
| Semgrep OWASP | OWASP Top 10 规则 | 每次 PR |

### 3.2 手工测试场景

#### S1. 多租户隔离突破（Critical）
```
Scenario: 租户 A 的用户尝试访问租户 B 的数据
  - 篡改 X-Tenant-Id header
  - 绕过 SDK 直接调 API 并注入其他 tenant_id
  - 通过 API Key 跨租户访问
  - SQL 注入修改 tenant_id 列

Expected: 所有跨租户访问返回 403/404，审计记录 DENIED
```

#### S2. 认证绕过（Critical）
```
Scenario: 未认证用户访问受保护端点
  - 无 Authorization header
  - 过期/伪造 JWT
  - 吊销后的 token 重用
  - 不同 realm 的 token 跨 realm 使用

Expected: 401 Unauthorized
```

#### S3. 权限提升（High）
```
Scenario: 普通用户执行管理员操作
  - L2 clearance 用户访问 L4 资源
  - 普通用户创建/销毁 KEK
  - 绕过 PAM 4-eyes 审批
  - JIT 提权超时后仍保留权限

Expected: 403 Forbidden + audit DENIED
```

#### S4. 密钥管理攻击（Critical）
```
Scenario: 尝试获取 KEK 明文
  - /envelope:encrypt 回显中包含 DEK plaintext
  - 内存 dump 获取密钥材料
  - Vault token 泄露后直接调 transit
  - KEK 销毁后仍可解密旧 ciphertext（应通过 min_decryption_version 阻止）

Expected: 密钥材料不出 crypto-service 进程
```

#### S5. 审计日志完整性（High）
```
Scenario: 篡改审计日志
  - 直接 INSERT/UPDATE/DELETE audit.events
  - 伪造 hash chain 使其验证通过
  - 删除 WORM 存储的 audit 文件
  - 在 legal_hold 资源上执行删除

Expected: hash chain 验证可检测篡改；WORM 不可删除；Legal Hold 阻止删除
```

#### S6. 注入攻击（Medium）
```
Scenario: OWASP Top 10 注入
  - SQL 注入：Postgres RLS 参数注入
  - NoSQL 注入：ClickHouse 查询注入
  - 命令注入：shell 参数注入点
  - 模板注入：Jinja2 template injection（notification）
  - ReDoS：DLP regex pattern DoS

Expected: 输入校验拒绝恶意 payload；WAF 规则匹配
```

## 4. 风险等级定义

| 等级 | 定义 | 修复 SLA |
|---|---|---|
| Critical | 可导致多租户数据泄露或系统完全失陷 | ≤24h |
| High | 可导致单租户数据泄露或权限提升 | ≤7d |
| Medium | 信息泄露或低风险漏洞 | ≤30d |
| Low | 最佳实践偏离，无直接影响 | ≤60d |

## 5. 测试环境

| 环境 | 用途 |
|---|---|
| staging | 预发环境，与生产架构一致但数据为合成数据 |
| CI | 每次 PR 自动跑 ZAP baseline scan + Semgrep + gitleaks |

## 6. 报告要求

- 摘要（Executive Summary）
- 漏洞清单（按 Critical → Low 排序，含 CVSS 评分）
- 每漏洞：复现步骤 + 影响分析 + 修复建议 + 修复后验证
- 附录：工具扫描原始输出、手工测试截图/录屏

## 7. 合规联动

- 等保测评机构预审：渗透测试报告作为安全计算环境控制项的证据
- SOC 2 Type II：年度渗透测试作为 Security CC 证据
- ISO 27001：渗透测试作为 A.12.6.1 技术脆弱性管理证据
