# Storage v1 — Phase 2 迁移 Runbook

> 配套设计文档：[`storage-v1.md`](./storage-v1.md) v1.1
> 适用阶段：Phase 2（audit worm → StorageClient，security-ops 校验请求体）
> 适用对象：SRE / Release engineer / 安全合规组

---

## 1. 概览

Phase 2 完成两件事，都在 feature flag 后面灰度：

| flag                                            | default | 控制范围                                                      |
|-------------------------------------------------|---------|---------------------------------------------------------------|
| `storage.worm_via_storage_client`               | OFF     | audit `write_worm()` 是否走 `packages/storage.StorageClient`  |
| `storage.security_ops_validate_key_format`      | OFF     | security-ops 服务层 `*_s3_key` 请求体格式是否硬阻断（否则只 warn）|

两个 flag 都 `fail_open=False`：lookup 失败/异常一律视为 OFF，**绝不**默默打开。

迁移目标（Phase 2 完成后状态）：
- audit 关键事件 (severity ∈ {SECURITY, CRITICAL}) 走新 bucket `foundation-audit`
  （key 形如 `tenants/{tid}/events/YYYY/MM/DD/HH/{event_id}.json`）
- 老 bucket `foundation-audit-worm` 进入只读窗口（默认 6 个月）
- security-ops 三类 `*_s3_key` 字段（sarif / pir-incident / pir-drill）请求体
  在落库前先过 `ObjectKey.from_string` 校验，并把原值写到业务表新列 `s3_location`

Phase 2 **不**触及：lifecycle GC、配额、workspace/KB bucket 写入路径。

---

## 2. 灰度时间线

```
T0 (Phase 2 prod 上线日)
  └── 部署：worm.py 已带新分支，但 flag=OFF；老路径继续工作
T0 + 1 周
  └── staging 把 storage.worm_via_storage_client 翻 ON，观察 7 天指标
T0 + 2 周
  └── prod 翻 ON（先 1 个非生产租户 → 全租户）
T0 + 3 周
  └── staging 把 storage.security_ops_validate_key_format 翻 ON
       同时通知所有 *_s3_key 调用方（CI/SDK）切到 storage-v1 §3.2 格式
T0 + 4-6 周
  └── prod 翻 ON
T0 + 6 个月
  └── 老 bucket foundation-audit-worm 只读窗口到期 → 走两人 sign-off 下线
```

---

## 3. 老 bucket `foundation-audit-worm` 只读窗口 SOP

### 3.1 进入只读窗口（T0 那天）

`foundation-audit-worm` bucket 已有 7 年的 Object Lock 保留期，**对象本身不可改不可删**。
但需要把 bucket policy 收紧为「只允许 GET，禁止 PUT」，避免任何残留代码在 flag 翻 ON 后
仍试图写入老 bucket。

MinIO 操作（在管理节点执行）：

```bash
# 1) 列一下当前 policy 备份
mc alias set foundation https://minio.internal.example.com $MINIO_ROOT_USER $MINIO_ROOT_PASSWORD
mc admin policy info foundation foundation-audit-worm-rw > /tmp/audit-worm-rw.policy.json

# 2) 设为下载（只读）
mc anonymous set download foundation/foundation-audit-worm
# 或针对 IAM 用户改 policy：
mc admin policy create foundation audit-worm-readonly /opt/policies/audit-worm-readonly.json
mc admin policy attach foundation audit-worm-readonly --user foundation-audit-service
mc admin policy detach foundation audit-worm-rw --user foundation-audit-service
```

`audit-worm-readonly.json` 推荐内容：

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket", "s3:GetObjectRetention", "s3:GetObjectLegalHold"],
      "Resource": [
        "arn:aws:s3:::foundation-audit-worm",
        "arn:aws:s3:::foundation-audit-worm/*"
      ]
    },
    {
      "Effect": "Deny",
      "Action": ["s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion"],
      "Resource": "arn:aws:s3:::foundation-audit-worm/*"
    }
  ]
}
```

### 3.2 在窗口期内（T0 + 1 周 ~ T0 + 6 个月）

- 老 bucket 的对象仍受 Object Lock 保护，**任何**审计回溯、合规审计、监管检查都能正常读
- Prometheus 监控两个关键指标：
  - `storage_audit_legacy_bucket_reads_total{bucket="foundation-audit-worm"}`：应稳步下降
  - `storage_audit_legacy_bucket_writes_total{bucket="foundation-audit-worm"}`：必须保持为 0
- 月度合规审计前不下线
- 老 bucket 的 7 年 Object Lock 保留期**不受**只读策略影响——这是底层 Object Lock 协议层面的不可变性

### 3.3 下线（T0 + 6 个月 + 月度审计周期后）

下线 = 把 bucket 完全归档/删除，需**两人 sign-off**：

| 角色       | 检查项                                                              |
|------------|---------------------------------------------------------------------|
| SRE 主备   | `storage_audit_legacy_bucket_reads_total` 连续 30 天 = 0          |
| 安全合规组 | 当前不存在 legal hold；最近一次审计报告确认老数据已迁移完整且可查 |
| 法务（可选）| 确认无在进行的诉讼/监管调查要保留这些数据                          |

下线时执行：

```bash
# 1) 列对象数和总容量备查
mc du foundation/foundation-audit-worm > /tmp/audit-worm-final-size.txt
mc ls --recursive foundation/foundation-audit-worm | wc -l

# 2) 把整桶导出为冷归档（如果合规要求保留 N 年只读副本，否则跳过）
mc mirror foundation/foundation-audit-worm s3://acme-corp-cold-archive/foundation-audit-worm/

# 3) 移除 Object Lock 保留（如果 mode=COMPLIANCE 则不能移除，只能等 retention 自然到期；
#    这种情况下下线 = 把 bucket policy 设为 deny-all，等 retention 期满 7 年后由 lifecycle rule 清理）
# 4) 删除 bucket（仅当 retention 已全部到期）
mc rb foundation/foundation-audit-worm --force
```

> ⚠️ COMPLIANCE 模式的 Object Lock **不能**被任何 IAM 用户提前解锁，包括 root。
> 实际下线流程是 7 年后由 MinIO/S3 自然清理；本 runbook 只负责把 bucket 标记为
> 「不再被任何活代码读写」+ 在审计台账上画句号。

---

## 4. 老数据迁移脚本骨架（伪代码）

如果合规要求**新老数据共用一个 bucket**（少见，但部分客户合规可能要求），需要把
`foundation-audit-worm` 的对象 copy 到 `foundation-audit` 并 rewrite key。

```bash
#!/bin/bash
# scripts/migrate-audit-worm.sh — Phase 2 数据迁移（可选）
# Usage: ./migrate-audit-worm.sh <tenant_id>
set -euo pipefail

TENANT_ID="${1:?tenant_id required}"
SRC_BUCKET="foundation-audit-worm"
DST_BUCKET="foundation-audit"

# Hive 风格 → storage-v1 §3 规范：
#   tenant={tid}/year=YYYY/month=MM/day=DD/hour=HH/{evt}.json
# → tenants/{tid}/events/YYYY/MM/DD/HH/{evt}.json
mc ls --recursive "foundation/${SRC_BUCKET}/tenant=${TENANT_ID}/" | while read -r line; do
  # 解析旧 key
  old_key=$(echo "$line" | awk '{print $6}')
  # 替换前缀
  new_key=$(echo "$old_key" | sed \
    -e "s|^tenant=${TENANT_ID}/|tenants/${TENANT_ID}/events/|" \
    -e 's|/year=\([0-9]*\)/month=\([0-9]*\)/day=\([0-9]*\)/hour=\([0-9]*\)/|/\1/\2/\3/\4/|')

  # 复制 + 保留 Object Lock 元数据
  mc cp --preserve \
    "foundation/${SRC_BUCKET}/${old_key}" \
    "foundation/${DST_BUCKET}/${new_key}"
done
```

> 一般做法是**不迁移老数据**：老 bucket 自然到期后清理，新 bucket 只装新写入。
> 上面脚本仅供合规强制要求时参考；任何运行前都要先 dry-run（`mc cp --dry-run`）。

---

## 5. 回滚

### 5.1 audit worm（flag flip）

发现新路径有问题时：

```bash
curl -X POST \
  -H "Authorization: Bearer $UNLEASH_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  https://unleash.internal.example.com/api/admin/features/storage.worm_via_storage_client/off
```

flag 翻 OFF 后，下一次 `write_worm()` 调用立即回到老 boto3 路径，写老 bucket。
**不**需要重启 audit 服务（FeatureFlagService 每次调用都查 gateway，gateway 有
~30s 缓存）。

如果同时需要恢复老 bucket 的写入：

```bash
mc admin policy attach foundation foundation-audit-worm-rw --user foundation-audit-service
mc admin policy detach foundation audit-worm-readonly --user foundation-audit-service
```

### 5.2 security-ops 校验（flag flip）

```bash
curl -X POST \
  -H "Authorization: Bearer $UNLEASH_ADMIN_TOKEN" \
  https://unleash.internal.example.com/api/admin/features/storage.security_ops_validate_key_format/off
```

flag OFF 后，drift 仅 log.warning 不阻断；已经写到业务表的 `s3_location` 数据**不**回滚。

---

## 6. 观测与告警

### 6.1 Prometheus 指标

| 指标                                                                      | 含义                                          | Alert 阈值                  |
|---------------------------------------------------------------------------|-----------------------------------------------|-----------------------------|
| `storage_audit_legacy_bucket_writes_total`                                | 老 bucket 写入数；T0+2 周后应为 0             | rate > 0 持续 5min          |
| `storage_audit_storage_client_writes_total{status="success"}`             | 新路径成功写入数                              | n/a                         |
| `storage_audit_storage_client_writes_total{status="failed"}`              | 新路径写入失败数                              | rate > 1/min 持续 10min     |
| `storage_audit_storage_client_writes_total{status="lock_error"}`          | put_object 收到 ObjectLockedError              | rate > 0 持续 1min          |
| `feature_flag_lookup_failures_total{flag="storage.worm_via_storage_client"}` | flag 查询异常次数（fail_open=False → 视为 OFF）| rate > 5/min                |
| `security_ops_s3_key_format_drift_total`                                  | 收到非 storage-v1 格式 key 的次数             | rate > 10/min（告警，flag ON 后应趋零） |
| `security_ops_s3_key_validation_blocked_total`                            | flag ON 期间被 422 拒绝的请求数               | rate > 0 时通知调用方            |

### 6.2 关键日志事件

- `worm.written route=storage_client`：新路径成功
- `worm.written route=legacy`：老路径成功
- `worm.storage_client.put_failed`：新路径异常（看 error 字段定位）
- `worm.storage_client.key_invalid`：tenant_id/event_id 不合规
- `security_ops.s3_key.format_drift`：security-ops 收到坏 key（flag OFF 时）

---

## 7. FAQ

**Q1：为什么不在 Phase 2 直接双写老 bucket + 新 bucket？**

A：双写复杂度高（事务边界、对账、双倍 cost），并且 audit 是 WORM——一旦写错
就 7 年改不掉。设计上 audit 不像普通业务数据有"重新刷一遍"的余地，所以选了
更保守的 flag 灰度 + 老路径整段保留，回滚仅需 flag flip。

**Q2：老 bucket 的数据怎么办？要不要迁过来？**

A：默认**不迁移**。`foundation-audit-worm` 进只读窗口，老数据在 retention 期内
仍可查（GET 不受影响）；查询代码（如 SIEM 集成）需感知两个 bucket。Phase 4+ 会
提供统一查询入口跨 bucket 聚合。强合规客户需要迁移，用 §4 的脚本骨架。

**Q3：security-ops `*_s3_key` 调用方（CI pipeline / SDK）不改造怎么办？**

A：默认 flag OFF，service 只 log.warning 不阻断，所以**不改造也能继续工作**。
但 `security_ops_s3_key_format_drift_total` 会一直冒；运维需通过该指标推动调用方
迁移，再翻 ON。最差情况下 flag 永远 OFF，安全损失是后续 GC 阶段无法精准定位
S3 对象，需要回扫 bucket。

**Q4：Phase 2 加的 `s3_location` 列里存的是什么？**

A：JSON 字符串数组，元素是调用方原始传入的 `*_s3_key`。比如：
`'["foundation-workspace::tenants/tnt_X/security-ops/scan/scan_Y/sarif.json"]'`。
Phase 4 GC 在 soft-delete 时读这一列、写入 `lifecycle.recycle_bin.original_location`，
hard-delete 时再据此 `delete_object`。如果调用方传的不是规范格式（flag OFF 时），
`s3_location` 里就是 raw 字符串——GC 阶段需要兜底处理。

**Q5：StorageClient 的 `as_system()` 会不会破坏租户隔离？**

A：`as_system` 仅用于受信背景任务（audit worker、lifecycle GC、admin 工具），
请求处理路径**必须**显式传 `tenant_id`。audit worker 是 SYSTEM actor，写跨租户
事件本身就是设计意图（合规审计要看所有租户活动），不算破口。

**Q6：feature flag 服务挂掉的话会怎样？**

A：两个 flag 都 `fail_open=False`，所以 FeatureFlagService 异常时一律返回 OFF：
- audit worm：回到老 boto3 路径写老 bucket，**写入不丢**
- security-ops：跳过校验、不写 warning（只 log lookup failed），**请求不阻断**

最差影响是观测信号短暂丢失，业务连续性不受影响。

**Q7：Phase 4 GC 来了之后这个 runbook 还有效吗？**

A：§3（老 bucket 只读窗口 SOP）和 §5（回滚）持续有效。§4（数据迁移脚本）
Phase 4 后基本无意义（GC 会按 `s3_location` 精准清理新 bucket，老 bucket 自然
到期）。§6 告警阈值在 Phase 4 上线时需要重新校准（届时 GC 会主动 `delete_object`，
`storage_audit_storage_client_writes_total{status="lock_error"}` 可能短期升高
属于正常）。

**Q8：如果 audit 服务实例数很大、feature flag 缓存导致部分实例 flag ON、
部分实例 flag OFF 怎么办？**

A：会发生，且**可接受**。同一个事件不会被同一 worker 处理两次，所以不会双写。
不同 worker 看 flag 状态短暂不一致，结果是同一时间段内既有事件写到新 bucket、
也有事件写到老 bucket——后续查询代码需感知两边。缓存收敛时间预计 < 1 分钟
（取决于 Unleash gateway 的 fetch_interval）。
