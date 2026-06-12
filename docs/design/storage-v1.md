# 存储层 v1 设计文档

> 状态：Approved v1.3
> Owner：平台基础设施
> 实施 milestone：Phase 1–6 全部落地（Phase 1-4 包代码 + Phase 5 dev 栈部署 + Phase 6 Helm bucket bootstrap）
> 相关文档：[audit-v1.md](./audit-v1.md) / [lifecycle-v1.md](./lifecycle-v1.md) / [security-ops-ci-v1.md](./security-ops-ci-v1.md) / [CONVENTIONS.md](../CONVENTIONS.md)

> **关键决策定稿**（2026-06-11）：
> - 租户隔离 = **prefix-per-tenant**（单 bucket + `tenants/{tenant_id}/` 前缀）
> - 推进节奏 = **串行**，Phase 1 → 2 → 3 → 4 全部落地后再上工作区/知识库业务
> - 配额并发安全 = **Postgres 行级原子更新**（`UPDATE ... SET used_bytes = used_bytes + :delta`），不引入 Redis
> - `storage.quota.write` scope 注册 = **Phase 3 时同步**进 `CONVENTIONS.md §4.x` 和 identity 的 `_ALLOWED_SCOPES`
> - 老 `foundation-audit-worm` bucket 6 个月只读窗口 = **Phase 2 上线日为起点**，写进 runbook

---

## 1. 目标与非目标

### 1.1 目标

| 目标 | 说明 |
|---|---|
| 统一抽象层 | 所有服务通过 `packages/storage` 访问对象存储，禁止各服务自建 boto3 client |
| 多 bucket 支持 | 按用途拆分 bucket，每类数据的生命周期和合规要求可独立配置 |
| 租户前缀强制 | key 必须以 `tenants/{tenant_id}/` 开头，由构造器强制，业务方不得绕过 |
| 配额管理 | 按租户 + bucket 用途分别计量，上传前检查，超额拒绝并告警 |
| GC 闭环 | lifecycle 服务软删除触发后，S3 对象最终物理删除，形成完整清理链路 |
| 可观测 | 上传/下载/删除操作产生 OTel span + 结构化日志 + Prometheus 指标 |

### 1.2 非目标

| 非目标 | 说明 |
|---|---|
| 跨区复制 / 多活 | 留 Phase 3+ 或由平台层（MinIO 联邦）处理，本文档不设计 |
| 冷热分层 | S3 lifecycle policy 接口预留，本期不实现自动分层 |
| 向量存储 | 向量进 pgvector 或独立向量库，不归本存储层管理 |
| 块存储 / 文件系统语义 | 只做对象存储（S3 API），不提供 POSIX 接口 |
| 客户端加密（CSE） | 字段级加密由 `packages/crypto` 负责，存储层只做透传 |

---

## 2. Bucket 划分

### 2.1 Bucket 清单

| Bucket 用途 | 默认名（dev） | 读写模式 | Object Lock | 生命周期特征 |
|---|---|---|---|---|
| 审计 WORM | `foundation-audit` | 仅写入，不支持修改/删除 | COMPLIANCE 模式，7 年保留 | 追加密集型；靠 S3 lifecycle policy 到期归档 |
| 工作区文件 | `foundation-workspace` | 读写均衡，预签名 URL 上传 | 关闭 | 用户主动删除 + GC 清理 |
| 知识库原始文档 | `foundation-kb-raw` | 写少读多；文档上传后较稳定 | 关闭 | 与 KB 文档同生命周期 |
| 知识库派生物 | `foundation-kb-derived` | 重写频繁（重建索引时全量覆盖） | 关闭 | 可随时重新生成；GC 主动清理 |

说明：
- audit bucket 继承现有 `foundation-audit-worm` 的 Object Lock 配置，做重命名（见 §7 迁移策略）。
- workspace / kb-raw / kb-derived 三个 bucket 在 Phase 1 完成抽象层后、Phase 2 时随迁移工作一并创建。
- security-ops 的 SARIF/PIR/SBOM 报告归入 `foundation-workspace`（同为结构化文件，无 WORM 需求），具体 key layout 见 §3。

### 2.2 Bucket 命名规范

环境后缀策略：dev 不加后缀，staging 加 `-staging`，prod 加 `-prod`（或由 Helm values 注入）：

```
foundation-audit          # dev
foundation-audit-staging  # staging
foundation-audit-prod     # prod
```

Helm values 示例（`deploy/helm/foundation/values.yaml` 现有 `global.s3` 节将被 `global.storage` 取代，Phase 2 时保留 `global.s3` 做一段时间兼容映射，新代码统一读 `global.storage`）：

```yaml
global:
  storage:
    endpoint: http://foundation-minio:9000
    region: cn-default
    existingSecret: foundation-s3-credentials
    buckets:
      audit:      foundation-audit
      workspace:  foundation-workspace
      kbRaw:      foundation-kb-raw
      kbDerived:  foundation-kb-derived
    presignedUrlTtlSeconds: 3600
```

### 2.3 minio-init job 扩展目标

**现状**：`deploy/docker-compose/dev.yml` 中现有 `minio-init` job 仅创建 `foundation-audit-worm` 一个 bucket（含 Object Lock）。

**扩展目标**（Phase 1 完成）：扩展为创建全部 4 个 bucket：

```yaml
minio-init:
  command:
    - |
      set -e
      mc alias set local http://minio:9000 ${MINIO_ROOT_USER} ${MINIO_ROOT_PASSWORD}
      # audit：Object Lock（COMPLIANCE，7 年）
      mc mb --with-lock --ignore-existing local/foundation-audit
      mc retention set --default COMPLIANCE "7y" local/foundation-audit
      # workspace / kb-raw / kb-derived：普通 bucket
      mc mb --ignore-existing local/foundation-workspace
      mc mb --ignore-existing local/foundation-kb-raw
      mc mb --ignore-existing local/foundation-kb-derived
      echo "=== minio-init: all buckets ready ==="
```

Helm 中对应同款 Job — 见 [`deploy/helm/foundation/templates/minio-init.yaml`](../../deploy/helm/foundation/templates/minio-init.yaml)（Phase 6 落地）：

- `helm.sh/hook: post-install,post-upgrade` + `hook-delete-policy: before-hook-creation,hook-succeeded` —— 每次 `helm install` / `helm upgrade` 都跑一次，老 Pod 自动清理
- 凭据走 `global.storage.existingSecret`（同 audit / security-ops 用的 Secret，key 为 `access-key` / `secret-key`），通过 `MC_HOST_local=http://$(KEY):$(SECRET)@endpoint` 注入避免 argv 泄露
- bucket 名从 `global.storage.buckets.*` 读取，Object Lock retention 从 `global.storage.audit.retentionYears` 读（默认 7）
- `mc mb --ignore-existing` 保证幂等——加新 bucket 只需在模板里 + 一行 `mc mb`，`helm upgrade` 即可，不影响存量
- **large profile**（`minio.enabled=false`）整段不渲染——客户使用外部 S3 / OSS 时由运维按 `values-large.yaml` 注释里的 `aws s3api create-bucket` 步骤手动创建

---

## 3. Key Layout 规范

### 3.1 强制前缀格式

所有对象 key 必须以 `tenants/{tenant_id}/` 开头，后接用途范围（scope）和资源层级：

```
tenants/{tenant_id}/{scope}/{...资源路径...}
```

`{tenant_id}` 使用不含等号的规范前缀（区别于现有 worm.py 中的 `tenant={id}` 格式——迁移时统一切换，见 §7）。

### 3.2 各 Bucket Key Layout

**foundation-audit**

```
tenants/{tenant_id}/events/{yyyy}/{mm}/{dd}/{hh}/{event_id}.json
```

示例：`tenants/tnt_01J5DEVXX00000000000000001/events/2026/06/11/14/evt_01JXYZ.json`

与现有 `worm.py` 的差异：现有 key 为 `tenant={id}/year=YYYY/month=MM/day=DD/hour=HH/{event_id}.json`（Hive 分区风格，已带 hour 段），迁移后改为规范的 `tenants/{id}/events/YYYY/MM/DD/HH/` 风格。**hour 段保留**——避免老数据回溯查询时层级断档，迁移脚本只需做前缀替换（`tenant={id}` → `tenants/{id}`、等号 → 斜杠）。

**foundation-workspace**

```
tenants/{tenant_id}/workspaces/{workspace_id}/files/{file_id}/{filename}
tenants/{tenant_id}/security-ops/{resource_type}/{resource_id}/{filename}
```

`resource_type` 取值：`sarif`、`pir`、`sbom`（对应 security-ops 现有 `*_s3_key` 字段）。

示例：
```
tenants/tnt_01J5.../security-ops/sarif/scn_01J5.../trivy-results.sarif.json
tenants/tnt_01J5.../workspaces/ws_01J5.../files/fil_01J5.../report.pdf
```

**foundation-kb-raw**

```
tenants/{tenant_id}/kb/{kb_id}/docs/{doc_id}/{filename}
```

示例：`tenants/tnt_01J5.../kb/kb_01J5.../docs/doc_01J5.../design.pdf`

**foundation-kb-derived**

```
tenants/{tenant_id}/kb/{kb_id}/chunks/{doc_id}/{chunk_id}.jsonl
tenants/{tenant_id}/kb/{kb_id}/embeddings-cache/{model_id}/{doc_id}.npz
tenants/{tenant_id}/kb/{kb_id}/pipeline-artifacts/{run_id}/{artifact_name}
```

### 3.3 抽象层如何强制 key 前缀

`packages/storage` 中的 `ObjectKey` 构造器是唯一合法的 key 生成入口。业务方**不得**手动拼接字符串传入客户端。

```python
# 伪代码——展示 API 形状，非完整实现
@dataclass(frozen=True)
class ObjectKey:
    tenant_id: str
    bucket_purpose: BucketPurpose  # BucketPurpose.AUDIT / WORKSPACE / KB_RAW / KB_DERIVED
    path_segments: tuple[str, ...]

    def __post_init__(self) -> None:
        if not TENANT_ID_PATTERN.match(self.tenant_id):
            raise KeyValidationError(f"invalid tenant_id: {self.tenant_id!r}")
        for seg in self.path_segments:
            if "/" in seg or seg in (".", ".."):
                raise KeyValidationError(f"invalid path segment: {seg!r}")

    @property
    def key(self) -> str:
        return f"tenants/{self.tenant_id}/" + "/".join(self.path_segments)

    # 工厂方法——按用途提供具名构造
    @classmethod
    def for_audit_event(cls, tenant_id: str, occurred_at: datetime, event_id: str) -> "ObjectKey":
        # 保留 hour 段：与现有 worm.py 层级一致，老数据迁移只需前缀替换
        return cls(tenant_id, BucketPurpose.AUDIT, (
            "events",
            f"{occurred_at.year:04d}", f"{occurred_at.month:02d}",
            f"{occurred_at.day:02d}", f"{occurred_at.hour:02d}",
            f"{event_id}.json",
        ))

    @classmethod
    def for_workspace_file(cls, tenant_id: str, workspace_id: str,
                           file_id: str, filename: str) -> "ObjectKey":
        return cls(tenant_id, BucketPurpose.WORKSPACE, (
            "workspaces", workspace_id, "files", file_id, filename,
        ))
```

### 3.4 跨租户访问禁止机制

- `StorageClient` 在初始化时绑定一个 `TenantContext`（从 `foundation_context` contextvars 读取）。
- 每次调用 `put_object / get_object / ...` 时，强制用 `client._tenant_id` 构造 key，业务方传入的 `ObjectKey` 若 `tenant_id` 不等于 client 绑定的 `tenant_id` 则抛 `KeyValidationError`。
- SYSTEM actor（后台任务）可使用 `StorageClient.as_system()` 绕过租户绑定，但必须显式传 `tenant_id` 参数并在调用链上记录审计。

---

## 4. `packages/storage` 抽象层 API 契约

### 4.1 包结构

```
packages/storage/
├── pyproject.toml                     # 纯库包；no FastAPI；依赖 boto3, pydantic-settings
├── src/foundation_storage/
│   ├── __init__.py                    # 暴露: StorageClient, ObjectKey, BucketPurpose,
│   │                                  #        StorageError, QuotaExceededError,
│   │                                  #        ObjectNotFoundError, KeyValidationError
│   ├── client.py                      # StorageClient 主体
│   ├── keys.py                        # ObjectKey, BucketPurpose
│   ├── config.py                      # StorageSettings (pydantic-settings)
│   ├── errors.py                      # 统一异常类型
│   ├── quota.py                       # 配额检查接口（Phase 3 填充实现）
│   └── observability.py              # OTel span 装饰器
├── tests/
│   ├── unit/
│   └── integration/                   # 用 moto 或 pytest-minio fixture
```

遵循 `docs/CONVENTIONS.md §1.2` 包结构约定。作为纯库（no HTTP server），不含 `api/` 目录。

### 4.2 核心类

**StorageClient 设计选择**

采用**单 client + bucket_purpose 参数**方案，而非为每个 bucket 创建独立 sub-client 类。理由：
- bucket 名通过配置注入，client 不感知实际名称——业务方只知道 `BucketPurpose.AUDIT`；
- 减少类的数量，测试和 mock 成本更低；
- bucket_purpose 在 key 构造时已经确定，client 只是做一次 `purposes_to_bucket[purpose]` 查找。

```python
# 伪代码——展示 API 形状
class StorageClient:
    """S3/MinIO 统一客户端。

    通过 BucketPurpose 枚举寻址 bucket，强制 ObjectKey 校验。
    线程安全：内部 boto3 client 懒初始化并复用。
    异步：所有 IO 操作通过 asyncio.run_in_executor 执行，与 audit worm.py 保持一致。
    """

    def __init__(self, settings: StorageSettings, tenant_id: str | None = None) -> None: ...

    # ── 核心 CRUD ──────────────────────────────────────────────────────
    async def put_object(
        self, key: ObjectKey, body: bytes | BinaryIO,
        content_type: str = "application/octet-stream",
        object_lock_mode: Literal["COMPLIANCE", "GOVERNANCE"] | None = None,
        object_lock_retain_until: datetime | None = None,
        metadata: dict[str, str] | None = None,
    ) -> str: ...  # 返回 s3://{bucket}/{key}

    async def get_object(self, key: ObjectKey) -> bytes: ...

    async def head_object(self, key: ObjectKey) -> ObjectMeta: ...
    # ObjectMeta: content_length, content_type, last_modified, metadata

    async def delete_object(self, key: ObjectKey) -> None: ...
    # audit bucket 的 Object Lock 会在 S3 层物理拦截，异常透传为 StorageError

    async def list_prefix(
        self, tenant_id: str, bucket_purpose: BucketPurpose,
        prefix_segments: tuple[str, ...], max_keys: int = 1000,
        continuation_token: str | None = None,
    ) -> tuple[list[ObjectMeta], str | None]: ...  # (items, next_token)

    # ── 预签名 URL ──────────────────────────────────────────────────────
    async def generate_presigned_url(
        self, key: ObjectKey,
        operation: Literal["put_object", "get_object"],
        expires_in: int | None = None,  # 默认读 settings.presigned_url_ttl_seconds
    ) -> str: ...

    # ── 分片上传 ────────────────────────────────────────────────────────
    async def initiate_multipart(self, key: ObjectKey,
                                  content_type: str = "application/octet-stream") -> str: ...
    # 返回 upload_id
    async def upload_part(self, key: ObjectKey, upload_id: str,
                          part_number: int, body: bytes) -> str: ...  # 返回 ETag
    async def complete_multipart(self, key: ObjectKey, upload_id: str,
                                  parts: list[dict]) -> str: ...  # 返回 s3:// URI
    async def abort_multipart(self, key: ObjectKey, upload_id: str) -> None: ...
```

**TenantContext 来源**

从 `foundation_identity.domain.base.foundation_context`（`ContextVar[FoundationContext | None]`）读取，与其他服务的做法一致（`packages/identity/src/foundation_identity/domain/base.py:34`）。`StorageClient` 工厂函数：

```python
def get_storage_client() -> StorageClient:
    ctx = foundation_context.get()
    tenant_id = ctx.tenant_id if ctx else None
    return StorageClient(get_settings(), tenant_id=tenant_id)
```

### 4.3 配置项

```python
class StorageSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="STORAGE_", ...)

    endpoint: str = "http://127.0.0.1:9001"
    region: str = "cn-default"
    access_key: str = "foundation"
    secret_key: str = "minio_change_me_min_12_chars"

    # bucket 名映射（可被各环境 ENV 覆盖）
    bucket_audit:       str = "foundation-audit"
    bucket_workspace:   str = "foundation-workspace"
    bucket_kb_raw:      str = "foundation-kb-raw"
    bucket_kb_derived:  str = "foundation-kb-derived"

    presigned_url_ttl_seconds: int = 3600
    multipart_threshold_bytes: int = 50 * 1024 * 1024   # 50 MB

    # 配额相关（Phase 3）
    quota_check_enabled: bool = True
    quota_db_dsn: PostgresDsn | None = None  # 若与主 DB 共用，可留空走主 DSN
```

### 4.4 异常模型

```python
class StorageError(Exception):
    """基类；包含 bucket_purpose, key, upstream_error"""

class QuotaExceededError(StorageError):
    """上传前检查超额；HTTP 映射 → 429"""
    tenant_id: str
    bucket_purpose: BucketPurpose
    limit_bytes: int
    used_bytes: int

class ObjectNotFoundError(StorageError):
    """get_object / head_object 时对象不存在；HTTP → 404"""

class KeyValidationError(StorageError):
    """key 前缀违规或 path segment 非法；HTTP → 400"""

class ObjectLockedError(StorageError):
    """尝试删除 WORM 对象；HTTP → 409"""
```

### 4.5 异步策略

与现有 `packages/audit/src/foundation_audit/adapters/worm.py:88-98` 保持一致：使用 `asyncio.run_in_executor(None, lambda: boto_client.xxx(...))` 而非 aioboto3。

理由：
- 现有代码已有 boto3 precedent，避免引入第二种异步 S3 库；
- aioboto3 维护活跃度弱于 boto3；
- run_in_executor 对于存储 IO 足够（线程池阻塞，非 CPU 密集）。

---

## 5. 租户配额数据模型

### 5.1 表定义

表放在 `lifecycle` schema，与 lifecycle service 的 DB migration 合并管理（`packages/lifecycle/migrations/`）：

```sql
CREATE TABLE lifecycle.tenant_storage_quota (
    id              VARCHAR(30) PRIMARY KEY,    -- "sqt_<ULID>" (prefix 4 + ULID 26 = 30，对齐 lifecycle 既有 bin_/crt_/dsj_ 惯例)
    tenant_id       VARCHAR(30) NOT NULL
                    REFERENCES tenant.tenant(id) ON DELETE CASCADE,
    bucket_purpose  VARCHAR(32) NOT NULL,       -- "audit"/"workspace"/"kb_raw"/"kb_derived"
    limit_bytes     BIGINT NOT NULL DEFAULT 10737418240,  -- 10 GB 默认
    used_bytes      BIGINT NOT NULL DEFAULT 0,
    soft_warn_pct   SMALLINT NOT NULL DEFAULT 80,         -- 达到 80% 时告警
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_quota_tenant_purpose UNIQUE (tenant_id, bucket_purpose)
);

CREATE INDEX idx_storage_quota_tenant ON lifecycle.tenant_storage_quota (tenant_id);
```

按 `bucket_purpose` 分行，因为 audit（7 年 WORM）和 workspace（用户文件）的配额业务含义完全不同，额度独立管理。

### 5.2 配额检查时机

```
PUT /workspaces/{id}/files  →  StorageClient.put_object()
                                    │
                                    ▼
                             QuotaChecker.check_before_upload(
                               tenant_id, bucket_purpose, estimated_bytes
                             )
                                    │ 超额
                                    ▼
                             raise QuotaExceededError(...)
                                    │ 未超额
                                    ▼
                             boto3.put_object(...)
                                    │ 成功
                                    ▼
                             QuotaChecker.increment_used(
                               tenant_id, bucket_purpose, actual_bytes
                             )
```

`estimated_bytes` 来自请求 `Content-Length`；实际字节数从 `head_object` 返回的 `content_length` 获得（put 完成后异步更新，避免 pre-flight head 的 race）。

### 5.3 used_bytes 维护策略

推荐**实时累加 + 每日对账校正**：

- **实时累加**：put 成功后 `UPDATE ... SET used_bytes = used_bytes + actual_bytes`；delete 成功后同步扣减。性能好，误差来自失败操作未回滚。
- **每日对账**：定时任务通过 `s3api list-objects-v2` 或 MinIO `mc admin info` 聚合前缀大小，与 DB 值对比；差值超阈值（如 1%）则强制覆写并记审计告警。

对账数据源：MinIO 优先用 `mc du --recursive local/bucket/tenants/{tenant_id}/` 获得精确字节数；AWS S3 用 CloudWatch `BucketSizeBytes` + `s3api list-objects-v2`（后者较慢，建议缓存 24h）。

### 5.4 管理 API

配额查询和调整接口由 `lifecycle-service` 提供（`lifecycle` schema 的 owner），与 lifecycle 现有的 retention override 管理风格一致：

```
GET  /api/lifecycle/v1/storage-quotas?tenant_id=xxx
PATCH /api/lifecycle/v1/storage-quotas/{tenant_id}/{bucket_purpose}
      { "limit_bytes": 53687091200, "soft_warn_pct": 85 }
```

这些 API 属于平台管理员操作，需要 `authz` RBAC 中的 `storage.quota.write` 权限。

---

## 6. GC 与 lifecycle 接通

### 6.1 现状

`packages/lifecycle/src/foundation_lifecycle/services/lifecycle_service.py:119-165` 中的 `hard_delete()` 方法设置 `entry.hard_deleted_at = now`，但没有任何 S3 删除操作。`sweep_expired()` 同理（第 169-209 行）。

### 6.2 改造方案

在 `hard_delete()` 和 `sweep_expired()` 中，通过 `packages/storage` 执行 `delete_object`：

```python
# 伪代码——展示改造后的 hard_delete 关键片段
async def hard_delete(self, session, *, ..., storage_client: StorageClient | None = None):
    ...
    entry.hard_deleted_at = now

    # 新增：删除关联的 S3 对象（如果有）
    if entry.original_location and storage_client:
        await self._delete_s3_objects(entry, storage_client)

    await session.flush()

async def _delete_s3_objects(self, entry: RecycleBin,
                              storage_client: StorageClient) -> None:
    """幂等删除 S3 对象；Object Lock bucket 的错误记录但不阻断。"""
    if not entry.original_location:
        return
    try:
        loc = json.loads(entry.original_location)
        s3_keys = loc.get("s3_keys", [])
        for key_str in s3_keys:
            key = ObjectKey.from_string(key_str)  # 解析已存储的 key
            await storage_client.delete_object(key)
    except ObjectLockedError:
        log.warning("gc.s3.object_locked", bin_id=entry.id)  # audit bucket 正常现象
    except ObjectNotFoundError:
        log.warning("gc.s3.already_deleted", bin_id=entry.id)  # 幂等，可忽略
    except StorageError as exc:
        log.error("gc.s3.delete_failed", bin_id=entry.id, error=str(exc))
        # 不阻断 DB 硬删除；对账任务会发现孤儿对象
```

`original_location` 字段（`lifecycle.recycle_bin` 表已有此列，类型 `Text`，注释为 "JSON: where to find the original data"）存储格式约定（**v1.2 修订：与 Phase 2 security-ops 业务表 `s3_location` 列对齐，存裸 list**）：

```json
[
  "foundation-workspace::tenants/tnt_xxx/workspaces/ws_yyy/files/fil_zzz/report.pdf"
]
```

每个元素格式为 `{bucket_name}::{object_key}`，便于在多 bucket 时明确定位。

**copy 路径（Phase 4 实现）**：

```
security-ops DELETE /scans/{id}
  ↓
读取 ScanRun.s3_location (Phase 2 已存的裸 list)
  ↓
LifecycleService.soft_delete(..., s3_location=parse_json_list)
  ↓
RecycleBin.original_location = json.dumps(s3_location list, ensure_ascii=False)
```

零格式转换——业务表和 recycle_bin 都存裸 list。

**写入方责任**（重要）：现有 `LifecycleService.soft_delete()` 调用方都没传 `original_location`，字段长期为 `NULL`（Phase 2 调研确认：全仓零写入点）。修复分两步：

- **Phase 2**：security-ops 在创建 scan_run / incident / sbom_record / drill 时，如果对应 `*_s3_key` 非空，**立即**在 recycle_bin（或业务表的对应 location 字段，看具体落点）写入 `original_location = {"s3_keys": [<bucket>::<key>]}`。这样 Phase 4 GC 上线时就有数据可清。
- **Phase 2 例外：audit 不补**。audit bucket 是 WORM，永远不被 GC（见 §6.4），写 `original_location` 没有意义，反而增加无用 IO。
- **Phase 4**：改造 `LifecycleService.soft_delete()` 签名，新增可选参数 `s3_location: dict | None = None`，供 workspace / kb 等新业务直接调用：

```python
async def soft_delete(
    self, session, *,
    resource_type: str, resource_id: str,
    tenant_id: str, deleted_by: str,
    s3_location: dict | None = None,  # 新增；调用方传入需 GC 的 S3 key 列表
    ...,
) -> RecycleBin: ...
```

各业务服务（audit / security-ops / workspace / kb）在调用 `soft_delete` 时必须显式传入对应的 `s3_keys`，否则 Phase 4 GC 无法回收对象（会被孤儿对账任务发现）。Phase 4 todo 中包含改造现有 `soft_delete` 调用点的工作项。

### 6.3 孤儿对账任务

扫描两个方向：

**方向 A（DB 无记录但对象存在 → 待清理）**
1. 遍历 bucket 中某租户前缀下的所有对象；
2. 提取 key 中的 `resource_id`；
3. 查询 DB 中对应的 `recycle_bin` / 业务表是否存在；
4. 若不存在且对象创建时间超过宽限期（默认 7 天），标记为 `ORPHAN` 并加入待清理队列。

**方向 B（DB 有记录但对象不存在 → 数据丢失）**
1. 查询 `recycle_bin.hard_deleted_at IS NOT NULL` 且 `original_location` 有 S3 key 的记录；
2. `head_object` 检查对象是否存在；
3. 若早于 `hard_deleted_at` 就消失了（非 GC 删除），打 `storage.object_missing` 告警。

### 6.4 audit WORM bucket 与 GC

`foundation-audit` bucket 的 Object Lock COMPLIANCE 模式**物理拦截**任何删除和修改请求（包括 root 用户）。GC 任务不得尝试删除此 bucket 中的对象。

到期销毁通过 S3/MinIO lifecycle policy 实现：

```json
{
  "Rules": [{
    "ID": "audit-expire-after-7y",
    "Prefix": "tenants/",
    "Status": "Enabled",
    "Expiration": { "Days": 2555 }
  }]
}
```

`packages/storage` 预留 `configure_lifecycle_policy(bucket_purpose, rules)` 接口，本期不实现自动配置，由运维手动在 MinIO Console / AWS Console 设置。

---

## 7. 现有服务迁移策略

### 7.1 audit：worm.py → packages/storage

**改造内容**：`packages/audit/src/foundation_audit/adapters/worm.py` 中的 boto3 client 建立逻辑替换为 `StorageClient`。

key layout 从 `tenant={id}/year=YYYY/...` 迁移到 `tenants/{id}/events/YYYY/MM/DD/`。

bucket 名从 `settings.worm_bucket`（默认 `foundation-audit-worm`）改为读 `StorageSettings.bucket_audit`（默认 `foundation-audit`）。

**老 bucket 处理**：现状显示 `worm.py` **只有写路径，无 read 路径**（worm.py 整个文件只有 `write_worm`），所以"双 bucket fallback 读"在 audit 范围内不存在——只要新写入切到新 bucket、老 bucket 保留只读即可。`foundation-audit-worm` 保留只读 6 个月（Phase 2 上线日起算），到期由运维双人 sign-off 下线。

**灰度方案**：feature flag `storage.worm_via_storage_client`（`default_value=False, fail_open=False`，仿照 `export.allow_l4_download` 模式）控制写入路径——`true` 走 `StorageClient`，`false` 走旧 `worm.py` 直连 boto3。feature-flag 服务已在 `packages/feature-flag` 中实现 Unleash 集成（参见 commit `e119bf2`）。

**老数据迁移**：现有 `foundation-audit-worm` 中 key 格式为 `tenant={id}/year=YYYY/month=MM/day=DD/hour=HH/{event_id}.json`，新 key 格式为 `tenants/{id}/events/YYYY/MM/DD/HH/{event_id}.json`。提供一次性迁移脚本：`mc cp --recursive` + 前缀替换（`tenant={id}` → `tenants/{id}/events`、等号 → 斜杠）。脚本属于运维 SOP，**不在本期代码改造范围**。

### 7.2 security-ops：*_s3_key 字段

**重要现状（Phase 2 调研后修订）**：security-ops 服务**自身不调用 boto3、不写 S3 对象**。`sarif_s3_key` / `pir_s3_key` / `sbom_s3_key` / `drill.pir_s3_key` 这些字段是**由外部调用方（CI 流水线、SDK）在 POST 请求体里作为字符串透传进来**，security-ops 只做存储和返回。真正的 S3 写入发生在 security-ops 进程之外。

**因此 Phase 2 不改 security-ops 内部逻辑**——所谓"切到 `packages/storage`"在 security-ops 包里**无可改之物**。Phase 2 范围内 security-ops 只做两件事：

1. **API 请求体校验**：`POST /scans/runs` 等接收 `*_s3_key` 字段的端点新增校验：字段值必须符合 `{bucket}::{key}` 格式（用 `ObjectKey.from_string` 试解析），其中 `{bucket}` 必须在 `StorageSettings.bucket_to_purpose_map()` 已知列表中。无效请求返回 400 + `FOUNDATION.STORAGE.KEY.INVALID`。
2. **同步补写 `original_location`**：service 层 INSERT scan_run / incident / sbom_record / drill 记录时，如果对应 `*_s3_key` 非空，同步在 `recycle_bin` 或对应业务表里写入 `original_location = {bucket}::{key}` 格式（具体写入位置见 §6.2 GC 铺路），为 Phase 4 GC 准备。

**调用方改造**：外部 CI 脚本 / SDK 需要改造为用 `StorageClient` 生成 key 后再传给 security-ops API。这部分**超出 Phase 2 范围**，由消费方各自负责（属于 SDK 改造工单，独立追踪）。Phase 2 上线后，未升级的调用方会因为 400 校验失败而被发现并推动改造——这就是范围分割点。

**DB migration**：不需要 schema 变更。

**切换时机**：`storage.security_ops_validate_key_format` feature flag（default False / fail_open False）控制是否启用 400 校验；初期可关闭校验只做"格式不符就告警"的观测模式，给调用方留改造窗口期。

### 7.3 migration 要点汇总

| 服务 | DB migration 需要 | 改造范围 | 兼容期 | feature flag |
|---|---|---|---|---|
| audit | 否 | worm.py 写入路径切 StorageClient；hour 段保留；老 bucket 6 月只读 | 6 个月（Phase 2 上线日起算） | `storage.worm_via_storage_client` (default False, fail_open False) |
| security-ops | 否 | API 请求体校验 `*_s3_key` 格式 + 同步补 `original_location`；不动 service 内部 | — | `storage.security_ops_validate_key_format` (default False, fail_open False) |
| workspace（新功能） | 是（新建 resource_type + recycle_bin 字段扩展） | N/A（全新） | — | — |
| kb（新功能） | 是（新建 KB 相关表） | N/A（全新） | — | — |

---

## 8. 落地 Phase 拆分

### Phase 1：`packages/storage` 抽象层

目标：建立标准库，现有服务可选接入。

- [ ] 创建 `packages/storage/` 目录，`pyproject.toml`（Poetry，Python 3.12+）
- [ ] 实现 `StorageSettings`（`config.py`）
- [ ] 实现 `BucketPurpose` 枚举和 `ObjectKey` 构造器（`keys.py`）
- [ ] 实现 `StorageClient`（`client.py`）：`put_object / get_object / head_object / delete_object / list_prefix / generate_presigned_url / initiate_multipart / complete_multipart / abort_multipart`
- [ ] 实现 `StorageError / QuotaExceededError / ObjectNotFoundError / KeyValidationError / ObjectLockedError`（`errors.py`）
- [ ] OTel span 装饰器（`observability.py`）
- [ ] 单元测试（moto mock）+ 集成测试（pytest-minio 或本地 MinIO fixture）
- [ ] 更新 `deploy/docker-compose/dev.yml` 的 `minio-init` job 创建全部 4 个 bucket

**验收标准**：
- `pytest packages/storage --cov=foundation_storage --cov-fail-under=80` 通过
- `mypy --strict packages/storage/src` 零错误
- 集成测试覆盖 put/get/delete/presign/multipart 全路径
- 手动在 dev 栈验证 4 个 bucket 正常创建

### Phase 2：Bucket 拆分 + 存量迁移

目标：audit 和 security-ops 切换到新抽象层，workspace bucket 就绪。

- [ ] 更新 `packages/audit/src/foundation_audit/adapters/worm.py`：写入路径走 `StorageClient`（feature flag 保护）
- [ ] audit bucket 创建（`foundation-audit`）+ 配置 Object Lock + 验证 7 年 COMPLIANCE retention
- [ ] `foundation-audit-worm` 设为只读（去除 write policy）
- [ ] 更新 security-ops 写入路径：`*_s3_key` 新值携带 bucket 标识
- [ ] Helm values 扩展 `global.storage.buckets` 映射，各 profile（small/medium/large）补全
- [ ] `values-large.yaml` 中 `minio.enabled: false` 时，`global.storage.endpoint` 改指外部 S3

**验收标准**：
- dev 栈 audit 事件写入 `foundation-audit` bucket 可在 MinIO Console 验证
- security-ops 扫描结果 SARIF key 格式含 bucket 标识
- audit worm.py 的 feature flag 切换可在不重启的情况下生效
- staging 环境双 bucket fallback 读测试通过

### Phase 3：租户配额

目标：上传前强制配额检查，定期对账。

- [ ] DB migration：`lifecycle` schema 新增 `tenant_storage_quota` 表
- [ ] `packages/storage/src/foundation_storage/quota.py`：`QuotaChecker` 实现
- [ ] `StorageClient.put_object` 调用前执行配额检查（`quota_check_enabled=True` 时）
- [ ] put 成功后异步 increment `used_bytes`
- [ ] lifecycle-service 新增 `/api/lifecycle/v1/storage-quotas` CRUD 端点
- [ ] 每日对账 cron job（复用 lifecycle service 的 APScheduler 调度，见 `lifecycle.config.sweep_enabled`）
- [ ] 对账告警：差值超 1% 时写 audit event + OTel metrics

**验收标准**：
- 超额上传返回 `429 QuotaExceededError`，响应体含 `limit_bytes / used_bytes`
- 单元测试：quota check 调用顺序（先 check 后 put）可通过 mock 验证
- 对账任务可手动触发并在日志中输出差值报告
- 配额调整 API 经 authz 权限检查，未授权返回 403

### Phase 4：GC 接通 + 孤儿对账

目标：lifecycle hard_delete 真正触发 S3 删除，孤儿对象可被发现和清理。

- [ ] `LifecycleService.soft_delete()` 签名新增 `s3_location: dict | None`，并改造所有现有调用点显式传入 S3 key（否则 GC 拿不到 key，本期所有清理失效）
- [ ] `lifecycle_service.hard_delete()` 和 `sweep_expired()` 接入 `StorageClient.delete_object`
- [ ] `recycle_bin.original_location` 约定格式文档化 + 写入工具函数（`parse_s3_location`）
- [ ] 孤儿对账任务（方向 A + 方向 B，见 §6.3）
- [ ] audit WORM bucket 跳过 GC 逻辑（`ObjectLockedError` 静默处理）
- [ ] S3 lifecycle policy 配置脚本（minio-init job 扩展；不自动触发，需运维确认）

**验收标准**：
- hard_delete 调用后，对应 `foundation-workspace` 中对象不再存在（集成测试验证）
- 孤儿对账任务扫描输出：孤儿对象数量、数据丢失告警数量（可观测）
- audit bucket 中的对象在 hard_delete 时不被删除（Object Lock 拦截，测试验证异常处理路径）
- `DestructionJob.resources_destroyed` 计数与实际 S3 删除数一致

---

## 9. 风险与回滚

### 9.1 老数据迁移失败

风险：audit key layout 切换期间，新旧格式共存，查询逻辑若未兼容会丢失历史数据。

缓解：双 bucket fallback（`storage.audit_bucket_migration_complete` flag 默认 `false`）；老 bucket 保留只读 6 个月；只有经过数据完整性验证并手动翻转 flag 后才切断 fallback。

回滚：翻转 feature flag 到 `false`，立即回到旧写路径，零停机。

### 9.2 配额 used_bytes 漂移

风险：失败的 put（网络中断、客户端取消）未能回滚 `used_bytes`，累积正向漂移；失败的 delete 导致 `used_bytes` 未减，积累负向漂移。

缓解：每日对账任务强制校正（§5.3）；对账差值告警让漂移可见；软上限（`soft_warn_pct=80%`）给运维提前介入的窗口。

### 9.3 Bucket Rename 风险

`foundation-audit-worm` → `foundation-audit` 是实质上的新建，因为 S3/MinIO 不支持 bucket 重命名。

策略：
1. 新建 `foundation-audit` bucket（含 Object Lock 配置）；
2. 双写期（新审计事件写新 bucket，老事件留老 bucket）；
3. 6 个月内老 bucket 只读；
4. 6 个月后如业务确认无回溯需求，由运维手动下线老 bucket（不可逆，需两人 sign-off）。

### 9.4 MinIO → AWS S3 切换时的差异点

| 差异点 | MinIO 行为 | AWS S3 行为 | 影响 |
|---|---|---|---|
| Object Lock COMPLIANCE 删除 | root 用户无法删除（MinIO 严格） | 任何用户含 root 均不可删除 | 一致，无影响 |
| Lifecycle policy 语法 | 基本兼容 S3 XML 格式 | 标准 S3 | 切换时需测试 lifecycle policy 应用结果 |
| `s3v4` 签名 | 完全支持 | 支持 | 无影响 |
| `endpoint_url` 参数 | 需要显式传入 | 不传（`None`）走 AWS 域名 | `StorageSettings.endpoint` 为空时去掉 `endpoint_url` 参数 |
| 预签名 URL 有效期上限 | 无硬上限 | PUT 最长 7 天，GET 最长 7 天 | `presigned_url_ttl_seconds` 默认 3600，不受影响 |
| 分片上传 part size | 最小 5 MB | 最小 5 MB，最后一 part 可更小 | 兼容，无影响 |

切换步骤：将 `StorageSettings.endpoint` 置空，`access_key / secret_key` 换为 IAM 凭证（或走 EC2 instance profile），bucket 名按实际 S3 bucket 名覆盖 ENV。

---

## 10. 待定问题与已决议事项

### 10.1 本次定稿已决议（不再待定）

| 事项 | 决议 | 落地位置 |
|---|---|---|
| Phase 3 ID 前缀 | `sqt_` 三字母+下划线（对齐 lifecycle 既有 `bin_`/`crt_`/`dsj_` 惯例），不是初稿的 `tsq_` | Phase 3 migration |
| Phase 3 scope 校验入口 | lifecycle 服务现状零 scope 校验，Phase 3 自建 `require_scope(scope)` Depends，不套用既有 | Phase 3 `api/dependencies.py` |
| Phase 4 sec-ops 删除路径 | 同步加 `DELETE /scans/{id}` / `DELETE /incidents/{id}` / `DELETE /drills/{id}`，调 `soft_delete` 并从业务表 `s3_location` 列读取传入 | Phase 4 |
| Phase 4 `original_location` 格式 | 与 sec-ops 业务表 `s3_location` 列对齐，存裸 list `["bucket::key", ...]`，不包 dict 外壳 | Phase 4 |
| Phase 4 `list_prefix` 分页 | 给 `StorageClient.list_prefix` 加 `continuation_token` 参数和返回值，向后兼容 | Phase 4 |
| Phase 4 audit bucket 孤儿对账 | 本期跳过（audit 写 ClickHouse `worm_uri` 不写 lifecycle，跨存储扫描成本高）；§6.4 已说 audit 不接 GC | Phase 4 |
| 配额 `used_bytes` 并发安全 | Postgres 行级原子更新（`UPDATE ... SET used_bytes = used_bytes + :delta`），不引入 Redis 或显式行锁 | Phase 3 `quota.py` |
| Phase 6 Helm bucket bootstrap | small/medium profile 走 `minio-init.yaml` post-install/post-upgrade Job 自动创建 4 bucket（含 audit Object Lock）；large profile 不渲染 Job，由运维按 `values-large.yaml` 注释手动 `aws s3api create-bucket` | Phase 6 |
| `storage.quota.write` scope 注册时机 | Phase 3 实现配额 API 时一并注册到 `CONVENTIONS.md §4.x` 和 identity `_ALLOWED_SCOPES`，不提前占位 | Phase 3 验收标准 |
| `foundation-audit-worm` 只读窗口起点 | Phase 2 上线日为起点计 6 个月，写进 `docs/design/storage-migration-v1.md`；过渡期残留写入由 feature flag 兜底，忽略不计 | Phase 2 migration 文档 |
| audit key 层级 | 保留 hour 段（`tenants/{tid}/events/YYYY/MM/DD/HH/{event_id}.json`），与现有 worm.py 5 层一致，老数据迁移只做前缀替换 | Phase 2 `ObjectKey.for_audit_event` |
| security-ops 改造范围 | security-ops 不调 boto3、不写 S3——只在 API 请求体校验 `*_s3_key` 格式 + 同步补 `original_location`；调用方（CI/SDK）改造超出本期范围 | Phase 2 §7.2 |
| Helm `global.s3` → `global.storage` | values.yaml 新增 `global.storage` 节并由 services-renderer 真正注入 audit 服务 ENV；老 `global.s3` 节暂留兼容；values-large.yaml 补外接 S3 示例 | Phase 2 Helm 改造工作项 |
| audit `original_location` 写入 | **不写**——audit 是 WORM 不被 GC。security-ops 在创建对象时立即补写 `original_location`，为 Phase 4 GC 铺路 | Phase 2 §6.2 |

### 10.2 真待定（需后续专项讨论）

1. **S3 lifecycle policy 自动配置**：本期由运维手动设置，后续是否通过 minio-init job 或 Terraform 自动化？何时实施？

2. **冷热分层时机**：audit bucket 和 kb-derived bucket 的访问频次随时间衰减，何时引入 S3 Glacier 或 MinIO ILM tiering？触发条件（时间？对象大小？）待定。

3. **跨区复制策略**：large profile 部署在多 AZ 时，`foundation-audit` 和 `foundation-workspace` 是否需要跨区同步？MinIO site replication vs AWS S3 Cross-Region Replication 的选型待定。

4. **向量库选型**：`foundation-kb-derived` 不放向量本身，但 chunk embedding 存储（pgvector vs 独立向量库）是知识库子项目的核心决策，影响 `kb-derived` bucket 的实际使用量，需知识库团队明确。

5. **预签名 URL 滥用防护**：预签名 URL 一经生成即可公开访问，无法在发出后撤销（除非 bucket policy 辅助）。是否需要记录生成日志 + 访问审计？建议 Phase 3 时评估。

---

## 附录 A：与现有代码对应关系

| 本文档引用位置 | 代码文件 | 行号/说明 |
|---|---|---|
> 行号为 2026-06-11 定稿时的位置，仅供查找参考；以代码为准，编辑器搜符号名更可靠。

| 本文档引用位置 | 代码文件 | 位置/说明 |
|---|---|---|
| 现有 boto3 client 建立 | `packages/audit/src/foundation_audit/adapters/worm.py` | 第 68-74 行附近 |
| `asyncio.run_in_executor` 模式 | 同上 | 第 89-99 行附近 |
| `FoundationContext` 定义 | `packages/identity/src/foundation_identity/domain/base.py` | 第 16-36 行附近 |
| `foundation_context` ContextVar | 同上 | 第 34 行附近 |
| lifecycle `hard_delete` 改造点 | `packages/lifecycle/src/foundation_lifecycle/services/lifecycle_service.py` | 第 119-165 行附近 |
| lifecycle `sweep_expired` 改造点 | 同上 | 第 169-209 行附近 |
| lifecycle `soft_delete` 签名 | 同上 | 第 85-93 行附近（需新增 `s3_location` 参数） |
| `recycle_bin.original_location` 字段 | `packages/lifecycle/src/foundation_lifecycle/domain/models.py` | 第 94 行附近 |
| `sarif_s3_key` 字段 | `packages/security-ops/src/foundation_security_ops/domain/models.py` | 第 57 行附近 |
| `pir_s3_key` / `sbom_s3_key` | 同上 | 第 131、156 行附近 |
| `drill.pir_s3_key` | 同上 | 第 222 行附近 |
| `settings.worm_bucket` 配置项 | `packages/audit/src/foundation_audit/config.py` | 第 81 行附近，默认值 `foundation-audit-worm` |
| minio-init 现有 job（仅创建 `foundation-audit-worm`） | `deploy/docker-compose/dev.yml` | 第 263-280 行附近，Phase 1 需扩展为 4 bucket |
| MinIO Helm values（medium） | `deploy/helm/foundation/values-medium.yaml` | 第 111-116 行附近 |
| MinIO Helm values（large 关闭） | `deploy/helm/foundation/values-large.yaml` | 第 51-52 行附近 |
| 现有 `global.s3` Helm 节（待替换为 `global.storage`） | `deploy/helm/foundation/values.yaml` | 第 120-124 行附近 |
| scope catalogue | `docs/CONVENTIONS.md` | §4.x（第 226 行附近的 "Scope catalogue"） |

---

*变更记录*

| 日期 | 版本 | 变更 |
|---|---|---|
| 2026-06-11 | 0.1.0 | 初版（存储层 v1 设计文档） |
| 2026-06-11 | 1.0.0 | 定稿：5 项决策落定（隔离/节奏/并发/scope/只读窗口）；修正 minio-init 现状描述与 `global.storage`/`global.s3` 引用；id 字段 VARCHAR(30) 对齐项目惯例；明确 `soft_delete` 需新增 `s3_location` 参数（否则 GC 无效）；附录 A 改为容忍行号漂移的措辞 |
| 2026-06-11 | 1.1.0 | Phase 2 调研期修订：audit key 保留 hour 段（5 层）；security-ops 范围澄清（不写 S3，只校验请求体 + 补 `original_location`）；audit feature flag 改名 `storage.worm_via_storage_client`；Helm `global.s3` 是孤儿节，Phase 2 同步改造 services-renderer 真正注入 ENV；audit WORM 不写 `original_location` |
| 2026-06-12 | 1.2.0 | Phase 3/4 调研期修订：(1) Phase 3 ID 前缀改 `sqt_` 对齐 lifecycle 既有 `bin_/crt_/dsj_` 惯例；(2) Phase 3 自建 `require_scope` Depends（lifecycle 现状零 scope 校验）；(3) Phase 4 同步加 security-ops DELETE 端点 + soft_delete 调用（不然 GC 无对象可清）；(4) `original_location` 改存裸 list `["bucket::key"]` 对齐业务表 `s3_location`；(5) Phase 4 给 `list_prefix` 加分页参数；(6) Phase 4 跳过 audit bucket 孤儿对账 |
| 2026-06-12 | 1.3.0 | Phase 6 落地：Helm `templates/minio-init.yaml` 以 post-install/post-upgrade Hook 自动创建 4 bucket（含 audit Object Lock COMPLIANCE retention），small/medium 走内嵌 MinIO，large profile 不渲染 Job；values.yaml 新增 `global.storage.initImage` 和 `global.storage.audit.retentionYears`；values-large.yaml 加 `aws s3api create-bucket` 步骤说明 |
