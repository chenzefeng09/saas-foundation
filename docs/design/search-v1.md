# Search 详细设计 v1

> 跨资源类型的统一搜索：OpenSearch（自托管，避免 ES 商业许可争议）+ 强制 ACL filter 注入（防越权）+ 多租户索引隔离。

| 字段 | 值 |
|---|---|
| 状态 | Draft v1 |
| Owner | Foundation 后端 |
| 实施 milestone | A-M3 |
| 相关文档 | authz / multi-tenancy / dlp-classification / audit |

## 0. TL;DR

- **物理隔离**：每租户 1 个 index alias，背后挂 1-N 个物理 index（按数据量自动 rollover）
- **ACL filter 强制注入**：所有查询经 SDK 必加 `tenant_id` + `sensitivity ≤ user.clearance` + `id ∈ list_accessible_ids(user, resource_type)`
- **索引 pipeline**：业务层 `index(resource)` → SDK 自动补字段 → 写入；删除 / 更新同理
- **搜索能力**：full-text（中英分词）+ keyword filter + facet aggregation + 高亮 + 拼写纠错
- **零越权保证**：双层校验 — SDK 注入 + OpenSearch index template 强制 mandatory filter（搜不到就是搜不到）

## 1. Context

- 业务需求：跨资源搜索（如「客户名 Alice 的所有文档、会话、订单」）
- 合规需求：**搜索结果不能越权**（搜索 = 隐式读取）；DLP sensitivity 必须过滤
- 历史教训：很多 SaaS 数据泄露源于「搜索界面没做权限过滤」，前端可见 ≠ 不可访问

## 2. 索引设计

### 2.1 物理布局

```
租户 tnt_a:
  alias: search-tnt_a
    ├─ search-tnt_a-000001   (active write)
    ├─ search-tnt_a-000002
    └─ search-tnt_a-000003
  rollover policy:
    - size > 50GB OR docs > 50M OR age > 30d → rollover
    - retention: 全部保留（依业务 lifecycle 配）
```

- **alias 收口**：业务层只写 `search-tnt_a`，OpenSearch 自动指向 active write index
- **rollover** 控制单 shard 大小，避免热 index 过载
- **共享物理集群**：3-N data node 服多个租户，靠 alias + ILM 隔离

**例外**：Enterprise tier 租户分独立 OpenSearch namespace 或独立集群（详见 multi-tenancy.md SaaS 三级隔离）。

### 2.2 文档结构

```json
{
  "_id": "doc:res_01J7XYZ",
  "tenant_id": "tnt_a",                  // mandatory filter 必校验
  "resource_type": "document",
  "resource_id": "res_01J7XYZ",
  "title": "客户合同 - Alice Inc",
  "title_en": "Customer Contract - Alice Inc",  // 多语言字段，分别分词
  "content": "...",                      // 全文索引
  "content_en": "...",
  "tags": ["contract", "pii"],
  "owner_user_id": "usr_01J7ABC",
  "owner_team_id": "tem_01J7DEF",
  "shared_with_users": ["usr_xxx", "usr_yyy"],   // 显式分享列表
  "shared_with_teams": ["tem_xxx"],
  "sensitivity": "L3",                   // L1-L5
  "created_at": "2026-05-22T...",
  "updated_at": "2026-05-22T...",
  "_extras": { ... }                     // 业务自定义字段，统一放 _extras
}
```

### 2.3 mapping（template）

```yaml
mappings:
  dynamic: strict                        # 禁止动态字段，必须显式声明
  properties:
    tenant_id:        { type: keyword }
    resource_type:    { type: keyword }
    resource_id:      { type: keyword }
    title:            { type: text, analyzer: ik_max_word, search_analyzer: ik_smart }
    title_en:         { type: text, analyzer: english }
    content:          { type: text, analyzer: ik_max_word }
    content_en:       { type: text, analyzer: english }
    tags:             { type: keyword }
    owner_user_id:    { type: keyword }
    owner_team_id:    { type: keyword }
    shared_with_users: { type: keyword }
    shared_with_teams: { type: keyword }
    sensitivity:      { type: keyword }
    created_at:       { type: date }
    updated_at:       { type: date }
    _extras:          { type: object, dynamic: true }
```

- **分词器**：中文 IK（ik_max_word 入库 / ik_smart 查询）；英文 standard / english
- **strict dynamic**：防止业务塞入未知字段导致 mapping 爆炸；自定义字段统一进 `_extras`
- **不索引敏感原值**：身份证、手机号、邮箱不入 content（防 GET _search 直接捞 PII）

## 3. ACL filter 注入

### 3.1 注入位置

> 所有查询必经 SDK；SDK 自动从 context 取 user，调 `authz.list_accessible_ids(user, resource_type)` 拿可见 ID 列表，注入 filter。

```python
# 业务层调用
results = client.search.query(
    q="alice contract",
    resource_types=["document", "message"],
    filters={"tags": ["contract"]},
    size=20,
    offset=0,
)
```

### 3.2 SDK 内部拼出的 OpenSearch DSL

```json
{
  "query": {
    "bool": {
      "must": [
        { "multi_match": { "query": "alice contract", "fields": ["title^2","title_en^2","content","content_en"] } }
      ],
      "filter": [
        { "term": { "tenant_id": "tnt_a" } },                    // 强制
        { "terms": { "resource_type": ["document","message"] } },
        { "range": { "sensitivity": { "lte_keyword": "L3" } } }, // user.clearance=L3 → 只看 L1-L3
        {
          "bool": {                                              // ACL：owner / shared / list_accessible_ids
            "should": [
              { "term": { "owner_user_id": "usr_01J7ABC" } },
              { "terms": { "owner_team_id": ["tem_x","tem_y"] } },    // 用户所在 team
              { "term": { "shared_with_users": "usr_01J7ABC" } },
              { "terms": { "shared_with_teams": ["tem_x","tem_y"] } },
              { "terms": { "resource_id": ["res_a","res_b", ...] } }  // authz.list_accessible_ids
            ],
            "minimum_should_match": 1
          }
        },
        { "terms": { "tags": ["contract"] } }
      ]
    }
  },
  "highlight": { "fields": { "title": {}, "content": {} } },
  "size": 20,
  "from": 0,
  "_source": ["resource_type","resource_id","title","tags","sensitivity","updated_at"]
}
```

### 3.3 双层校验（兜底）

**第一层（SDK）**：注入如上 filter。

**第二层（OpenSearch index template）**：在 index alias 上挂 `filter` 别名定义：

```json
PUT /_aliases
{
  "actions": [
    {
      "add": {
        "index": "search-tnt_a-*",
        "alias": "search-tnt_a-readonly",
        "filter": { "term": { "tenant_id": "tnt_a" } }
      }
    }
  ]
}
```

业务用 `search-tnt_a-readonly` alias 查询。即使 SDK bug 漏注 `tenant_id` filter，alias 层兜底过滤；跨租户绝无可能。

**第三层（authz）**：搜索结果带 resource_id → 业务层调用 `read(resource_id)` 时仍走 authz 二次校验（防 index 过期数据漏过滤）。

### 3.4 list_accessible_ids 优化

`authz.list_accessible_ids(user, resource_type)` 返回大量 ID 时（>10k）：
- 改用 `has_parent` / `has_child` join（不推荐 OS）→
- 或改用 `term_lookup`（OpenSearch 支持 terms filter 用另一 index 的 doc 提供值）：
  ```json
  { "terms": { "resource_id": { "index": "authz-acl-tnt_a", "id": "usr_01J7ABC", "path": "accessible_ids" } } }
  ```
- 或前置过滤：authz 索引 `(user_id, resource_type, resource_id)` 倒排 → 搜索时 join

v1 采用 simple terms（≤10k）；v1.1 加 term_lookup 优化（大租户）。

## 4. 索引 pipeline（写入）

### 4.1 SDK

```python
from foundation_search import SearchClient

client = SearchClient.from_env()

# 1. 索引一条
client.index(
    resource_type="document",
    resource_id="res_01J7XYZ",
    document={
        "title": "客户合同",
        "content": "...",
        "tags": ["contract"],
        "owner_user_id": "usr_01J7ABC",
        "owner_team_id": "tem_01J7DEF",
        "shared_with_users": [],
        "shared_with_teams": [],
        "_extras": {"contract_number": "C-2026-001"},
    },
)
# SDK 自动补 tenant_id（从 ctx）+ sensitivity（从 dlp.resource_label）+ updated_at

# 2. 批量索引
client.bulk_index([...])

# 3. 部分更新（ACL 变化场景常用）
client.update(
    resource_type="document",
    resource_id="res_01J7XYZ",
    partial={"shared_with_users": ["usr_xxx", "usr_yyy"]},
)

# 4. 删除
client.delete(resource_type="document", resource_id="res_01J7XYZ")

# 5. 重新打 sensitivity 标签后强制刷新（dlp scanner 升级触发）
client.reindex_from_source(resource_type="document", resource_id="res_01J7XYZ")
```

### 4.2 写入策略

- **同步写**：默认走 outbox（业务 DB 事务 + outbox row），异步 worker 同步到 OpenSearch
- **batch**：worker 每 1s 或 500 文档 batch 写入（性能）
- **失败重试**：3 次指数退避 → DLQ
- **顺序保证**：同 resource_id 串行（按 resource_id hash 路由 worker）

### 4.3 ACL 变更同步

> 这是搜索最容易出 bug 的地方。

触发 reindex 的 ACL 事件：
- 文档分享 / 取消分享 → update shared_with_*
- 用户从 team 移除 → 该 team 下所有资源 `shared_with_teams` 不变，但 user.team_membership 变（直接重算 list_accessible_ids 即可，无需重索引文档）
- 资源 sensitivity 升降 → update sensitivity
- owner 转移 → update owner_*

**关键**：用户的 team membership 变化 **不需要重索引文档**，只需失效 `list_accessible_ids` 缓存（authz 端处理）。

## 5. 数据模型（OpenSearch 之外，PG 元数据）

```sql
-- 1. 资源类型注册
CREATE TABLE search.resource_type (
  resource_type    TEXT PRIMARY KEY,         -- 全局唯一
  schema_version   INT NOT NULL,
  fields           JSONB NOT NULL,           -- 字段定义（mapping 摘要）
  custom_analyzers JSONB,                    -- 业务自定义分词
  enabled          BOOLEAN NOT NULL DEFAULT TRUE,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 2. 租户索引 metadata
CREATE TABLE search.tenant_index (
  tenant_id        TEXT NOT NULL,
  alias            TEXT NOT NULL,
  active_index     TEXT NOT NULL,
  shard_count      INT NOT NULL DEFAULT 1,
  replica_count    INT NOT NULL DEFAULT 1,
  rollover_size_gb INT NOT NULL DEFAULT 50,
  retention_days   INT,                      -- NULL = unlimited
  PRIMARY KEY (tenant_id)
);

-- 3. 索引 outbox（业务 DB 用）
CREATE TABLE search.outbox (
  tenant_id        TEXT NOT NULL,
  outbox_id        TEXT NOT NULL,
  op               TEXT NOT NULL,             -- 'index'/'update'/'delete'/'reindex_from_source'
  resource_type    TEXT NOT NULL,
  resource_id      TEXT NOT NULL,
  payload          JSONB,
  status           TEXT NOT NULL DEFAULT 'pending',
  attempt          INT NOT NULL DEFAULT 0,
  last_error       TEXT,
  enqueued_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  processed_at     TIMESTAMPTZ,
  PRIMARY KEY (tenant_id, outbox_id)
);
CREATE INDEX idx_search_outbox_pending ON search.outbox(status, enqueued_at) WHERE status='pending';
```

## 6. 查询能力

| 功能 | 实现 |
|---|---|
| Full-text | multi_match across title/content (boosted) |
| Filter | terms / range / exists |
| Facet | terms aggregation（按 tag / type / sensitivity） |
| 排序 | _score / updated_at / 自定义 |
| 分页 | from/size（≤10000）/ search_after（深分页） |
| 高亮 | OpenSearch highlight |
| 拼写纠错 | suggest + did-you-mean（仅英文 v1） |
| 跨字段搜索 | multi_match cross_fields |
| 同义词 | 业务可注册 synonym list per resource_type |
| 模糊匹配 | fuzzy（编辑距离 ≤2） |

## 7. 与其他模块集成

| 模块 | 集成 |
|---|---|
| **authz** | `list_accessible_ids` SDK 注入 filter；ACL 变更 webhook |
| **dlp** | 索引时自动补 sensitivity；clearance 比较过滤 |
| **org** | team membership 变化 → list_accessible_ids 缓存失效 |
| **audit** | 所有搜索请求审计（query + filter + result_count + user）|
| **lifecycle** | 资源 hard delete → DELETE doc；recycle_bin → status=archived（搜索默认排除） |
| **identity** | user.locale → query analyzer 选择 |

## 8. 部署形态

| 形态 | OpenSearch | 索引策略 |
|---|---|---|
| small | 1 节点（dev only） | 全部租户 1 alias-per-tenant + 1 shard |
| medium | 3 节点（master + 2 data） | per-tenant alias + 1-3 shard，按数据量 |
| large | 3 master + N data（按需扩） | per-tenant alias；大租户独立 index group；Enterprise 独立集群 |

## 9. 错误码

| code | HTTP |
|---|---|
| `FOUNDATION.SEARCH.RESOURCE_TYPE.UNKNOWN` | 400 |
| `FOUNDATION.SEARCH.QUERY.MALFORMED` | 400 |
| `FOUNDATION.SEARCH.INDEX.WRITE_FAILED` | 500 |
| `FOUNDATION.SEARCH.PAGE.TOO_DEEP` | 400 |（建议用 search_after）|
| `FOUNDATION.SEARCH.RATE_LIMITED` | 429 |
| `FOUNDATION.SEARCH.CLUSTER.UNHEALTHY` | 503 |

## 10. 性能与容量

| 指标 | 目标 |
|---|---|
| query P95 | < 200ms（result_count < 100） |
| index P95 | < 50ms（单条） |
| bulk_index | 5000/s/节点 |
| 每租户索引 | ≤ 50 GB 触发 rollover |
| 单 shard | ≤ 50 GB |

## 11. 待解决问题

| # | 问题 | 决策 |
|---|---|---|
| 1 | list_accessible_ids 超大（>10k） | v1.1 term_lookup；v1 限制并 fallback 到「最近 100 个 + 关键词二次过滤」 |
| 2 | 多语言混合文档 | 同时索引 title + title_en；查询并行匹配 |
| 3 | 同义词租户隔离 | per-tenant analyzer settings（OpenSearch 支持 dynamic settings） |
| 4 | 拼写纠错中文 | v1 仅英文；中文 v1.1 接 elastic 中文 suggest |
| 5 | 索引 outbox 堆积 | KEDA 触发 + 告警；DLQ 人工介入 |
| 6 | Enterprise 独立集群跨集群搜索 | 业务层 federated query（v1.2） |
| 7 | 法律保留期间不允许 DELETE | 与 lifecycle 联动；hold 期间 update 为 `_excluded_by_hold=true` filter |
| 8 | 历史数据回填 | 提供 `reindex_resource_type` 工具，分批 + 限速；大租户夜间窗口跑 |
| 9 | DLP 升级 sensitivity 后旧 cache | 索引 update 时清 query cache（OpenSearch refresh）|
| 10 | 搜索结果点击转化埋点 | 业务层埋；search 不内置 |

## 12. 验证标准（A-M3 出口）

| # | 验证 | 通过 |
|---|---|---|
| 1 | 跨租户隔离 | tenant_a 用户搜不到 tenant_b 文档（双层 + 三层兜底）|
| 2 | sensitivity 过滤 | clearance=L2 用户搜不到 L3+ 文档 |
| 3 | shared_with 过滤 | 文档分享给用户 X → X 能搜到；取消分享后立即搜不到 |
| 4 | team 变更 | 用户离开 team → 立即搜不到该 team 文档（list_accessible_ids 缓存失效）|
| 5 | rollover | 模拟 50GB → 自动 rollover，旧 index 仍可读 |
| 6 | 中英文搜索 | IK 分词正确；多语言文档双语都能命中 |
| 7 | 索引 pipeline | outbox 写入 → < 5s 可搜 |
| 8 | DLQ 处理 | OpenSearch down 模拟 → 重试 3 次 → DLQ → 恢复后 re-queue 成功 |
| 9 | 性能 | 1000 QPS 持续 5min P95 < 200ms |
| 10 | 越权 fuzz | 1 万次随机跨 user/sensitivity/team 查询，0 越权 |
| 11 | 索引 ACL 变更 | shared_with 更新 → < 5s 反映到搜索结果 |
| 12 | 审计 | 所有 query 落 audit；含 result_count |
