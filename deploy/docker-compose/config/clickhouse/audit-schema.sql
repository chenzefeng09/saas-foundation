-- =============================================================================
-- ClickHouse 审计 schema — audit-service M2
-- 单机开发版（无 ON CLUSTER / ReplicatedMergeTree）
-- prev_hash / curr_hash / merkle_root 用 String(hex)，不用 FixedString，
-- 便于 clickhouse-connect Python 端直接传字符串
-- =============================================================================

CREATE DATABASE IF NOT EXISTS audit;

-- ---------------------------------------------------------------------------
-- 1. audit.events — 热存储主表
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit.events
(
    -- 标识
    event_id            String,
    schema_version      UInt16 DEFAULT 1,

    -- 时间
    occurred_at         DateTime64(3, 'UTC'),
    ingested_at         DateTime64(3, 'UTC') DEFAULT now64(3),
    tsa_timestamp       Nullable(DateTime64(3, 'UTC')),

    -- 多租户
    tenant_id           LowCardinality(String),

    -- 来源
    service             LowCardinality(String),
    service_version     LowCardinality(String) DEFAULT '',

    -- 事件类型
    event_type          LowCardinality(String),
    severity            LowCardinality(String),   -- DEBUG/INFO/NOTICE/WARN/ERROR/SECURITY/CRITICAL
    outcome             LowCardinality(String),   -- SUCCESS/FAILURE/DENIED/PARTIAL

    -- Actor
    actor_kind          LowCardinality(String),   -- USER/SYSTEM/ADMIN/MIGRATOR/SERVICE_ACCOUNT/API_KEY
    actor_user_id       Nullable(String),
    actor_api_key_id    Nullable(String),

    -- Target / Resource
    resource_type       LowCardinality(String) DEFAULT '',
    resource_id         Nullable(String),
    resource_path       Nullable(String),

    -- 链路追踪
    request_id          String DEFAULT '',
    trace_id            Nullable(String),
    span_id             Nullable(String),
    session_id          Nullable(String),
    parent_event_id     Nullable(String),

    -- 上下文
    ip                  Nullable(String),
    user_agent          Nullable(String),
    country             Nullable(LowCardinality(String)),

    -- 负载（脱敏后 JSON 字符串）
    payload             String DEFAULT '{}',
    payload_size        UInt32 DEFAULT 0,
    payload_truncated   Bool DEFAULT false,

    -- 合规
    compliance_modes    Array(LowCardinality(String)),
    retention_until     Date DEFAULT toDate(addYears(occurred_at, 1)),
    legal_hold          Bool DEFAULT false,

    -- 完整性 hash chain
    prev_hash           String DEFAULT '',          -- 64-char hex, genesis = '0' * 64
    curr_hash           String DEFAULT '',          -- 64-char hex

    -- Merkle batch 归属（写入 CH 时填入）
    merkle_batch_id     Nullable(String),           -- "mrk_..."
    merkle_leaf_idx     Nullable(UInt32),

    -- batch 签名（冗余存；正式版本在 merkle_batch 表）
    batch_signature     Nullable(String),

    -- WORM 双写状态
    worm_written        Bool DEFAULT false,
    worm_uri            Nullable(String)
)
ENGINE = MergeTree
PARTITION BY (toYYYYMM(occurred_at), tenant_id)
ORDER BY (tenant_id, occurred_at, event_id)
TTL toDateTime(occurred_at) + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

-- ---------------------------------------------------------------------------
-- 2. audit.merkle_batch — 每批 Merkle root + 签名 + TSA
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit.merkle_batch
(
    batch_id            String,
    tenant_id           LowCardinality(String),
    service             LowCardinality(String) DEFAULT '',
    created_at          DateTime64(3, 'UTC') DEFAULT now64(3),
    sealed_at           DateTime64(3, 'UTC') DEFAULT now64(3),
    event_count         UInt32 DEFAULT 0,
    first_event_id      String DEFAULT '',
    last_event_id       String DEFAULT '',
    merkle_root         String DEFAULT '',          -- 64-char hex
    signature           String DEFAULT '',          -- Ed25519 signature (base64)
    signature_key_id    String DEFAULT '',          -- crypto KEK label / key version
    tsa_token           Nullable(String),           -- RFC 3161 TimeStampToken (base64)
    tsa_provider        LowCardinality(String) DEFAULT '',  -- 'freetsa' / 'ntsc' / ...
    tsa_timestamp       Nullable(DateTime64(3, 'UTC')),
    external_anchor     Nullable(String)            -- optional git commit / blockchain tx
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(created_at)
ORDER BY (tenant_id, created_at, batch_id)
SETTINGS index_granularity = 8192;

-- ---------------------------------------------------------------------------
-- 3. audit.events_by_resource — 按 resource_type / resource_id 查的二级视图
--    (ReplacingMergeTree 不适合 append-only；用普通 MergeTree AS 镜像)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit.events_by_resource
(
    event_id            String,
    tenant_id           LowCardinality(String),
    resource_type       LowCardinality(String),
    resource_id         Nullable(String),
    occurred_at         DateTime64(3, 'UTC'),
    event_type          LowCardinality(String),
    severity            LowCardinality(String),
    outcome             LowCardinality(String),
    actor_user_id       Nullable(String),
    curr_hash           String DEFAULT ''
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (tenant_id, resource_type, resource_id, occurred_at)
TTL toDateTime(occurred_at) + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;
