-- =============================================================================
-- ClickHouse 审计 schema 占位（A-M2 由 audit-service 接管完善）
-- 本地开发只建库 + 一个最小事件表，让 service 启动不至于报"表不存在"
-- =============================================================================

CREATE DATABASE IF NOT EXISTS audit;

CREATE TABLE IF NOT EXISTS audit.events
(
    event_id        String,
    event_type      LowCardinality(String),
    occurred_at     DateTime64(3, 'UTC'),
    tenant_id       String,
    actor_user_id   Nullable(String),
    actor_kind      LowCardinality(String),  -- USER / SYSTEM / ADMIN / MIGRATOR
    service         LowCardinality(String),
    resource_type   LowCardinality(String),
    resource_id     Nullable(String),
    request_id      String,
    trace_id        Nullable(String),
    severity        LowCardinality(String),  -- INFO / WARN / ERROR / SECURITY
    outcome         LowCardinality(String),  -- SUCCESS / FAILURE / DENIED
    payload         String,                  -- JSON
    prev_hash       String,
    curr_hash       String,
    signature       Nullable(String),
    schema_version  UInt16
)
ENGINE = MergeTree
PARTITION BY (toYYYYMM(occurred_at), tenant_id)
ORDER BY (tenant_id, occurred_at, event_id)
TTL toDateTime(occurred_at) + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS audit.events_by_resource AS audit.events
ENGINE = MergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (tenant_id, resource_type, resource_id, occurred_at);
