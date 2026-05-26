#!/usr/bin/env bash
# 给本地 dev 栈塞示例数据
# - 已由 init/postgres/02-tenant-table.sql 创建两个 dev tenant
# - 这里补充：Keycloak realm + 测试用户、ClickHouse 示例审计事件、MinIO bucket
set -euo pipefail

source deploy/docker-compose/.env 2>/dev/null || true

GREEN='\033[32m'; YELLOW='\033[33m'; RESET='\033[0m'

echo -e "${YELLOW}=== Seeding local stack ===${RESET}"

# 1) 创建 MinIO bucket
echo "→ MinIO bucket 'foundation'..."
docker exec foundation-minio mc alias set local http://localhost:9000 \
  "${MINIO_ROOT_USER:-foundation}" "${MINIO_ROOT_PASSWORD:-minio_change_me_min_12_chars}" 2>/dev/null || true
docker exec foundation-minio mc mb local/foundation --ignore-existing 2>/dev/null || true
docker exec foundation-minio mc mb local/foundation-audit-worm --ignore-existing 2>/dev/null || true
docker exec foundation-minio mc retention set --default compliance 7y local/foundation-audit-worm 2>/dev/null || \
  echo -e "  ${YELLOW}WORM retention not set (object lock requires bucket creation with --with-lock)${RESET}"

# 2) ClickHouse 示例事件
echo "→ ClickHouse seed audit event..."
docker exec foundation-clickhouse clickhouse-client --query "
  INSERT INTO audit.events (event_id, event_type, occurred_at, tenant_id, actor_user_id, actor_kind, service, resource_type, resource_id, request_id, severity, outcome, payload, prev_hash, curr_hash, schema_version)
  VALUES ('evt_seed_001', 'foundation.identity.user.login_success', now64(3), 'tnt_01J5DEV0000000000000000A', 'usr_01J5DEV0USR000000000000A', 'USER', 'identity', 'session', 'sess_seed_001', 'req_seed_001', 'INFO', 'SUCCESS', '{\"method\":\"EMAIL_PASSWORD\"}', '', 'hash_seed', 1)
" || echo "  (event may already exist)"

# 3) Keycloak realm（待 P0 #4 Identity 详细设计后再补；当前仅占位）
echo "→ Keycloak realm seeding deferred to identity package (P0 #4)"

echo -e "${GREEN}Seed done.${RESET}"
echo ""
echo "Dev tenants:"
docker exec foundation-postgres psql -U postgres -d foundation -tA \
  -c "SELECT id, name, tier FROM tenant.tenant"
