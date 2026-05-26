#!/usr/bin/env bash
# healthcheck.sh —— 本地栈业务级断言（不只是 ping 端口）
#
# 跑完后绿表示：业务层可以直接开始开发
set -euo pipefail

GREEN='\033[32m'; RED='\033[31m'; YELLOW='\033[33m'; RESET='\033[0m'

source deploy/docker-compose/.env 2>/dev/null || true

fail=0
warn=0

check() {
  local name=$1 cmd=$2
  if eval "$cmd" > /dev/null 2>&1; then
    echo -e "  ${GREEN}✓${RESET} $name"
  else
    echo -e "  ${RED}✗${RESET} $name"
    fail=$((fail+1))
  fi
}

warn_check() {
  local name=$1 cmd=$2 hint=$3
  if eval "$cmd" > /dev/null 2>&1; then
    echo -e "  ${GREEN}✓${RESET} $name"
  else
    echo -e "  ${YELLOW}!${RESET} $name — $hint"
    warn=$((warn+1))
  fi
}

echo "═══ saas-foundation local stack healthcheck ═══"
echo ""
echo "▸ Infra container readiness"

check "Postgres ready"           "docker exec foundation-postgres pg_isready -U postgres"
check "PgBouncer transaction"     "docker exec foundation-pgbouncer psql -h 127.0.0.1 -p 6432 -U pgbouncer_admin -d pgbouncer -c 'SHOW POOLS' 2>&1 | grep -q transaction"
check "Redis PONG"                "docker exec foundation-redis redis-cli -a ${REDIS_PASSWORD:-redis_change_me} ping | grep -q PONG"
check "Keycloak /health/ready"    "curl -sf http://localhost:${PORT_KEYCLOAK:-8080}/health/ready | grep -q UP"
check "ClickHouse ping"           "curl -sf http://localhost:${PORT_CLICKHOUSE_HTTP:-8123}/ping | grep -q Ok"
check "OpenSearch cluster"        "curl -sk -u admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD:-OpenSearch_Change_Me_123!} https://localhost:${PORT_OPENSEARCH_HTTP:-9200}/_cluster/health | grep -qE 'yellow|green'"
check "Vault initialized"         "docker exec foundation-vault vault status 2>&1 | grep -q 'Initialized\\s*true'"
check "MinIO online"              "docker exec foundation-minio mc ready local 2>&1 | grep -q 'Online'"
check "OPA health"                "curl -sf http://localhost:8181/health"
check "Unleash health"            "curl -sf http://localhost:${PORT_UNLEASH:-4242}/health | grep -q OK"
check "OTel accepts OTLP"         "curl -sf -X POST http://localhost:${PORT_OTEL_HTTP:-4318}/v1/traces -H 'Content-Type: application/json' -d '{\"resourceSpans\":[]}'"
check "Jaeger UI"                 "curl -sf http://localhost:${PORT_JAEGER_UI:-16686}/"
check "Mailhog UI"                "curl -sf http://localhost:${PORT_MAILHOG_UI:-8025}/"

echo ""
echo "▸ Multi-tenancy baseline (docs/multi-tenancy.md)"

check "DB roles app_user/admin/migrator/observability" \
  "docker exec foundation-postgres psql -U postgres -d foundation -tAc \"SELECT count(*) FROM pg_roles WHERE rolname IN ('app_user','app_admin','app_migrator','app_observability')\" | grep -q 4"

check "app_user is NOBYPASSRLS" \
  "docker exec foundation-postgres psql -U postgres -d foundation -tAc \"SELECT NOT rolbypassrls FROM pg_roles WHERE rolname='app_user'\" | grep -q t"

check "app_migrator has BYPASSRLS" \
  "docker exec foundation-postgres psql -U postgres -d foundation -tAc \"SELECT rolbypassrls FROM pg_roles WHERE rolname='app_migrator'\" | grep -q t"

check "tenant.tenant table exists" \
  "docker exec foundation-postgres psql -U postgres -d foundation -tAc \"SELECT to_regclass('tenant.tenant')\" | grep -q tenant.tenant"

check "≥2 dev tenants seeded" \
  "[ \$(docker exec foundation-postgres psql -U postgres -d foundation -tAc 'SELECT count(*) FROM tenant.tenant') -ge 2 ]"

echo ""
echo "▸ Business-level assertions (post-up-init applied?)"

warn_check "Vault transit engine enabled" \
  "docker exec -e VAULT_TOKEN=${VAULT_DEV_ROOT_TOKEN:-dev-root-token-change-me} foundation-vault vault secrets list 2>&1 | grep -q '^transit/'" \
  "run 'make up-full' or 'bash tools/dev/post-up-init.sh'"

warn_check "Vault has dev KEKs" \
  "docker exec -e VAULT_TOKEN=${VAULT_DEV_ROOT_TOKEN:-dev-root-token-change-me} foundation-vault vault list transit/keys 2>&1 | grep -q 'tnt_01J5DEV'" \
  "run 'make up-full'"

warn_check "MinIO bucket 'foundation' exists" \
  "docker exec foundation-minio mc ls local/foundation" \
  "run 'make up-full'"

warn_check "MinIO bucket 'foundation-audit-worm' has lock" \
  "docker exec foundation-minio mc retention info local/foundation-audit-worm 2>&1 | grep -qi compliance" \
  "run 'make up-full'"

warn_check "ClickHouse audit.events table" \
  "docker exec foundation-clickhouse clickhouse-client --query 'EXISTS TABLE audit.events' | grep -q 1" \
  "ClickHouse init SQL may need rerun"

warn_check "Keycloak realm 'foundation' loaded" \
  "curl -sf http://localhost:${PORT_KEYCLOAK:-8080}/realms/foundation/.well-known/openid-configuration | grep -q issuer" \
  "wait for Keycloak start or check init/keycloak/foundation-realm.json"

warn_check "Keycloak dev user alice can authenticate" \
  "curl -sf -X POST http://localhost:${PORT_KEYCLOAK:-8080}/realms/foundation/protocol/openid-connect/token \
    -d 'grant_type=password' -d 'client_id=foundation-frontend' \
    -d 'username=alice@tenant-a.local' -d 'password=Tenant-A-Dev-Pwd-15chars!' | grep -q access_token" \
  "realm import may not include alice; try 'make seed-kc'"

warn_check "OPA policy compiled (package foundation.authz exists)" \
  "curl -sf http://localhost:8181/v1/policies | grep -q foundation.authz" \
  "OPA policies/ mount may be empty"

warn_check "OPA default-deny on empty grants" \
  "[ \$(curl -sf -X POST http://localhost:8181/v1/data/foundation/authz/allow \
       -H 'Content-Type: application/json' \
       -d '{\"input\":{\"policy_id\":\"x.y.z\",\"action\":\"x.y.z\",\"user\":{\"tenant_id\":\"tnt_a\",\"role_grants\":[]},\"resource\":{\"tenant_id\":\"tnt_a\"},\"tenant\":{\"compliance_modes\":[\"pipl\"],\"data_residency\":\"cn-only\"},\"request\":{\"mfa_satisfied\":true,\"country\":\"CN\",\"destination_country\":\"CN\"},\"permission_definition\":{\"risk_level\":\"LOW\"},\"now\":\"2026-05-22T10:00:00Z\"}}' \
       | python3 -c 'import sys,json; print(json.load(sys.stdin)[\"result\"])') = False ]" \
  "OPA policies not loaded; check config/opa/policies/"

echo ""
echo "═══════════════════════════════════════════════"
if [ "$fail" -eq 0 ] && [ "$warn" -eq 0 ]; then
  echo -e "${GREEN}All green — local stack is dev-ready.${RESET}"
elif [ "$fail" -eq 0 ]; then
  echo -e "${YELLOW}${warn} business-level check(s) need attention.${RESET}"
  echo "Run: ${GREEN}make up-full${RESET}  (it runs up + post-up-init + healthcheck)"
  exit 0
else
  echo -e "${RED}${fail} infra failure(s), ${warn} warning(s).${RESET}"
  echo "Inspect: docker compose -f deploy/docker-compose/dev.yml logs <svc>"
  exit 1
fi
