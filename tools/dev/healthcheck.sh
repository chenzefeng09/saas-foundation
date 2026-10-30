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

# ── probes that need more than a one-liner ──────────────────────────────────
# PgBouncer admin console needs the admin password (config/pgbouncer/userlist.txt;
# dev.yml's own healthcheck uses the same dev default).
PGBOUNCER_ADMIN_PASSWORD="${PGBOUNCER_ADMIN_PASSWORD:-pgbouncer_admin_change_me}"
pgbouncer_transaction_mode() {
  docker exec -e PGPASSWORD="$PGBOUNCER_ADMIN_PASSWORD" foundation-pgbouncer \
    psql -h 127.0.0.1 -p 6432 -U pgbouncer_admin -d pgbouncer -Atc 'SHOW CONFIG' \
    | grep -q '^pool_mode|transaction|'
}
# Keycloak ≥ 25 serves /health/* on the management port 9000, which dev.yml does not
# publish (host :9000 is ClickHouse) — ask from inside the container.
keycloak_ready() {
  docker exec foundation-keycloak bash -c 'exec 3<>/dev/tcp/127.0.0.1/9000 &&
    printf "GET /health/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" >&3 &&
    cat <&3' | grep -q '"status": *"UP"'
}
# dev.yml runs OpenSearch with the security plugin disabled: plain HTTP, no auth.
opensearch_cluster() {
  curl -sf "http://localhost:${PORT_OPENSEARCH_HTTP:-9200}/_cluster/health" \
    | grep -qE '"status":"(yellow|green)"'
}
# Signs every realm-file seed user in (password grant); prints no secrets.
keycloak_seed_users_sign_in() {
  KC_URL="http://localhost:${PORT_KEYCLOAK:-8080}" \
  KC_REALM_FILE=deploy/docker-compose/init/keycloak/foundation-realm.json \
    python3 deploy/docker-compose/init/keycloak-seed/seed-dev-users.py --check
}

echo "═══ saas-foundation local stack healthcheck ═══"
echo ""
echo "▸ Infra container readiness"

check "Postgres ready"           "docker exec foundation-postgres pg_isready -U postgres"
check "PgBouncer pool_mode=transaction" pgbouncer_transaction_mode
check "Redis PONG"                "docker exec foundation-redis redis-cli -a ${REDIS_PASSWORD:-redis_change_me} ping | grep -q PONG"
check "Keycloak /health/ready"    keycloak_ready
check "ClickHouse ping"           "curl -sf http://localhost:${PORT_CLICKHOUSE_HTTP:-8123}/ping | grep -q Ok"
check "OpenSearch cluster"        opensearch_cluster
check "Vault initialized"         "docker exec foundation-vault vault status 2>&1 | grep -q 'Initialized\\s*true'"
check "MinIO ready"               "docker exec foundation-minio mc ready local"
check "OPA health"                "curl -sf http://localhost:8181/health"
check "Unleash health"            "curl -sf http://localhost:${PORT_UNLEASH:-4242}/health | grep -q '\"health\":\"GOOD\"'"
check "OTel accepts OTLP"         "curl -sf -X POST http://localhost:${PORT_OTEL_HTTP:-4318}/v1/traces -H 'Content-Type: application/json' -d '{\"resourceSpans\":[]}'"
check "Jaeger UI"                 "curl -sf http://localhost:${PORT_JAEGER_UI:-16686}/"
if docker ps --format '{{.Names}}' | grep -qx foundation-mailhog; then
  check "Mailhog UI"              "curl -sf http://localhost:${PORT_MAILHOG_UI:-8025}/"
else
  echo "  - Mailhog UI — skipped (optional; start with: docker compose --profile extras up -d mailhog)"
fi

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

warn_check "Keycloak seed users can sign in" keycloak_seed_users_sign_in \
  "re-run the keycloak-init job: docker compose -f deploy/docker-compose/dev.yml --env-file deploy/docker-compose/.env up keycloak-init"

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
