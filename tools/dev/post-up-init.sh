#!/usr/bin/env bash
# post-up-init.sh —— 本地栈起来后做业务级初始化
#
# - Vault: 启用 transit secrets engine + 创建初始 KEK
# - MinIO: 建 4 个 bucket（含 1 个 WORM）
# - Keycloak: 等待 realm 导入完成 + 创建 2 个 Organization
# - 幂等：重复跑无副作用
#
# 用法：
#   make up-full   # 推荐
#   或：bash tools/dev/post-up-init.sh

set -euo pipefail

source deploy/docker-compose/.env 2>/dev/null || true

GREEN='\033[32m'; YELLOW='\033[33m'; RED='\033[31m'; RESET='\033[0m'

step() { echo -e "${YELLOW}→${RESET} $*"; }
ok()   { echo -e "  ${GREEN}✓${RESET} $*"; }
fail() { echo -e "  ${RED}✗${RESET} $*" >&2; exit 1; }

VAULT_ADDR="http://localhost:${PORT_VAULT:-8200}"
VAULT_TOKEN="${VAULT_DEV_ROOT_TOKEN:-dev-root-token-change-me}"
KC_URL="http://localhost:${PORT_KEYCLOAK:-8080}"
KC_ADMIN="${KEYCLOAK_ADMIN:-admin}"
KC_PWD="${KEYCLOAK_ADMIN_PASSWORD:-keycloak_admin_change_me}"

# ─────────────────────────────────────────────────────────────
# 0) 预检
# ─────────────────────────────────────────────────────────────
step "preflight: containers up?"
for c in foundation-postgres foundation-keycloak foundation-vault foundation-minio foundation-opa; do
  if ! docker ps --format '{{.Names}}' | grep -q "^${c}$"; then
    fail "$c not running — run 'make up' first"
  fi
done
ok "containers running"

# ─────────────────────────────────────────────────────────────
# 1) Vault: 启用 transit + 建 KEK
# ─────────────────────────────────────────────────────────────
step "vault: enable transit secrets engine"
if docker exec foundation-vault sh -c "VAULT_TOKEN=$VAULT_TOKEN vault secrets list -format=json | grep -q '\"transit/\"'"; then
  ok "transit already enabled"
else
  docker exec -e VAULT_TOKEN="$VAULT_TOKEN" foundation-vault vault secrets enable transit
  ok "transit enabled"
fi

step "vault: seed KEKs for dev tenants"
for tenant in tnt_01J5DEV0000000000000000A tnt_01J5DEV0000000000000000B; do
  for purpose in pii_phone pii_id_card pii_bank_account audit_hashchain jwt_signing; do
    key="${purpose}_${tenant}"
    if docker exec -e VAULT_TOKEN="$VAULT_TOKEN" foundation-vault \
         sh -c "vault read transit/keys/$key >/dev/null 2>&1"; then
      :  # 已存在
    else
      docker exec -e VAULT_TOKEN="$VAULT_TOKEN" foundation-vault \
        vault write -f "transit/keys/$key" \
          type=aes256-gcm96 \
          derived=true \
          auto_rotate_period=2160h >/dev/null
    fi
  done
done
ok "KEKs ready (10 keys: 5 purpose × 2 dev tenants)"

# ─────────────────────────────────────────────────────────────
# 2) MinIO: 建 bucket
# ─────────────────────────────────────────────────────────────
step "minio: bootstrap buckets"
docker exec foundation-minio mc alias set local http://localhost:9000 \
  "${MINIO_ROOT_USER:-foundation}" "${MINIO_ROOT_PASSWORD:-minio_change_me_min_12_chars}" >/dev/null 2>&1 || true

declare -a buckets=(
  "foundation"                  # 通用对象
  "foundation-export"           # 用户导出
  "foundation-backup"           # DB 备份
)
for b in "${buckets[@]}"; do
  docker exec foundation-minio mc mb "local/$b" --ignore-existing >/dev/null
  ok "bucket: $b"
done

# WORM bucket：注意 mc mb --with-lock 仅在创建时能加；幂等检查
if ! docker exec foundation-minio mc ls local/foundation-audit-worm >/dev/null 2>&1; then
  docker exec foundation-minio mc mb local/foundation-audit-worm --with-lock >/dev/null
  docker exec foundation-minio mc retention set --default compliance 7y local/foundation-audit-worm >/dev/null
  ok "bucket: foundation-audit-worm (WORM compliance 7y)"
else
  ok "bucket: foundation-audit-worm (already exists)"
fi

# ─────────────────────────────────────────────────────────────
# 3) Keycloak: 等 realm 就绪 + 建 Organizations
# ─────────────────────────────────────────────────────────────
step "keycloak: wait for foundation realm"
for i in $(seq 1 30); do
  if curl -sf "$KC_URL/realms/foundation/.well-known/openid-configuration" >/dev/null 2>&1; then
    ok "realm 'foundation' ready"
    break
  fi
  if [ "$i" -eq 30 ]; then fail "realm not ready after 5 min"; fi
  sleep 10
done

step "keycloak: get admin token"
KC_TOKEN=$(curl -sf -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password" -d "client_id=admin-cli" \
  -d "username=$KC_ADMIN" -d "password=$KC_PWD" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
[ -n "$KC_TOKEN" ] || fail "failed to get admin token"
ok "admin token acquired"

step "keycloak: create Organizations (1:1 with tenant.tenant)"
for tenant in tnt_01J5DEV0000000000000000A tnt_01J5DEV0000000000000000B; do
  # 检查是否存在
  exists=$(curl -sf -H "Authorization: Bearer $KC_TOKEN" \
    "$KC_URL/admin/realms/foundation/organizations?search=$tenant" \
    | python3 -c "import sys,json; data=json.load(sys.stdin); print(len(data))" 2>/dev/null || echo 0)
  if [ "$exists" -gt 0 ]; then
    ok "organization $tenant already exists"
    continue
  fi
  resp=$(curl -sf -w '%{http_code}' -o /tmp/kc-org-create.json \
    -X POST "$KC_URL/admin/realms/foundation/organizations" \
    -H "Authorization: Bearer $KC_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"$tenant\",\"alias\":\"$tenant\",\"domains\":[{\"name\":\"${tenant//tnt_/}.local\",\"verified\":true}]}" || true)
  if [ "$resp" = "201" ]; then
    ok "organization $tenant created"
  else
    echo -e "  ${YELLOW}!${RESET} organization $tenant create returned $resp (may need KC 26.4+ Organizations feature flag)"
  fi
done

# ─────────────────────────────────────────────────────────────
# 4) OPA: smoke test
# ─────────────────────────────────────────────────────────────
step "opa: smoke test (kill switch 应硬拒)"
resp=$(curl -sf -X POST http://localhost:8181/v1/data/foundation/authz/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "policy_id": "billing.invoice.void",
      "action": "billing.invoice.void",
      "user": {"tenant_id":"tnt_a","role_grants":[]},
      "resource": {"tenant_id":"tnt_a"},
      "tenant": {"compliance_modes":["pipl"],"data_residency":"cn-only"},
      "request": {"mfa_satisfied":true,"country":"CN","destination_country":"CN"},
      "permission_definition": {"risk_level":"LOW"},
      "now": "2026-05-22T10:00:00Z"
    }
  }')
result=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('result', 'MISSING'))" 2>/dev/null || echo "PARSE_ERROR")
if [ "$result" = "False" ] || [ "$result" = "false" ]; then
  ok "OPA returns default deny as expected"
else
  echo -e "  ${YELLOW}!${RESET} OPA returned: $result (expected False)"
fi

# ─────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}post-up-init done.${RESET}"
echo ""
echo "Next:"
echo "  make healthcheck    # 业务级断言"
echo "  make seed           # 塞示例数据"
echo "  open $KC_URL        # KC admin UI"
