#!/usr/bin/env bash
# post-up-init.sh —— 本地栈起来后做业务级初始化
#
# - Vault: 启用 transit secrets engine + 创建初始 KEK
# - MinIO: 建 4 个 bucket（含 1 个 WORM）
# - Keycloak: 等待 realm 导入完成 + 为每个 tenant.tenant 建 Organization（仅当 KC 开启了该特性）
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
KC_CONTAINER="${KC_CONTAINER:-foundation-keycloak}"

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
# The two dev tenants seeded by deploy/docker-compose (keycloak realm, tenant and
# audit-init jobs).  The KEKs services actually use are created through the
# crypto API by the audit-init / crypto-fieldencrypt-init jobs; these raw
# transit keys are the per-tenant keys tools/dev/healthcheck.sh looks for.
for tenant in tnt_01J5DEVXX00000000000000001 tnt_01J5DEVXX00000000000000002; do
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
# 3) Keycloak: 等 realm 就绪 + Organizations（1:1 tenant.tenant，仅当 KC 支持）
# ─────────────────────────────────────────────────────────────
# Organizations 在 KC 26 才 GA（docs/design/identity-v1.md 以 26.x 为目标），dev 栈当前跑
# KC ${KEYCLOAK_VERSION:-25.0}：25 里它是默认关闭的 preview feature，admin API 直接 404；
# 开了 feature 还要 realm 级 organizationsEnabled=true，且 25 的 Organization 没有 alias
# 字段（传了 400）。平台代码目前不依赖 KC Organization，所以 KC 不支持时跳过并说明原因，
# 不为 dev 去开 preview feature。
# admin 调用走容器内 kcadm.sh → http://localhost:8080：master realm 要求"外部"来源用 HTTPS，
# 宿主机经端口映射来的请求可能被判为外部（403 "HTTPS required"）。密码只在容器内展开。
step "keycloak: wait for foundation realm"
for i in $(seq 1 30); do
  if curl -sf "$KC_URL/realms/foundation/.well-known/openid-configuration" >/dev/null 2>&1; then
    ok "realm 'foundation' ready"
    break
  fi
  if [ "$i" -eq 30 ]; then fail "realm not ready after 5 min"; fi
  sleep 10
done

KCADM_CONFIG=/tmp/kcadm-post-up-init.config
# kcadm chatter goes to stderr; only show it when a call fails.
kcadm() {
  local err rc=0
  err=$(mktemp)
  docker exec "$KC_CONTAINER" /opt/keycloak/bin/kcadm.sh "$@" --config "$KCADM_CONFIG" 2>"$err" || rc=$?
  if [ "$rc" -ne 0 ]; then echo "  kcadm $* failed:" >&2; cat "$err" >&2; fi
  rm -f "$err"
  return "$rc"
}

step "keycloak: admin login (kcadm in $KC_CONTAINER)"
if ! login_out=$(docker exec "$KC_CONTAINER" sh -c '/opt/keycloak/bin/kcadm.sh config credentials \
    --config "$1" --server http://localhost:8080 --realm master \
    --user "$KEYCLOAK_ADMIN" --password "$KEYCLOAK_ADMIN_PASSWORD"' _ "$KCADM_CONFIG" 2>&1); then
  fail "kcadm login failed: $login_out"
fi
ok "admin session ready"

step "keycloak: Organizations (1:1 with tenant.tenant)"
org_probe=$(kcadm get serverinfo | python3 -c '
import json, sys
info = json.load(sys.stdin)
on = any(f.get("name") == "ORGANIZATION" and f.get("enabled") for f in info.get("features", []))
print(info["systemInfo"]["version"], "on" if on else "off")')
kc_version=${org_probe% *}
if [ "${org_probe#* }" != "on" ]; then
  ok "skipped: Keycloak $kc_version has the Organizations feature off (preview in KC 25, GA in 26); nothing in the platform uses KC Organizations yet"
else
  realm_flag=$(kcadm get realms/foundation --fields organizationsEnabled \
    | python3 -c 'import json, sys; print(json.load(sys.stdin).get("organizationsEnabled") is True)')
  if [ "$realm_flag" != "True" ]; then
    kcadm update realms/foundation -s organizationsEnabled=true
    ok "realm 'foundation': organizationsEnabled=true"
  fi
  existing=$(kcadm get organizations -r foundation -q first=0 -q max=1000 \
    | python3 -c 'import json, sys; print("\n".join(o["name"] for o in json.load(sys.stdin)))')
  tenants=$(docker exec foundation-postgres psql -U postgres -d foundation -Atc \
    "SELECT id, tier FROM tenant.tenant ORDER BY id")
  [ -n "$tenants" ] || fail "no rows in tenant.tenant"
  while IFS='|' read -r tenant tier; do
    if grep -qxF "$tenant" <<<"$existing"; then
      ok "organization $tenant already exists"
      continue
    fi
    lower=$(tr '[:upper:]' '[:lower:]' <<<"$tenant")
    domain="[{\"name\":\"${lower#tnt_}.local\"}]"
    if [ "${kc_version%%.*}" -ge 26 ]; then
      kcadm create organizations -r foundation -s "name=$tenant" -s "alias=$lower" \
        -s "domains=$domain" -s "attributes={\"tier\":[\"$tier\"]}" >/dev/null
    else
      # KC 25 preview: no alias field, and attributes on create fail
      # ("Can not update organization group").
      kcadm create organizations -r foundation -s "name=$tenant" -s "domains=$domain" >/dev/null
    fi
    ok "organization $tenant created"
  done <<<"$tenants"
fi
docker exec "$KC_CONTAINER" rm -f "$KCADM_CONFIG"

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
