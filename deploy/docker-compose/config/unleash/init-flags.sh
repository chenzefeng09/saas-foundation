#!/bin/sh
# =============================================================================
# unleash-init: 幂等同步 feature-flag preset 到 Unleash Admin API (v6)
#
# 设计要点：
#   1. 幂等 — flag 已存在 → 跳过创建；strategy 已是目标状态 → 跳过写入。
#   2. v6 环境坑 — Unleash v6 启用 environment 时会自动插一条
#      flexibleRollout 100% 的 default strategy。本脚本在写入业务
#      strategy 前删除所有已存在的 strategies，确保不留 100% 兜底。
#   3. 每个 flag 的 strategy 只在 "development" environment 配置；
#      其他 environment 由运维按生产需求单独配置。
#
# 环境变量（由 docker-compose 注入）：
#   UNLEASH_URL        e.g. http://unleash:4242
#   UNLEASH_ADMIN_TOKEN e.g. *:*.unleash-insecure-admin-api-token
#   UNLEASH_PROJECT    default: default
#   UNLEASH_ENV        default: development
# =============================================================================

set -e

UNLEASH_URL="${UNLEASH_URL:-http://unleash:4242}"
UNLEASH_ADMIN_TOKEN="${UNLEASH_ADMIN_TOKEN:-*:*.unleash-insecure-admin-api-token}"
UNLEASH_PROJECT="${UNLEASH_PROJECT:-default}"
UNLEASH_ENV="${UNLEASH_ENV:-development}"

BASE="${UNLEASH_URL}/api/admin"
AUTH_HEADER="Authorization: ${UNLEASH_ADMIN_TOKEN}"
CT_HEADER="Content-Type: application/json"

log() { echo "=== unleash-init: $*" >&2; }
die() { echo "!!! unleash-init ERROR: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# wait_ready — 最多等 120 秒直到 /health 返回 OK
# ---------------------------------------------------------------------------
wait_ready() {
  log "waiting for Unleash to be ready at ${UNLEASH_URL}/health ..."
  i=0
  while true; do
    if curl -sf "${UNLEASH_URL}/health" | grep -q "GOOD\|OK"; then
      log "Unleash is ready"
      return 0
    fi
    i=$((i+1))
    if [ "$i" -ge 24 ]; then
      die "Unleash did not become ready within 120s"
    fi
    sleep 5
  done
}

# ---------------------------------------------------------------------------
# ensure_context_field <field_name> <description>
#   幂等创建自定义 Context Field（Unleash constraint 依赖它）
#   已存在时 PUT /api/admin/context/<name> 会成功更新，409 不会出现
# ---------------------------------------------------------------------------
ensure_context_field() {
  FIELD="$1"
  DESC="$2"

  log "ensuring context field: ${FIELD}"
  # Check existence
  HTTP_CODE=$(curl -s -o /tmp/ctx_resp.txt -w "%{http_code}" \
    -X GET "${BASE}/context/${FIELD}" \
    -H "${AUTH_HEADER}" -H "${CT_HEADER}")

  if [ "$HTTP_CODE" = "200" ]; then
    log "context field already exists: ${FIELD}"
    return 0
  fi

  # Create
  HTTP_CODE=$(curl -s -o /tmp/ctx_resp.txt -w "%{http_code}" \
    -X POST "${BASE}/context" \
    -H "${AUTH_HEADER}" -H "${CT_HEADER}" \
    -d "{\"name\":\"${FIELD}\",\"description\":\"${DESC}\",\"legalValues\":[]}")
  if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    log "context field created: ${FIELD}"
  elif [ "$HTTP_CODE" = "409" ]; then
    log "context field already exists (409, idempotent): ${FIELD}"
  else
    log "WARN: create context field ${FIELD} returned HTTP ${HTTP_CODE}:"
    cat /tmp/ctx_resp.txt >&2
  fi
}

# ---------------------------------------------------------------------------
# upsert_flag <flag_key> <description> <type>
#   type: release | experiment | permission | kill-switch | operational
# ---------------------------------------------------------------------------
upsert_flag() {
  FLAG="$1"
  DESC="$2"
  TYPE="${3:-release}"

  log "upsert flag: ${FLAG}"
  HTTP_CODE=$(curl -s -o /tmp/uf_resp.txt -w "%{http_code}" \
    -X GET "${BASE}/features/${FLAG}" \
    -H "${AUTH_HEADER}" -H "${CT_HEADER}")

  if [ "$HTTP_CODE" = "404" ]; then
    # 创建 flag（初始 disabled）
    HTTP_CODE=$(curl -s -o /tmp/uf_resp.txt -w "%{http_code}" \
      -X POST "${BASE}/projects/${UNLEASH_PROJECT}/features" \
      -H "${AUTH_HEADER}" -H "${CT_HEADER}" \
      -d "{\"name\":\"${FLAG}\",\"description\":\"${DESC}\",\"type\":\"${TYPE}\",\"impressionData\":false}")
    if [ "$HTTP_CODE" != "201" ] && [ "$HTTP_CODE" != "200" ]; then
      log "WARN: create flag ${FLAG} returned HTTP ${HTTP_CODE}:"
      cat /tmp/uf_resp.txt >&2
    else
      log "created flag: ${FLAG}"
    fi
  elif [ "$HTTP_CODE" = "200" ]; then
    log "flag already exists (idempotent): ${FLAG}"
  else
    log "WARN: GET ${FLAG} returned HTTP ${HTTP_CODE} — skipping"
  fi
}

# ---------------------------------------------------------------------------
# delete_all_strategies <flag_key>
#   删除 development environment 下的所有已存在 strategies（处理 v6 默认插入的 100% 坑）
# ---------------------------------------------------------------------------
delete_all_strategies() {
  FLAG="$1"
  log "cleaning existing strategies for ${FLAG} in env ${UNLEASH_ENV}"

  HTTP_CODE=$(curl -s -o /tmp/strat_list.txt -w "%{http_code}" \
    -X GET "${BASE}/projects/${UNLEASH_PROJECT}/features/${FLAG}/environments/${UNLEASH_ENV}" \
    -H "${AUTH_HEADER}" -H "${CT_HEADER}")

  if [ "$HTTP_CODE" != "200" ]; then
    log "WARN: could not list strategies for ${FLAG} (HTTP ${HTTP_CODE}) — skip delete"
    return 0
  fi

  # 提取所有 strategy id（要求 grep/sed 在 curlimages 中可用）
  # 格式：{"strategies":[{"id":"<uuid>",...},...],...}
  STRAT_IDS=$(grep -o '"id":"[^"]*"' /tmp/strat_list.txt | grep -v '"environmentId"' | sed 's/"id":"//;s/"//')
  for SID in $STRAT_IDS; do
    log "  deleting strategy ${SID} from ${FLAG}"
    curl -sf -X DELETE \
      "${BASE}/projects/${UNLEASH_PROJECT}/features/${FLAG}/environments/${UNLEASH_ENV}/strategies/${SID}" \
      -H "${AUTH_HEADER}" -H "${CT_HEADER}" || \
      log "  WARN: failed to delete strategy ${SID} (may not exist)"
  done
}

# ---------------------------------------------------------------------------
# add_strategy_constraint <flag_key> <json_strategy_body>
#   添加一条 strategy（含 constraints）到 development environment
# ---------------------------------------------------------------------------
add_strategy() {
  FLAG="$1"
  BODY="$2"

  log "  adding strategy to ${FLAG} ..."
  HTTP_CODE=$(curl -s -o /tmp/as_resp.txt -w "%{http_code}" \
    -X POST "${BASE}/projects/${UNLEASH_PROJECT}/features/${FLAG}/environments/${UNLEASH_ENV}/strategies" \
    -H "${AUTH_HEADER}" -H "${CT_HEADER}" \
    -d "$BODY")

  if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
    log "  strategy added to ${FLAG}"
  else
    log "WARN: add_strategy ${FLAG} returned HTTP ${HTTP_CODE}:"
    cat /tmp/as_resp.txt >&2
  fi
}

# ---------------------------------------------------------------------------
# enable_flag_in_env <flag_key>
#   在 development environment 中启用 flag
# ---------------------------------------------------------------------------
enable_flag_in_env() {
  FLAG="$1"
  log "enabling ${FLAG} in env ${UNLEASH_ENV}"
  HTTP_CODE=$(curl -s -o /tmp/en_resp.txt -w "%{http_code}" \
    -X POST "${BASE}/projects/${UNLEASH_PROJECT}/features/${FLAG}/environments/${UNLEASH_ENV}/on" \
    -H "${AUTH_HEADER}" -H "${CT_HEADER}" \
    -d "")
  if [ "$HTTP_CODE" != "200" ] && [ "$HTTP_CODE" != "201" ] && [ "$HTTP_CODE" != "204" ]; then
    log "WARN: enable ${FLAG} returned HTTP ${HTTP_CODE}:"
    cat /tmp/en_resp.txt >&2
  fi
}

# ===========================================================================
# Main
# ===========================================================================
wait_ready

log "=========================================="
log "Syncing feature flag presets to Unleash"
log "Project: ${UNLEASH_PROJECT}  Env: ${UNLEASH_ENV}"
log "=========================================="

# ---------------------------------------------------------------------------
# 0. 注册自定义 Context Field（constraint 用到的字段必须先在 Unleash 中存在）
# ---------------------------------------------------------------------------
ensure_context_field "tenantId"    "Tenant identifier (saas-foundation multi-tenant)"
ensure_context_field "tenantTier"  "Tenant subscription tier: FREE | PRO | ENTERPRISE"

# ---------------------------------------------------------------------------
# 1. billing.saas_mode
#    策略: tier IN [PRO, ENTERPRISE] (userWithId constraint on tenantId → 用 custom strategy / constraint)
#    Unleash v6 constraint: contextName=tenantTier, operator=IN_LIST values=[PRO,ENTERPRISE]
#    实际: 用 flexibleRollout strategy + constraint 而非 userWithId，
#          constraint contextName=tier (需 SDK 传 properties.tier)
# ---------------------------------------------------------------------------
upsert_flag "billing.saas_mode" "Enable Stripe-based SaaS billing; active for PRO/ENTERPRISE tiers" "release"
delete_all_strategies "billing.saas_mode"
add_strategy "billing.saas_mode" '{
  "name": "flexibleRollout",
  "title": "tier=PRO|ENTERPRISE rollout",
  "constraints": [
    {
      "contextName": "tenantTier",
      "operator": "IN",
      "values": ["PRO", "ENTERPRISE"],
      "inverted": false,
      "caseInsensitive": true
    }
  ],
  "parameters": {
    "rollout": "100",
    "stickiness": "default",
    "groupId": "billing.saas_mode"
  }
}'
enable_flag_in_env "billing.saas_mode"

# ---------------------------------------------------------------------------
# 2. auth.social_login.google
#    策略: 百分比 rollout 示例（gradual rollout 20%）
# ---------------------------------------------------------------------------
upsert_flag "auth.social_login.google" "Enable Google social login (OAuth2)" "release"
delete_all_strategies "auth.social_login.google"
add_strategy "auth.social_login.google" '{
  "name": "flexibleRollout",
  "title": "gradual 20% rollout",
  "constraints": [],
  "parameters": {
    "rollout": "20",
    "stickiness": "userId",
    "groupId": "auth.social_login.google"
  }
}'
# 注：dev 环境保持 disabled（测试时手动开）

# ---------------------------------------------------------------------------
# 3. auth.social_login.github
# ---------------------------------------------------------------------------
upsert_flag "auth.social_login.github" "Enable GitHub social login (OAuth2)" "release"
delete_all_strategies "auth.social_login.github"
add_strategy "auth.social_login.github" '{
  "name": "default",
  "title": "default off",
  "constraints": [],
  "parameters": {}
}'

# ---------------------------------------------------------------------------
# 4. auth.social_login.wechat
# ---------------------------------------------------------------------------
upsert_flag "auth.social_login.wechat" "Enable WeChat social login (OAuth2)" "release"
delete_all_strategies "auth.social_login.wechat"
add_strategy "auth.social_login.wechat" '{
  "name": "default",
  "title": "default off",
  "constraints": [],
  "parameters": {}
}'

# ---------------------------------------------------------------------------
# 5. compliance.gmtls_enabled
# ---------------------------------------------------------------------------
upsert_flag "compliance.gmtls_enabled" "Enable 国密 TLS (GMTLS / SM2-TLS)" "kill-switch"
delete_all_strategies "compliance.gmtls_enabled"
add_strategy "compliance.gmtls_enabled" '{
  "name": "default",
  "title": "default off",
  "constraints": [],
  "parameters": {}
}'

# ---------------------------------------------------------------------------
# 6. compliance.sm_algorithms
# ---------------------------------------------------------------------------
upsert_flag "compliance.sm_algorithms" "Enable SM2/SM3/SM4 algorithms (国密)" "kill-switch"
delete_all_strategies "compliance.sm_algorithms"
add_strategy "compliance.sm_algorithms" '{
  "name": "default",
  "title": "default off",
  "constraints": [],
  "parameters": {}
}'

# ---------------------------------------------------------------------------
# 7. export.allow_l4_download
# ---------------------------------------------------------------------------
upsert_flag "export.allow_l4_download" "Allow L4 classified data download (高风险)" "kill-switch"
delete_all_strategies "export.allow_l4_download"
add_strategy "export.allow_l4_download" '{
  "name": "default",
  "title": "default off",
  "constraints": [],
  "parameters": {}
}'

# ---------------------------------------------------------------------------
# 8. ai.thinking_ui
#    策略: 全量放开（100%）
# ---------------------------------------------------------------------------
upsert_flag "ai.thinking_ui" "Show AI thinking/reasoning UI steps" "release"
delete_all_strategies "ai.thinking_ui"
add_strategy "ai.thinking_ui" '{
  "name": "flexibleRollout",
  "title": "full rollout 100%",
  "constraints": [],
  "parameters": {
    "rollout": "100",
    "stickiness": "default",
    "groupId": "ai.thinking_ui"
  }
}'
enable_flag_in_env "ai.thinking_ui"

log "=========================================="
log "All flags synced. Summary:"
log "  billing.saas_mode       → tier IN [PRO,ENTERPRISE], ENABLED"
log "  auth.social_login.google → 20% gradual rollout, DISABLED"
log "  auth.social_login.github → default off, DISABLED"
log "  auth.social_login.wechat → default off, DISABLED"
log "  compliance.gmtls_enabled → kill-switch, DISABLED"
log "  compliance.sm_algorithms → kill-switch, DISABLED"
log "  export.allow_l4_download → kill-switch, DISABLED"
log "  ai.thinking_ui           → 100% rollout, ENABLED"
log "=========================================="
log "Done."
