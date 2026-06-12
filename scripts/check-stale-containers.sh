#!/usr/bin/env bash
#
# check-stale-containers.sh — detect locally-built containers running stale code.
#
# WHAT THIS DOES
#   For each Docker service that is built from LOCAL SOURCE (has a `build:` section
#   in its compose file), compare:
#       (A) the build time of the image the container is *actually running*
#     vs
#       (B) the most recent change time of that service's source code
#           (git last-commit time, AND a filesystem fallback that catches
#            uncommitted/un-staged edits).
#   If the source changed AFTER the image was built, the container is running old
#   code and is flagged STALE → it should be rebuilt.
#
# SCOPE / CAVEATS
#   - Only meaningful for services built from local source. Pure image-pull
#     third-party services (postgres, redis, minio, prometheus, otel, keycloak,
#     vault, …) are NOT in the service map below and are never judged.
#   - The judgment baseline is: image build time vs source change time.
#   - The remedy for a STALE service is simply to rebuild + recreate that one
#     container (the exact command is printed at the end for every STALE row).
#   - "Source change time" is taken over each service's precise source subdir
#     (e.g. packages/lifecycle), not the whole repo, to avoid false positives.
#     The foundation dev.yml copies packages into /tmp before `poetry install`,
#     so several services share build context = packages/ ; we still scope the
#     staleness check to the individual package subdir.
#
# USAGE
#   ./scripts/check-stale-containers.sh
#   (no arguments; reads live Docker state + the two repos' git/filesystem)
#
# REQUIREMENTS: docker, git, bash, GNU/BSD find (uses -newermt).
#
set -uo pipefail

# ---------------------------------------------------------------------------
# Service map. One line per service that is built from local source.
# Fields (pipe-separated):
#   repo_root | compose_file (relative to repo_root) | service | container |
#   source_subdir (relative to repo_root)
#
# *-migrate one-shot containers are intentionally omitted: they reuse the main
# service's image and source, so the main service's row already covers them.
# ---------------------------------------------------------------------------
FOUNDATION_ROOT="/Users/chenzefeng/Development/saas-foundation"
AGENT_ROOT="/Users/chenzefeng/Development/agent-platform"
FOUNDATION_COMPOSE="deploy/docker-compose/dev.yml"
AGENT_COMPOSE="deploy/docker-compose/agent-platform.yml"

SERVICES=(
  # --- saas-foundation (compose: dev.yml) ---
  "$FOUNDATION_ROOT|$FOUNDATION_COMPOSE|api-platform|foundation-api-platform|packages/api-platform"
  "$FOUNDATION_ROOT|$FOUNDATION_COMPOSE|audit|foundation-audit|packages/audit"
  "$FOUNDATION_ROOT|$FOUNDATION_COMPOSE|audit-worker|foundation-audit-worker|packages/audit"
  "$FOUNDATION_ROOT|$FOUNDATION_COMPOSE|authz|foundation-authz|packages/authz"
  "$FOUNDATION_ROOT|$FOUNDATION_COMPOSE|billing|foundation-billing|packages/billing"
  "$FOUNDATION_ROOT|$FOUNDATION_COMPOSE|compliance|foundation-compliance|packages/compliance"
  "$FOUNDATION_ROOT|$FOUNDATION_COMPOSE|crypto|foundation-crypto|packages/crypto"
  "$FOUNDATION_ROOT|$FOUNDATION_COMPOSE|data-protection|foundation-data-protection|packages/data-protection"
  "$FOUNDATION_ROOT|$FOUNDATION_COMPOSE|dlp|foundation-dlp|packages/dlp"
  "$FOUNDATION_ROOT|$FOUNDATION_COMPOSE|feature-flag|foundation-feature-flag|packages/feature-flag"
  "$FOUNDATION_ROOT|$FOUNDATION_COMPOSE|identity|foundation-identity|packages/identity"
  "$FOUNDATION_ROOT|$FOUNDATION_COMPOSE|lifecycle|foundation-lifecycle|packages/lifecycle"
  "$FOUNDATION_ROOT|$FOUNDATION_COMPOSE|llm-gateway|foundation-llm-gateway|packages/llm-gateway"
  "$FOUNDATION_ROOT|$FOUNDATION_COMPOSE|notification|foundation-notification|packages/notification"
  "$FOUNDATION_ROOT|$FOUNDATION_COMPOSE|org|foundation-org|packages/org"
  "$FOUNDATION_ROOT|$FOUNDATION_COMPOSE|pam|foundation-pam|packages/pam"
  "$FOUNDATION_ROOT|$FOUNDATION_COMPOSE|search|foundation-search|packages/search"
  "$FOUNDATION_ROOT|$FOUNDATION_COMPOSE|security-ops|foundation-security-ops|packages/security-ops"

  # --- agent-platform (compose: agent-platform.yml) ---
  "$AGENT_ROOT|$AGENT_COMPOSE|agent-scheduler|agent-scheduler|services/agent-scheduler"
  "$AGENT_ROOT|$AGENT_COMPOSE|app-registry|agent-app-registry|services/app-registry"
  "$AGENT_ROOT|$AGENT_COMPOSE|bff|agent-bff|services/bff"
  "$AGENT_ROOT|$AGENT_COMPOSE|knowledge-ingest|agent-knowledge-ingest|services/knowledge-ingest"
  "$AGENT_ROOT|$AGENT_COMPOSE|mcp-registry|agent-mcp-registry|services/mcp-registry"
  "$AGENT_ROOT|$AGENT_COMPOSE|sandbox-pool|agent-sandbox-pool|services/sandbox-pool"
  "$AGENT_ROOT|$AGENT_COMPOSE|session-orchestrator|agent-session-orchestrator|services/session-orchestrator"
  "$AGENT_ROOT|$AGENT_COMPOSE|skill-store|agent-skill-store|services/skill-store"
  "$AGENT_ROOT|$AGENT_COMPOSE|web|agent-web|apps/web"
  "$AGENT_ROOT|$AGENT_COMPOSE|web-fetch-gateway|agent-web-fetch-gateway|services/web-fetch-gateway"
)

# Directory name patterns to ignore in the filesystem fallback scan.
FIND_PRUNE=( -name .git -o -name node_modules -o -name __pycache__ -o -name .venv -o -name .mypy_cache -o -name .pytest_cache -o -name .next -o -name dist )

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
iso_to_epoch() {
  # Convert an ISO-8601 timestamp to epoch seconds (GNU date, then BSD date).
  local ts="$1"
  date -d "$ts" +%s 2>/dev/null && return 0
  # BSD date: strip fractional seconds and normalize timezone
  local clean; clean="$(echo "$ts" | sed -E 's/\.[0-9]+//; s/Z$/+0000/; s/([+-][0-9]{2}):([0-9]{2})$/\1\2/')"
  date -j -f "%Y-%m-%dT%H:%M:%S%z" "$clean" +%s 2>/dev/null && return 0
  echo ""
}

epoch_to_human() {
  local e="$1"
  [ -z "$e" ] && { echo "-"; return; }
  date -r "$e" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || date -d "@$e" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "$e"
}

# ANSI colors (only if stdout is a tty)
if [ -t 1 ]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'; C_RST=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_DIM=""; C_BOLD=""; C_RST=""
fi

# ---------------------------------------------------------------------------
# Collect results
# ---------------------------------------------------------------------------
declare -a ROWS=()          # display rows: status|svc|container|img_human|src_human
declare -a STALE_CMDS=()    # rebuild commands for STALE services
declare -a STALE_DETAIL=()  # "why stale" detail lines

for entry in "${SERVICES[@]}"; do
  IFS='|' read -r repo compose svc container subdir <<<"$entry"
  src_dir="$repo/$subdir"

  # --- container running? ---
  state="$(docker inspect -f '{{.State.Status}}' "$container" 2>/dev/null)"
  if [ -z "$state" ]; then
    ROWS+=("MISSING|$svc|$container|-|-")
    continue
  fi
  if [ "$state" != "running" ]; then
    ROWS+=("NOTRUN|$svc|$container ($state)|-|-")
    continue
  fi

  # --- running image build time (use the image the container actually runs) ---
  img_id="$(docker inspect -f '{{.Image}}' "$container" 2>/dev/null)"
  img_created_iso="$(docker inspect -f '{{.Created}}' "$img_id" 2>/dev/null)"
  img_epoch="$(iso_to_epoch "$img_created_iso")"
  # container's own creation time, for reference
  cont_created_iso="$(docker inspect -f '{{.Created}}' "$container" 2>/dev/null)"

  if [ -z "$img_epoch" ]; then
    ROWS+=("NOTRUN|$svc|$container (no image time)|-|-")
    continue
  fi

  # --- source change time: git last commit touching the subdir ---
  git_iso=""
  git_short=""
  if [ -d "$src_dir" ] && git -C "$repo" rev-parse --git-dir >/dev/null 2>&1; then
    git_iso="$(git -C "$repo" log -1 --format=%cI -- "$subdir" 2>/dev/null)"
    git_short="$(git -C "$repo" log -1 --format='%h %cs %s' -- "$subdir" 2>/dev/null)"
  fi
  git_epoch="$(iso_to_epoch "$git_iso")"

  # --- filesystem fallback: files newer than the image (catches uncommitted) ---
  newer_files=""
  if [ -d "$src_dir" ]; then
    newer_files="$(find "$src_dir" -type d \( "${FIND_PRUNE[@]}" \) -prune -o \
                     -type f -newermt "@$img_epoch" -print 2>/dev/null | head -5)"
  fi

  # --- decide ---
  stale=0
  reasons=()
  if [ -n "$git_epoch" ] && [ "$git_epoch" -gt "$img_epoch" ]; then
    stale=1
    reasons+=("git: commit ${git_short:-?} is newer than image")
  fi
  if [ -n "$newer_files" ]; then
    stale=1
    reasons+=("fs: files changed after image build (e.g. $(echo "$newer_files" | sed "s#$repo/##" | tr '\n' ',' | sed 's/,$//'))")
  fi

  img_human="$(epoch_to_human "$img_epoch")"
  if [ -n "$git_epoch" ]; then
    src_human="$(epoch_to_human "$git_epoch")"
  else
    src_human="(no git history)"
  fi

  if [ "$stale" -eq 1 ]; then
    ROWS+=("STALE|$svc|$container|$img_human|$src_human")
    STALE_CMDS+=("$repo|$compose|$svc")
    for r in "${reasons[@]}"; do
      STALE_DETAIL+=("$svc :: $r")
    done
  else
    ROWS+=("OK|$svc|$container|$img_human|$src_human")
  fi
done

# ---------------------------------------------------------------------------
# Render table (STALE first, then NOTRUN/MISSING, then OK)
# ---------------------------------------------------------------------------
print_row() {
  local status="$1" svc="$2" cont="$3" img="$4" src="$5"
  local badge color
  case "$status" in
    STALE)   color="$C_RED";  badge="STALE" ;;
    OK)      color="$C_GRN";  badge="OK" ;;
    NOTRUN)  color="$C_YEL";  badge="NOT-RUNNING" ;;
    MISSING) color="$C_DIM";  badge="NO-CONTAINER" ;;
  esac
  printf "%s%-12s%s %-22s %-38s %-21s %-21s\n" \
    "$color" "$badge" "$C_RST" "$svc" "$cont" "$img" "$src"
}

echo
echo "${C_BOLD}Stale-container inspection — image build time vs source change time${C_RST}"
echo "${C_DIM}Generated: $(date '+%Y-%m-%d %H:%M:%S %Z')${C_RST}"
echo
printf "%-12s %-22s %-38s %-21s %-21s\n" "STATUS" "SERVICE" "CONTAINER" "IMAGE BUILT" "SOURCE CHANGED"
printf '%.0s-' {1..118}; echo

for order in STALE NOTRUN MISSING OK; do
  for row in "${ROWS[@]}"; do
    IFS='|' read -r st svc cont img src <<<"$row"
    [ "$st" = "$order" ] && print_row "$st" "$svc" "$cont" "$img" "$src"
  done
done

# ---------------------------------------------------------------------------
# Summary + remediation
# ---------------------------------------------------------------------------
echo
n_stale=${#STALE_CMDS[@]}
if [ "$n_stale" -eq 0 ]; then
  echo "${C_GRN}${C_BOLD}All running local-build containers are up to date with their source.${C_RST}"
else
  echo "${C_RED}${C_BOLD}$n_stale service(s) STALE — running older code than the source.${C_RST}"
  echo
  echo "${C_BOLD}Why:${C_RST}"
  for d in "${STALE_DETAIL[@]}"; do
    echo "  - $d"
  done
  echo
  echo "${C_BOLD}Rebuild commands (run from each repo root):${C_RST}"
  for c in "${STALE_CMDS[@]}"; do
    IFS='|' read -r repo compose svc <<<"$c"
    echo "  ${C_DIM}# repo: $repo${C_RST}"
    echo "  docker compose -f $compose build $svc && docker compose -f $compose up -d --no-deps $svc"
  done
fi
echo
