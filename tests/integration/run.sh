#!/usr/bin/env bash
# =============================================================================
# saas-foundation 集成测试运行脚本
#
# 用法：
#   cd deploy/docker-compose
#   cp .env.example .env
#   bash ../../tests/integration/run.sh
#
# 或者分步运行：
#   bash ../../tests/integration/run.sh up       # 启动基础设施
#   bash ../../tests/integration/run.sh migrate   # 跑数据库迁移
#   bash ../../tests/integration/run.sh test      # 跑集成测试
#   bash ../../tests/integration/run.sh down      # 完整清理
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_DIR="$REPO_ROOT/deploy/docker-compose"

COMPOSE_CMD="docker compose -f dev.yml -f integration.yml"

cd "$COMPOSE_DIR"

case "${1:-all}" in
  up)
    echo "=== Starting infrastructure ==="
    $COMPOSE_CMD up -d postgres pgbouncer redis keycloak vault opa clickhouse minio unleash jaeger otel-collector mailhog
    echo ""
    echo "=== Waiting for infrastructure healthy ==="
    $COMPOSE_CMD ps
    ;;
  vault-init)
    echo "=== Initialising Vault transit engine ==="
    $COMPOSE_CMD run --rm vault-init
    ;;
  build)
    echo "=== Building foundation service images ==="
    $COMPOSE_CMD build identity authz org crypto
    ;;
  migrate)
    echo "=== Running Alembic migrations ==="
    echo "  Note: in the current setup, each service runs its own migration on startup."
    echo "  If you need to run migrations manually:"
    echo "    cd packages/<service> && poetry run alembic upgrade head"
    ;;
  start-services)
    echo "=== Starting foundation services ==="
    $COMPOSE_CMD up -d identity authz org crypto
    echo ""
    echo "=== Waiting for services healthy ==="
    for i in {1..30}; do
      if curl -sf http://localhost:8001/healthz > /dev/null && \
         curl -sf http://localhost:8002/healthz > /dev/null && \
         curl -sf http://localhost:8003/healthz > /dev/null && \
         curl -sf http://localhost:8004/healthz > /dev/null; then
        echo "All services healthy!"
        break
      fi
      echo "  Waiting... ($i/30)"
      sleep 2
    done
    ;;
  test)
    echo "=== Running integration tests ==="
    $COMPOSE_CMD run --rm integration-runner
    ;;
  all)
    echo "============================================="
    echo "  saas-foundation Integration Test Suite"
    echo "============================================="
    echo ""

    # 1. Infrastructure
    echo "--- Step 1/5: Starting infrastructure ---"
    $COMPOSE_CMD up -d --wait postgres pgbouncer redis keycloak vault opa

    # 2. Vault init
    echo ""
    echo "--- Step 2/5: Initialising Vault ---"
    $COMPOSE_CMD run --rm vault-init

    # 3. Build services
    echo ""
    echo "--- Step 3/5: Building service images ---"
    $COMPOSE_CMD build identity authz org crypto integration-runner

    # 4. DB migrations
    echo ""
    echo "--- Step 4/5: Running DB migrations ---"
    # Run migrations for each service directly
    for svc in identity authz org crypto; do
      echo "  Migrating $svc..."
      docker run --rm \
        --network saas-foundation-dev_foundation \
        -e "${svc^^}_DB_DSN_MIGRATOR=postgresql+asyncpg://app_migrator:${APP_MIGRATOR_PASSWORD:-app_migrator_change_me}@postgres:5432/foundation" \
        -e "CRYPTO_VAULT_URL=http://vault:8200" \
        -e "CRYPTO_VAULT_TOKEN=${VAULT_DEV_ROOT_TOKEN:-dev-root-token-change-me}" \
        -v "$REPO_ROOT/packages/$svc/migrations:/app/migrations:ro" \
        -v "$REPO_ROOT/packages/$svc/alembic.ini:/app/alembic.ini:ro" \
        "foundation-${svc}:latest" \
        python -m alembic upgrade head || echo "  (migration may have already run on startup)"
    done

    # 5. Start services and run tests
    echo ""
    echo "--- Step 5/5: Starting services and running tests ---"
    $COMPOSE_CMD up -d identity authz org crypto

    # Wait for services
    echo "  Waiting for services..."
    for i in {1..30}; do
      healthy=0
      for port in 8001 8002 8003 8004; do
        curl -sf "http://localhost:${port}/healthz" > /dev/null && ((healthy++)) || true
      done
      if [ "$healthy" -eq 4 ]; then
        echo "  All 4 services healthy!"
        break
      fi
      echo "    ${healthy}/4 healthy, waiting... ($i/30)"
      sleep 2
    done

    # Run tests
    echo ""
    echo "=== Running integration tests ==="
    $COMPOSE_CMD run --rm integration-runner
    TEST_EXIT=$?

    echo ""
    echo "=== Integration test suite complete (exit=$TEST_EXIT) ==="
    exit $TEST_EXIT
    ;;
  down)
    echo "=== Cleaning up ==="
    $COMPOSE_CMD down -v
    ;;
  *)
    echo "Usage: $0 {up|vault-init|build|migrate|start-services|test|all|down}"
    exit 1
    ;;
esac
