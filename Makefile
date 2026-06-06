# =============================================================================
# saas-foundation 顶层 Makefile
#
# 用 make help 查看所有命令
# 单 service 命令：make -C packages/identity test
# =============================================================================

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.ONESHELL:
.DEFAULT_GOAL := help

COMPOSE_FILE := deploy/docker-compose/dev.yml
COMPOSE := docker compose -f $(COMPOSE_FILE) --env-file deploy/docker-compose/.env

PACKAGES := $(shell find packages -mindepth 1 -maxdepth 1 -type d -not -name '.*' 2>/dev/null)
PACKAGE_SRC_PATHS := $(shell find $(CURDIR)/packages -mindepth 2 -maxdepth 2 -type d -name src 2>/dev/null | paste -sd ':' -)
POETRY_VIRTUALENVS_PATH ?= $(or $(TMPDIR),/tmp)/poetry-venvs
export POETRY_VIRTUALENVS_PATH
PYTHONPATH ?= src:$(PACKAGE_SRC_PATHS)
export PYTHONPATH

# Colorize
BOLD := \033[1m
GREEN := \033[32m
YELLOW := \033[33m
RED := \033[31m
RESET := \033[0m

.PHONY: help
help: ## 显示本帮助
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-22s$(RESET) %s\n", $$1, $$2}'

# -----------------------------------------------------------------------------
# 本地开发栈
# -----------------------------------------------------------------------------
.PHONY: env
env: ## 复制 .env.example 到 .env（若不存在）
	@if [ ! -f deploy/docker-compose/.env ]; then \
	  cp deploy/docker-compose/.env.example deploy/docker-compose/.env; \
	  echo "$(YELLOW)Created deploy/docker-compose/.env — adjust passwords before prod use$(RESET)"; \
	fi

.PHONY: up
up: env ## 起本地开发栈（postgres/keycloak/clickhouse/...）
	$(COMPOSE) up -d
	@echo "$(GREEN)Stack starting. Run 'make ps' to check.$(RESET)"

.PHONY: up-full
up-full: up ## 起栈 + 等容器就绪 + post-up-init + healthcheck (一条龙)
	@echo "$(YELLOW)Waiting for keycloak (up to 3 min)...$(RESET)"
	@i=0; until curl -sf http://localhost:8080/realms/foundation/.well-known/openid-configuration >/dev/null 2>&1; do \
	  i=$$((i+5)); [ $$i -gt 180 ] && echo "$(RED)keycloak realm not ready$(RESET)" && exit 1; \
	  sleep 5; printf "."; \
	done; echo ""
	@bash tools/dev/post-up-init.sh
	@bash tools/dev/healthcheck.sh

.PHONY: post-up-init
post-up-init: ## 业务级初始化（Vault transit / MinIO buckets / KC Organizations）
	@bash tools/dev/post-up-init.sh

.PHONY: down
down: ## 停服务保留数据
	$(COMPOSE) down

.PHONY: nuke
nuke: ## ⚠️ 停服务 + 删数据卷（不可恢复）
	@read -p "$(RED)This destroys all local DB data. Continue? [y/N] $(RESET)" confirm; \
	if [ "$$confirm" = "y" ]; then $(COMPOSE) down -v; fi

.PHONY: ps
ps: ## 看本地栈状态
	$(COMPOSE) ps

.PHONY: logs
logs: ## 跟随某 service 日志（make logs SVC=keycloak）
	$(COMPOSE) logs -f $(SVC)

.PHONY: psql
psql: ## 进入 Postgres（postgres super 用户）
	$(COMPOSE) exec postgres psql -U postgres -d foundation

.PHONY: psql-pgbouncer
psql-pgbouncer: ## 通过 PgBouncer 进 foundation 库（app_user）
	docker run --rm -it --network saas-foundation-dev_foundation postgres:16-alpine \
	  psql "host=foundation-pgbouncer port=6432 user=app_user password=app_user_change_me dbname=foundation"

.PHONY: clickhouse
clickhouse: ## 进 ClickHouse client
	$(COMPOSE) exec clickhouse clickhouse-client

.PHONY: healthcheck
healthcheck: ## 跑本地栈所有 service 的健康检查
	@bash tools/dev/healthcheck.sh

# -----------------------------------------------------------------------------
# 代码质量（跨所有 package）
# -----------------------------------------------------------------------------
.PHONY: lint
lint: ## ruff check + mypy（所有 package）
	@for pkg in $(PACKAGES); do \
	  echo "$(BOLD)→ $$pkg$(RESET)"; \
	  $(MAKE) -C $$pkg lint || exit 1; \
	done

.PHONY: format
format: ## ruff format（所有 package）
	@for pkg in $(PACKAGES); do \
	  echo "$(BOLD)→ $$pkg$(RESET)"; \
	  $(MAKE) -C $$pkg format || exit 1; \
	done

.PHONY: test
test: ## pytest（所有 package）
	@for pkg in $(PACKAGES); do \
	  echo "$(BOLD)→ $$pkg$(RESET)"; \
	  if [ -f $$pkg/Makefile ]; then \
	    $(MAKE) -C $$pkg test || exit 1; \
	  elif [ -f $$pkg/pyproject.toml ]; then \
	    cd $$pkg && poetry run pytest || exit 1; \
	    cd - > /dev/null; \
	  else \
	    echo "$(YELLOW)skip $$pkg: no Makefile or pyproject.toml$(RESET)"; \
	  fi; \
	done

.PHONY: test-rls-fuzz
test-rls-fuzz: ## 跑 RLS 越权 fuzz（所有 package 的 tests/security/）
	@for pkg in $(PACKAGES); do \
	  if [ -d $$pkg/tests/security ]; then \
	    echo "$(BOLD)→ $$pkg$(RESET)"; \
	    cd $$pkg && poetry run pytest tests/security/ -v && cd - > /dev/null; \
	  fi \
	done

# -----------------------------------------------------------------------------
# 数据库
# -----------------------------------------------------------------------------
.PHONY: migrate
migrate: ## 跑所有 package 的 alembic upgrade head（app_migrator）
	@export DATABASE_URL=postgres://app_migrator:app_migrator_change_me@localhost:5432/foundation; \
	for pkg in $(PACKAGES); do \
	  if [ -d $$pkg/migrations ]; then \
	    echo "$(BOLD)→ Migrate $$pkg$(RESET)"; \
	    cd $$pkg && poetry run alembic upgrade head && cd - > /dev/null; \
	  fi \
	done

.PHONY: seed
seed: ## 给本地栈塞测试数据（dev tenant + 测试用户）
	@bash tools/dev/seed.sh

# -----------------------------------------------------------------------------
# 安全扫描（本地跑 CI 的子集）
# -----------------------------------------------------------------------------
.PHONY: scan
scan: scan-secrets scan-sast scan-license ## 跑全套安全扫描

.PHONY: scan-secrets
scan-secrets: ## gitleaks
	docker run --rm -v $$(pwd):/repo ghcr.io/gitleaks/gitleaks:latest detect \
	  --source=/repo --config=/repo/tools/ci/gitleaks.toml -v

.PHONY: opa-test
.PHONY: opa-eval
.PHONY: up-full
.PHONY: post-up-init
.PHONY: scan-sast
scan-sast: ## semgrep
	docker run --rm -v $$(pwd):/src semgrep/semgrep semgrep \
	  --config=p/python --config=p/owasp-top-ten \
	  --config=/src/tools/ci/semgrep-rules.yaml \
	  --severity=ERROR --severity=WARNING \
	  --exclude='tests/' --exclude='_template/' /src

.PHONY: scan-license
scan-license: ## pip-licenses
	@for pkg in $(PACKAGES); do \
	  if [ -f $$pkg/pyproject.toml ]; then \
	    cd $$pkg && poetry run pip-licenses \
	      --fail-on="GPL;AGPL;LGPL-2.0;LGPL-2.1;LGPL-3.0" \
	      --format=plain || exit 1; \
	    cd - > /dev/null; \
	  fi \
	done

.PHONY: sbom
sbom: ## 生成 SBOM (CycloneDX + SPDX)
	docker run --rm -v $$(pwd):/src anchore/syft dir:/src \
	  -o cyclonedx-json=/src/sbom.cdx.json \
	  -o spdx-json=/src/sbom.spdx.json
	@echo "$(GREEN)SBOM: sbom.cdx.json + sbom.spdx.json$(RESET)"

# -----------------------------------------------------------------------------
# Helm
# -----------------------------------------------------------------------------
.PHONY: opa-test
opa-test: ## OPA 策略单元测试（用 docker 跑 opa test）
	docker run --rm -v $$(pwd)/deploy/docker-compose/config/opa:/work \
	  openpolicyagent/opa:0.68.0-rootless test /work/policies/ -v

.PHONY: opa-eval
opa-eval: ## OPA 本地评估示例（环境变量 INPUT 传 JSON）
	@curl -sf -X POST http://localhost:8181/v1/data/foundation/authz/allow \
	  -H 'Content-Type: application/json' \
	  -d "$${INPUT:-{\"input\":{\"policy_id\":\"x\",\"action\":\"x\",\"user\":{\"tenant_id\":\"tnt_a\",\"role_grants\":[]},\"resource\":{\"tenant_id\":\"tnt_a\"},\"tenant\":{\"compliance_modes\":[\"pipl\"],\"data_residency\":\"cn-only\"},\"request\":{\"mfa_satisfied\":true,\"country\":\"CN\",\"destination_country\":\"CN\"},\"permission_definition\":{\"risk_level\":\"LOW\"},\"now\":\"2026-05-22T10:00:00Z\"}}}" | python3 -m json.tool

.PHONY: helm-lint
helm-lint: ## helm lint 三档 profile
	cd deploy/helm/foundation && helm dependency update
	@for p in small medium large; do \
	  echo "$(BOLD)→ profile=$$p$(RESET)"; \
	  cd deploy/helm/foundation && helm lint . -f values-$$p.yaml && cd - > /dev/null; \
	done

.PHONY: helm-render
helm-render: ## helm template 渲染（默认 small；make helm-render PROFILE=medium）
	cd deploy/helm/foundation && helm dependency update
	cd deploy/helm/foundation && helm template foundation . \
	  -f values-$(or $(PROFILE),small).yaml \
	  --namespace foundation \
	  > /tmp/foundation-render-$(or $(PROFILE),small).yaml
	@echo "$(GREEN)Rendered to /tmp/foundation-render-$(or $(PROFILE),small).yaml$(RESET)"

# -----------------------------------------------------------------------------
# 集成测试（docker-compose 全栈）
# -----------------------------------------------------------------------------
INTEGRATION_COMPOSE := docker compose -f deploy/docker-compose/dev.yml -f deploy/docker-compose/integration.yml --env-file deploy/docker-compose/.env

.PHONY: integration-up
integration-up: env ## 起集成测试全栈（基础设施 + 4 foundation 服务）
	$(INTEGRATION_COMPOSE) up -d --wait postgres pgbouncer keycloak vault opa
	$(INTEGRATION_COMPOSE) run --rm vault-init
	$(INTEGRATION_COMPOSE) build identity authz org crypto integration-runner
	$(INTEGRATION_COMPOSE) up -d identity authz org crypto
	@echo "$(GREEN)Integration stack starting... run 'make integration-ps' to check.$(RESET)"

.PHONY: integration-ps
integration-ps: ## 看集成测试栈状态
	$(INTEGRATION_COMPOSE) ps

.PHONY: integration-test
integration-test: ## 跑集成测试（需要先 make integration-up）
	$(INTEGRATION_COMPOSE) run --rm integration-runner

.PHONY: integration-down
integration-down: ## 停集成测试栈 + 清数据
	$(INTEGRATION_COMPOSE) down -v

.PHONY: integration-all
integration-all: env ## 一条龙：起栈 → 等就绪 → 跑测试 → 清栈
	@echo "$(BOLD)=== Integration Test Suite ===$(RESET)"
	$(INTEGRATION_COMPOSE) up -d --wait postgres pgbouncer keycloak vault opa
	$(INTEGRATION_COMPOSE) run --rm vault-init
	$(INTEGRATION_COMPOSE) build identity authz org crypto integration-runner
	$(INTEGRATION_COMPOSE) up -d identity authz org crypto
	@echo "$(YELLOW)Waiting for services (up to 60s)...$(RESET)"
	@for i in {1..30}; do \
	  ok=0; \
	  for port in 8001 8002 8003 8004; do \
	    curl -sf http://localhost:$$port/healthz >/dev/null 2>&1 && ok=$$((ok+1)) || true; \
	  done; \
	  if [ $$ok -eq 4 ]; then echo "$(GREEN)All 4 services healthy$(RESET)"; break; fi; \
	  echo "  $$ok/4 healthy ($$i/30)"; sleep 2; \
	done
	$(INTEGRATION_COMPOSE) run --rm integration-runner || TEST_EXIT=$$?
	@echo ""
	@echo "$(BOLD)=== Test suite exit: $${TEST_EXIT:-0} ===$(RESET)"
	@echo "$(YELLOW)Stack still running. Run 'make integration-down' to clean up.$(RESET)"

# -----------------------------------------------------------------------------
# foundation-sdk 发布（详见 docs/sdk-release.md）
# -----------------------------------------------------------------------------
SDK_DIR := sdks/python

.PHONY: sdk-build
sdk-build: ## 构建 foundation-sdk wheel + sdist 到 sdks/python/dist/
	cd $(SDK_DIR) && ./build.sh

.PHONY: sdk-publish-dry
sdk-publish-dry: sdk-build ## twine check，不上传（用于 PR 验证）
	cd $(SDK_DIR) && ./publish.sh --dry-run

.PHONY: sdk-publish
sdk-publish: sdk-build ## 上传到内部 PyPI（需 FOUNDATION_PYPI_URL/TOKEN）
	@test -n "$$FOUNDATION_PYPI_URL"   || { echo "$(RED)FOUNDATION_PYPI_URL not set$(RESET)"; exit 1; }
	@test -n "$$FOUNDATION_PYPI_TOKEN" || { echo "$(RED)FOUNDATION_PYPI_TOKEN not set$(RESET)"; exit 1; }
	cd $(SDK_DIR) && ./publish.sh

# -----------------------------------------------------------------------------
# 文档
# -----------------------------------------------------------------------------
.PHONY: docs-serve
docs-serve: ## 本地起 markdown 文档预览（http://localhost:8000）
	cd docs && python3 -m http.server 8000

# -----------------------------------------------------------------------------
# 杂项
# -----------------------------------------------------------------------------
.PHONY: clean
clean: ## 清掉 __pycache__ / .venv / dist 等
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type d -name .pytest_cache -prune -exec rm -rf {} +
	find . -type d -name .mypy_cache -prune -exec rm -rf {} +
	find . -type d -name .ruff_cache -prune -exec rm -rf {} +
	find . -type d -name dist -prune -exec rm -rf {} +
	find . -type d -name '*.egg-info' -prune -exec rm -rf {} +
