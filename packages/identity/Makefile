# =============================================================================
# foundation-identity Makefile
# =============================================================================

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

POETRY := poetry
PORT := 8001

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

.PHONY: install
install: ## poetry install
	$(POETRY) install

.PHONY: lock
lock: ## 重新生成 poetry.lock
	$(POETRY) lock --no-update

.PHONY: format
format: ## ruff format
	$(POETRY) run ruff format src tests

.PHONY: lint
lint: ## ruff check + mypy
	$(POETRY) run ruff check src tests
	$(POETRY) run mypy src

.PHONY: lint-fix
lint-fix:
	$(POETRY) run ruff check --fix src tests

.PHONY: test
test: ## 全部
	$(POETRY) run pytest

.PHONY: test-unit
test-unit: ## 仅单元
	$(POETRY) run pytest -m unit

.PHONY: test-integration
test-integration: ## 仅集成（需 postgres）
	$(POETRY) run pytest -m integration

.PHONY: cov
cov: ## 覆盖率
	$(POETRY) run pytest --cov --cov-report=html
	@echo "open htmlcov/index.html"

.PHONY: run
run: ## 本地启动 dev server (reload)
	$(POETRY) run uvicorn foundation_identity.main:app \
	  --host 0.0.0.0 --port $(PORT) --reload

.PHONY: migrate
migrate: ## 应用迁移
	$(POETRY) run alembic upgrade head

.PHONY: migrate-down
migrate-down: ## 回退一步
	$(POETRY) run alembic downgrade -1

.PHONY: migrate-rev
migrate-rev: ## 生成迁移：make migrate-rev MSG="add x"
	$(POETRY) run alembic revision --autogenerate -m "$(MSG)"

.PHONY: docker
docker: ## 本地构建镜像
	docker build -t foundation-identity:dev .

.PHONY: clean
clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov dist build .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
