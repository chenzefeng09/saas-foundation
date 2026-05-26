SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

POETRY := poetry
PORT := 8005

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

.PHONY: install
install: ## poetry install
	$(POETRY) install

.PHONY: lint
lint: ## ruff check + mypy
	$(POETRY) run ruff check src tests
	$(POETRY) run mypy src

.PHONY: format
format:
	$(POETRY) run ruff format src tests

.PHONY: test
test:
	$(POETRY) run pytest

.PHONY: test-unit
test-unit:
	$(POETRY) run pytest -m unit

.PHONY: run
run: ## 本地 dev server
	$(POETRY) run uvicorn foundation_audit.main:app --host 0.0.0.0 --port $(PORT) --reload

.PHONY: worker
worker: ## 启动 batch worker
	$(POETRY) run python -c "import asyncio; from foundation_audit.worker.batch_processor import BatchProcessor; asyncio.run(BatchProcessor().run_forever())"

.PHONY: migrate
migrate:
	$(POETRY) run alembic upgrade head

.PHONY: docker
docker:
	docker build -t foundation-audit:dev .

.PHONY: clean
clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov dist build .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
