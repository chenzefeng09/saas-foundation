SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

POETRY := poetry

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
format: ## ruff format
	$(POETRY) run ruff format src tests

.PHONY: test
test: ## pytest with coverage
	$(POETRY) run pytest tests/unit --cov=foundation_storage --cov-fail-under=80 -v

.PHONY: run
run: ## library package — no app to run
	@echo "foundation-storage is a pure library; nothing to run."
