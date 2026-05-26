# =============================================================================
# OpenAPI contracts — Makefile
# =============================================================================
# 跑法（在 contracts/openapi/ 目录或 repo root 都可）：
#   make help            # 列命令
#   make lint            # spectral 校验所有 spec
#   make bundle          # redocly bundle 内联 $ref 产出 bundle/<svc>.yaml
#   make sdk-python      # 生成 Python SDK 到 sdks/python/foundation_<svc>/
#   make sdk-typescript  # 生成 TS SDK 到 sdks/typescript/packages/<svc>/
#   make sdk-go          # 生成 Go SDK 到 sdks/go/<svc>/
#   make diff-prev       # 与 git HEAD~1 对比，识破坏性变更
#   make docs            # 生成 ReDoc HTML 文档
# =============================================================================

SHELL := /bin/bash
ROOT  := $(shell git rev-parse --show-toplevel 2>/dev/null || pwd)
SPECS_DIR := $(ROOT)/contracts/openapi
BUNDLE_DIR := $(SPECS_DIR)/bundle
DOCS_DIR := $(ROOT)/docs/api-reference

# 18 个 service spec（按 milestone 排）
SPECS := \
  identity authz org crypto \
  audit lifecycle dlp data-protection \
  notification search opa-bundle scim-dingtalk pam feature-flag \
  compliance billing api-platform llm-gateway \
  security-ops

SPEC_FILES := $(addprefix $(SPECS_DIR)/,$(addsuffix .yaml,$(SPECS)))
BUNDLE_FILES := $(addprefix $(BUNDLE_DIR)/,$(addsuffix .yaml,$(SPECS)))

.PHONY: help
help:
	@echo "OpenAPI Contracts — Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: lint
lint: ## Spectral 校验所有 spec
	@command -v spectral >/dev/null 2>&1 || { echo "Install spectral: npm i -g @stoplight/spectral-cli"; exit 1; }
	@cd $(SPECS_DIR) && spectral lint --ruleset .spectral.yaml _common.yaml $(addsuffix .yaml,$(SPECS))

.PHONY: lint-one
lint-one: ## Spectral 校验单个 spec：make lint-one SVC=identity
	@cd $(SPECS_DIR) && spectral lint --ruleset .spectral.yaml $(SVC).yaml

.PHONY: bundle
bundle: ## redocly bundle 把 $ref 内联展开
	@command -v redocly >/dev/null 2>&1 || { echo "Install: npm i -g @redocly/cli"; exit 1; }
	@mkdir -p $(BUNDLE_DIR)
	@for svc in $(SPECS); do \
	  echo "Bundling $$svc..."; \
	  redocly bundle $(SPECS_DIR)/$$svc.yaml -o $(BUNDLE_DIR)/$$svc.yaml --ext yaml; \
	done
	@echo "✅ Bundles written to $(BUNDLE_DIR)/"

.PHONY: validate-bundle
validate-bundle: bundle ## bundle 后再校验一次（确保展开后仍合规）
	@for f in $(BUNDLE_FILES); do \
	  echo "Validating $$f..."; \
	  redocly lint $$f || exit 1; \
	done

# --------------------------------------------------------------------------
# SDK 生成（openapi-generator-cli）
# --------------------------------------------------------------------------

OPENAPI_GENERATOR := docker run --rm -v $(ROOT):/local openapitools/openapi-generator-cli:latest

.PHONY: sdk-python
sdk-python: bundle ## 生成 Python SDK
	@mkdir -p $(ROOT)/sdks/python
	@for svc in $(SPECS); do \
	  pkg=$$(echo $$svc | tr '-' '_'); \
	  echo "Generating Python SDK for $$svc → foundation_$$pkg..."; \
	  $(OPENAPI_GENERATOR) generate \
	    -i /local/contracts/openapi/bundle/$$svc.yaml \
	    -g python \
	    -o /local/sdks/python/foundation_$$pkg \
	    --additional-properties=packageName=foundation_$$pkg,projectName=foundation-$$svc,packageVersion=1.0.0,library=asyncio; \
	done

.PHONY: sdk-typescript
sdk-typescript: bundle ## 生成 TypeScript SDK
	@mkdir -p $(ROOT)/sdks/typescript/packages
	@for svc in $(SPECS); do \
	  echo "Generating TS SDK for $$svc..."; \
	  $(OPENAPI_GENERATOR) generate \
	    -i /local/contracts/openapi/bundle/$$svc.yaml \
	    -g typescript-fetch \
	    -o /local/sdks/typescript/packages/$$svc \
	    --additional-properties=npmName=@foundation/$$svc,npmVersion=1.0.0,supportsES6=true,typescriptThreePlus=true; \
	done

.PHONY: sdk-go
sdk-go: bundle ## 生成 Go SDK
	@mkdir -p $(ROOT)/sdks/go
	@for svc in $(SPECS); do \
	  echo "Generating Go SDK for $$svc..."; \
	  $(OPENAPI_GENERATOR) generate \
	    -i /local/contracts/openapi/bundle/$$svc.yaml \
	    -g go \
	    -o /local/sdks/go/$$svc \
	    --additional-properties=packageName=$$svc,withGoMod=true; \
	done

.PHONY: sdk-all
sdk-all: sdk-python sdk-typescript sdk-go ## 生成 3 套 SDK

# --------------------------------------------------------------------------
# 破坏性变更检测
# --------------------------------------------------------------------------

.PHONY: diff-prev
diff-prev: ## 与 git HEAD~1 对比，识别破坏性 API 变更
	@command -v oasdiff >/dev/null 2>&1 || { echo "Install: go install github.com/tufin/oasdiff@latest"; exit 1; }
	@mkdir -p /tmp/openapi-prev
	@for svc in $(SPECS); do \
	  git show HEAD~1:contracts/openapi/$$svc.yaml > /tmp/openapi-prev/$$svc.yaml 2>/dev/null || continue; \
	  echo ""; echo "=== $$svc ==="; \
	  oasdiff breaking /tmp/openapi-prev/$$svc.yaml $(SPECS_DIR)/$$svc.yaml || true; \
	done

.PHONY: diff-base
diff-base: ## 与 main 分支对比
	@command -v oasdiff >/dev/null 2>&1 || { echo "Install: go install github.com/tufin/oasdiff@latest"; exit 1; }
	@mkdir -p /tmp/openapi-base
	@for svc in $(SPECS); do \
	  git show origin/main:contracts/openapi/$$svc.yaml > /tmp/openapi-base/$$svc.yaml 2>/dev/null || continue; \
	  echo ""; echo "=== $$svc ==="; \
	  oasdiff breaking /tmp/openapi-base/$$svc.yaml $(SPECS_DIR)/$$svc.yaml || true; \
	done

# --------------------------------------------------------------------------
# 文档生成
# --------------------------------------------------------------------------

.PHONY: docs
docs: bundle ## 生成 ReDoc 静态 HTML 文档
	@command -v redocly >/dev/null 2>&1 || { echo "Install: npm i -g @redocly/cli"; exit 1; }
	@mkdir -p $(DOCS_DIR)
	@for svc in $(SPECS); do \
	  echo "Building docs for $$svc..."; \
	  redocly build-docs $(BUNDLE_DIR)/$$svc.yaml -o $(DOCS_DIR)/$$svc.html; \
	done
	@echo "✅ Docs written to $(DOCS_DIR)/"

.PHONY: serve-docs
serve-docs: ## 本地起 redoc preview server：make serve-docs SVC=identity
	@cd $(SPECS_DIR) && redocly preview-docs $(SVC).yaml

# --------------------------------------------------------------------------
# CI hook
# --------------------------------------------------------------------------

.PHONY: ci
ci: lint validate-bundle ## CI 入口：lint + bundle 校验

.PHONY: clean
clean: ## 清理 bundle / docs / sdk 产出
	@rm -rf $(BUNDLE_DIR) $(DOCS_DIR)
	@echo "✅ Cleaned"
