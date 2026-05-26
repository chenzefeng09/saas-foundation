# LLM Gateway 详细设计 v1

> **唯一**模型出口：所有 LLM 调用经底座 `llm-gateway` 转发到外部端点（Claude / Bedrock / Azure OpenAI / Vertex / 客户自有 vLLM / Ollama）。
> 平台**不部署任何推理引擎**。LiteLLM 作为底层路由，封装层做租户隔离、配额联动、prompt 审计、能力探测。

| 字段 | 值 |
|---|---|
| 状态 | Draft v1 |
| Owner | LLM Gateway 后端 |
| 实施 milestone | A-M4 |
| 相关文档 | identity / authz / audit / billing / dlp / compliance / crypto |

## 0. TL;DR

- **底层**：LiteLLM Proxy（自托管，OSS）
- **封装层**：`llm-gateway-service` 包装 LiteLLM admin API + 添加底座原生能力
- **协议**：对外暴露 OpenAI-compatible + Anthropic Messages-compatible 双协议
- **租户隔离**：每租户虚拟 key 映射底层 provider key；不串
- **能力探测**：注册端点时跑套件（function calling / streaming / context / parallel tool）→ 输出兼容性报告
- **配额**：token 用量按 `(tenant, model, op_type)` 聚合上报给 billing
- **审计**：prompt + response 落 audit（按 sensitivity 脱敏）；DLP 阻断高敏 prompt
- **数据驻留**：cn-only 租户不可注册海外 provider（与 compliance 联动）
- **fallback**：主端点不可用 → 自动降级到备用端点；记录降级 audit

## 1. Context

- 业务诉求：客户希望底座支持多种推理服务（自有 GPU vLLM / 公有云 Claude / OpenAI 等）+ 动态切换
- 安全诉求：LLM prompt 可能含 PII / 商业秘密 → 必须审计 + DLP 阻断
- 合规诉求：中国客户禁出境 → cn-only 强制
- 成本诉求：token 用量是大头 → 必须配额 + 限流 + 计费

## 2. 架构

```
业务层（agent / chat / RAG）
        │
        │ OpenAI / Anthropic 协议
        ▼
┌──────────────────────────────────┐
│    llm-gateway-service (FastAPI) │
│    - 租户解析                     │
│    - DLP 前置过滤                 │
│    - 配额检查                     │
│    - prompt 审计 hash              │
│    - 路由 → LiteLLM               │
│    - response 后置 DLP             │
│    - 用量上报 billing              │
└───────────┬──────────────────────┘
            │
            ▼
   ┌──────────────────┐
   │  LiteLLM Proxy   │  (sidecar / 独立 deployment)
   │  - virtual key    │
   │  - provider fallback│
   │  - load balancing │
   └────┬─────────────┘
        │ HTTPS
        ▼
   外部 Provider:
   - Claude API (Anthropic)
   - Bedrock (AWS)
   - Vertex (GCP)
   - Azure OpenAI
   - 客户自有 vLLM (OpenAI-compatible)
   - 客户自有 llama.cpp / Ollama
```

## 3. Endpoint / Model 注册

### 3.1 数据模型

```sql
CREATE TABLE llm_gateway.endpoint (
  tenant_id        TEXT NOT NULL,
  endpoint_id      TEXT NOT NULL,
  name             TEXT NOT NULL,
  provider         TEXT NOT NULL,           -- 'anthropic'/'bedrock'/'azure_openai'/'vertex'/'vllm'/'ollama'/'litellm_custom'
  api_base         TEXT NOT NULL,
  api_key_enc      BYTEA NOT NULL,          -- crypto.encrypt
  region           TEXT,                    -- 'us-east-1'/'cn-north-1'
  data_residency   TEXT,                    -- 'cn-only'/'eu-only'/'global'
  allow_training_on_data BOOLEAN NOT NULL DEFAULT FALSE,  -- 是否允许 provider 用数据训练（必须 false）
  active           BOOLEAN NOT NULL DEFAULT TRUE,
  health_status    TEXT NOT NULL DEFAULT 'UNKNOWN',  -- 'HEALTHY'/'DEGRADED'/'DOWN'
  last_probed_at   TIMESTAMPTZ,
  created_by       TEXT NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, endpoint_id)
);

CREATE TABLE llm_gateway.model (
  tenant_id        TEXT NOT NULL,
  model_id         TEXT NOT NULL,           -- 内部 ID 'mdl_xxx'
  endpoint_id      TEXT NOT NULL,
  model_name       TEXT NOT NULL,           -- provider 侧名 'claude-sonnet-4-20250514' / 'gpt-4o' / 'qwen3-32b'
  alias            TEXT,                    -- 业务层用：'default-fast' / 'default-smart'
  capabilities     JSONB NOT NULL,          -- {tool_use, streaming, context_window, parallel_tools, vision, thinking}
  cost_per_1k_input_tokens  NUMERIC,
  cost_per_1k_output_tokens NUMERIC,
  currency         TEXT NOT NULL DEFAULT 'USD',
  rate_limit       JSONB,                   -- {rpm, tpm}
  active           BOOLEAN NOT NULL DEFAULT TRUE,
  PRIMARY KEY (tenant_id, model_id)
);

CREATE TABLE llm_gateway.fallback_chain (
  tenant_id        TEXT NOT NULL,
  alias            TEXT NOT NULL,           -- 'default-smart'
  chain            JSONB NOT NULL,          -- [{model_id, weight}, ...]  按优先级
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, alias)
);
```

### 3.2 能力探测套件

注册新 endpoint 时强制跑：

```python
class CapabilityProbe:
    async def probe_endpoint(self, endpoint, model) -> CapabilityReport:
        return CapabilityReport(
            function_calling   = await self._test_function_calling(),
            streaming          = await self._test_streaming(),
            context_window     = await self._test_context_window(),
            parallel_tools     = await self._test_parallel_tools(),
            vision             = await self._test_vision(),
            thinking_blocks    = await self._test_thinking(),
            tool_response_block = await self._test_tool_response(),
        )
```

测试用 minimal canonical prompts；记录响应特征（如是否返回 `tool_use` content block / 是否流式分片等）。

**强制能力**（缺一即拒绝注册）：
- function calling / tool use
- streaming
- context window ≥ 32K

**可选能力**（不影响注册，但记录）：
- parallel tool calls
- vision
- thinking blocks

### 3.3 健康检查

每 60s 跑一次 lightweight probe（短 prompt → 检查响应延迟 / 错误率）。
状态：
- HEALTHY：成功率 ≥ 99%
- DEGRADED：90-99%（仍可用，但告警）
- DOWN：< 90% 或连续 5min 错（fallback 启用）

## 4. 租户虚拟 Key 映射

```
租户 A 的 virtual key 'vk_a_anthropic'
   ↓ LiteLLM
   实际调用 Anthropic API 用底层 key 'sk-ant-actual-xxx'
   
租户 B 看不到 vk_a 或 sk-ant-actual；只看自己的 vk_b
```

LiteLLM 的 virtual key 功能：
- 创建 vk 时绑定底层 provider key + scope + 限额
- 业务层用 vk 调用 → LiteLLM 翻译到真 key
- vk 可随时 rotate / revoke

`llm-gateway-service` 包装：每次业务调用前，根据 (tenant_id, model_alias) 解析出 vk → 转发 LiteLLM。

## 5. 调用流程

```python
# 业务层（agent / chat）
from foundation_llm_gateway import LLMClient

client = LLMClient.from_env()  # 注入 tenant_context

response = await client.messages.create(
    model="default-smart",     # alias，本地解析到 vk
    messages=[{"role": "user", "content": "..."}],
    tools=[...],
    stream=True,
)
```

内部流程：

```
1. 解析 tenant_id（from ctx）+ user_id
2. 解析 alias → model_id → endpoint
3. DLP 前置：
   - prompt 含 sensitivity ≥ L4 内容 → 阻断（用 dlp.scan_text）
   - PII 自动脱敏 选项（compliance 可配）
4. compliance.cross_border 检查：
   - 租户 data_residency=cn-only & endpoint.region 出境 → 拒绝
5. billing.quota.check(llm_token_count, estimate_amount=count_input_tokens)
   - 不足 → QUOTA_EXCEEDED
6. audit.event_begin (prompt_hash, model, tools[], user)
7. 调 LiteLLM proxy → provider
8. stream 转发给业务方 + 累计 tokens
9. 完成后：
   - billing.quota.consume(input_tokens + output_tokens, idempotency=request_id)
   - audit.event_complete (response_hash, latency, tokens, status)
   - DLP 后置：response 含 PII → 通知 + 自动脱敏（可选）
   - 失败 → 触发 fallback chain
```

## 6. Fallback 策略

```yaml
# 租户配置示例
fallback_chains:
  default-smart:
    - { model: "claude-sonnet-4", weight: 100, on_fail: ["timeout", "5xx", "rate_limit"] }
    - { model: "gpt-4o", weight: 100, on_fail: [...] }
    - { model: "qwen3-32b-internal", weight: 100, on_fail: [...] }
```

行为：
- model 1 失败 → 立即尝试 model 2（不阻塞用户）
- weight 用于 A/B（v1.1）
- fallback 触发写 audit + 通知（重大降级）

**注意**：fallback 模型能力不同（如从 vision 模型回到非 vision），业务层需感知能力降级。response header 加 `X-LLM-Fallback-From: claude-sonnet-4` 提示。

## 7. 数据隔离承诺

- 所有 LiteLLM 调用强制带 `metadata.tenant_id`
- 默认拒绝任何 `allow_training_on_data=true` 的 provider 配置
- Anthropic API、Azure OpenAI、Vertex 已默认不训练用户数据（合同保证）
- 客户自有 vLLM / Ollama：数据完全在客户机房，无外泄风险

## 8. SDK 双协议

### 8.1 OpenAI-compatible

```python
client.chat.completions.create(
    model="default-smart",
    messages=[...],
    tools=[...],
    stream=True,
)
```

### 8.2 Anthropic Messages-compatible

```python
client.messages.create(
    model="default-smart",
    messages=[...],
    system="...",
    tools=[...],
    stream=True,
)
```

底层都路由到 LiteLLM 的对应转换（LiteLLM 内置 OpenAI ↔ Anthropic 协议互转）。

## 9. 与其他模块集成

| 模块 | 集成 |
|---|---|
| **identity** | 调用方 user_id |
| **authz** | 调用 LLM 需 `llm_gateway:call` scope |
| **audit** | prompt / response hash + tokens + latency 落 audit |
| **billing** | token 用量上报；调用前 check quota |
| **dlp** | prompt / response 内容扫描；高敏 blocking |
| **compliance** | data_residency 强制；ROPA 自动标注（@pii_processing） |
| **crypto** | endpoint API key 加密存储 |
| **notification** | 健康 DOWN 告警；fallback 触发告警 |
| **feature-flag** | 灰度新模型 |

## 10. API 端点

| Method | Path | 说明 |
|---|---|---|
| POST | `/api/llm-gateway/v1/chat/completions` | OpenAI 协议 |
| POST | `/api/llm-gateway/v1/messages` | Anthropic 协议 |
| GET | `/api/llm-gateway/v1/models` | 列租户可用模型 |
| GET | `/api/llm-gateway/v1/endpoints` | 列 endpoint（管理员） |
| POST | `/api/llm-gateway/v1/endpoints` | 注册 endpoint（带探测） |
| POST | `/api/llm-gateway/v1/endpoints/{id}/probe` | 重新探测能力 |
| DELETE | `/api/llm-gateway/v1/endpoints/{id}` | 删除 |
| PUT | `/api/llm-gateway/v1/fallback-chains/{alias}` | 配置 fallback |

## 11. 错误码

| code | HTTP |
|---|---|
| `FOUNDATION.LLM_GATEWAY.AUTHN.INVALID_KEY` | 401 |
| `FOUNDATION.LLM_GATEWAY.POLICY.MODEL_NOT_ALLOWED` | 403 |
| `FOUNDATION.LLM_GATEWAY.COMPLIANCE.DATA_RESIDENCY_VIOLATION` | 403 |
| `FOUNDATION.LLM_GATEWAY.POLICY.DLP_BLOCKED` | 403 |
| `FOUNDATION.LLM_GATEWAY.QUOTA.EXCEEDED` | 429 |
| `FOUNDATION.LLM_GATEWAY.RATE.LIMITED` | 429 |
| `FOUNDATION.LLM_GATEWAY.UPSTREAM.MODEL_NOT_FOUND` | 404 |
| `FOUNDATION.LLM_GATEWAY.UPSTREAM.UNAVAILABLE` | 503 |
| `FOUNDATION.LLM_GATEWAY.UPSTREAM.TIMEOUT` | 504 |
| `FOUNDATION.LLM_GATEWAY.VALIDATION.CAPABILITY_MISSING` | 422 |（注册时探测不通过）|
| `FOUNDATION.LLM_GATEWAY.VALIDATION.CONTEXT_TOO_LARGE` | 413 |
| `FOUNDATION.LLM_GATEWAY.STATE.FALLBACK_ALL_EXHAUSTED` | 503 |

## 12. 部署形态

| 形态 | LiteLLM 部署 | 端点数 | 探测频率 |
|---|---|---|---|
| small | sidecar | 1-2 个（够 POC） | 5 min |
| medium | 独立 deployment（3 replicas） | 5-20 个 | 1 min |
| large | + per-region pool | 50+ | 30s + on-call |

## 13. 性能与容量

| 指标 | 目标 |
|---|---|
| llm-gateway-service overhead | < 50ms（不含 provider 调用） |
| 配额检查 | < 5ms（Redis） |
| DLP 扫描（短 prompt） | < 100ms |
| 端到端 P95 | 取决于 provider（不在本服务控制范围）|
| 单实例吞吐 | 100 并发（streaming） |

## 14. 待解决问题

| # | 问题 | 决策 |
|---|---|---|
| 1 | streaming 中途 quota 耗尽 | 估算输入 token 预扣 + 收到完整 response 校准；超额下次调用拒绝（不打断当前流） |
| 2 | 长 prompt 全量 DLP 扫描成本 | 异步采样 + 同步 regex 快速通道；超阈值阻断 |
| 3 | thinking blocks 是否计费 | 计费（属于 output tokens）|
| 4 | LiteLLM upstream 版本兼容 | 锁定 LiteLLM 版本；季度评估升级 |
| 5 | 客户 vLLM 不支持 streaming | 降级为同步；UI 提示 |
| 6 | tool call 跨多 provider 一致性 | 业务层负责工具定义；本服务只透传 |
| 7 | Azure OpenAI 区域选择 | 按租户 region 路由 |
| 8 | 价格波动 | cost_per_1k_*_tokens 字段可手动更新；月度对账时核对 |
| 9 | rate_limit 共享 vs 独占 | LiteLLM virtual key 隔离 rate_limit；超出走 fallback |
| 10 | 大文件 vision 上传 | 走对象存储 + 引用 URL；不直接进 prompt |

## 15. 验证标准（A-M4 出口）

| # | 验证 | 通过 |
|---|---|---|
| 1 | 双协议 e2e | OpenAI + Anthropic 两套 API 调通 |
| 2 | 能力探测 | 注册端点跑全套探测；缺强制能力拒绝 |
| 3 | 租户虚拟 key 隔离 | 租户 A 调用不可见 B 的 key / 用量 |
| 4 | DLP 前置阻断 | L4+ prompt 阻断；不调 provider |
| 5 | 配额熔断 | 月度 token 上限触发 429 |
| 6 | fallback | 主 provider DOWN → 自动切备用；audit 记录 |
| 7 | 数据驻留 | cn-only 租户注册 us-east-1 端点 → 拒绝 |
| 8 | 健康检查 | 模拟端点 500 → 60s 内 status 变 DEGRADED |
| 9 | streaming | 数千 token 流式响应正常 |
| 10 | tool use 透传 | function call → tool_use block 正确返回 |
| 11 | 用量上报 billing | 调用后 quota.current_usage 正确累计 |
| 12 | 审计 | prompt_hash + response_hash + tokens + status 全在 audit |
| 13 | RLS | 跨租户查询 endpoint / model 失败 |
| 14 | 性能 | gateway overhead < 50ms p95 |
| 15 | LiteLLM 升级 | 升级一次 + e2e 回归通过 |
