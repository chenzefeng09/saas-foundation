# 自部署推理引擎接入 llm-gateway —— 缓存命中 + 会话亲和路由部署落地

> **版本**: v1-draft
> **适用底座**: SaaS Foundation / `packages/llm-gateway`（内部前缀 `/api/llm-gateway/v1`）
> **目标读者**: 运维 / 未来实施
> **覆盖环境**: 生产 k8s + 开发 docker-compose
> **状态**: 文档交付，**不改代码、不起引擎**。所有引擎参数/响应字段均为"截至 **2026-06** 的事实，以你固定的引擎版本实测为准"。
>
> 配套阅读：[CONVENTIONS.md](./CONVENTIONS.md)、`packages/llm-gateway` 源码。

---

## 0. TL;DR（先看这张表）

| 引擎 | provider_type | prefix cache 默认 | cache 观测字段 | 启用观测所需参数 | 亲和方案 | affinity_mode |
|------|---------------|-------------------|----------------|------------------|----------|---------------|
| **DeepSeek**（云，对照基线） | `deepseek` | 上游托管 | `prompt_cache_hit_tokens` / `prompt_cache_miss_tokens`（顶层） | 开箱即用 | 上游托管，无需自管 | `none` |
| **vLLM** | `vllm` | V1 默认开 | `usage.prompt_tokens_details.cached_tokens` | `--enable-prompt-tokens-details` | 外部 consistent-hash LB（大规模可选 vLLM Router） | `external_lb` |
| **SGLang** | `openai_compatible` ⚠️ | RadixAttention 默认开 | `usage.prompt_tokens_details.cached_tokens` | `--enable-cache-report` | 官方 SGLang Router（cache-aware） | `engine_router` |
| **llama.cpp**（官方 `llama-server`） | `openai_compatible` ⚠️ | `--cache-prompt` 默认开 | `timings.cache_n`（私有，最稳）/ `prompt_tokens_details.cached_tokens` | 默认就有，无需开关 | 外部 consistent-hash LB | `external_lb` |

> ⚠️ **代码现状（务必先读）**：`packages/llm-gateway` 的 `ProviderKind` 枚举（`services/llm_gateway_service.py`）目前包含 `vllm`、`deepseek`，但**尚无 `sglang` / `llamacpp` 成员**。注册时传入未知 `provider_type` 会被静默回退为 `openai_compatible`（见 `register_provider`：`except ValueError: kind = ProviderKind.OPENAI_COMPATIBLE`）。
> 含义：
> - SGLang / llama.cpp 当前只能以 `openai_compatible` 注册，走 OpenAI 兼容透传路径——**可用**，但网关无法按 kind 对它们做差异化 usage 归一化。
> - 待 `normalize_usage`（另一任务）落地并在枚举中补上 `sglang` / `llamacpp` 后，再把 `provider_type` 切到对应值。本文在示例中标出"目标值"与"当前可用值"两栏。

---

## 1. 架构总览 + 数据流

### 1.1 三层职责

接入链路严格分三层，各司其职，**不要混在一层做**：

| 层 | 组件 | 职责 | 不负责 |
|----|------|------|--------|
| **协议 + 观测** | llm-gateway | OpenAI 兼容协议归一、虚拟 key 鉴权、配额/计费、按 `provider.kind` 归一化 cache 观测（`normalize_usage`）、透传 `X-Session-Id` | 不选实例、不做亲和路由 |
| **亲和（路由）** | 外部 LB（Istio/Nginx/Envoy）或引擎官方 router | 按 `X-Session-Id` 一致性哈希，把同会话固定打到同一副本 | 不懂 OpenAI 协议语义、不做计费 |
| **缓存** | 引擎副本（vLLM/SGLang/llama.cpp） | prefix/KV cache 命中、在 usage 里回报 cache 字段 | 不做跨副本共享（默认都是单实例命中） |

**关键约束**：网关的 `base_url` 是**单值**，指向 LB 或 engine router 的入口。亲和路由完全由外部 LB/router 承担，**网关不做实例选择**。当 provider 的 `capabilities.affinity_mode != "none"` 且请求 `metadata` 带 `session_id` / `run_id` 时，网关在转发上游时注入 `X-Session-Id` header——LB/router 据此哈希。

### 1.2 数据流图（四引擎）

```
                        ┌──────────────────────────────────────────────────────────┐
                        │  client / worker (OpenAI SDK, metadata.session_id=run_id) │
                        └───────────────────────────────┬──────────────────────────┘
                                                        │  POST /api/llm-gateway/v1/chat/completions
                                                        ▼
                        ┌──────────────────────────────────────────────────────────┐
                        │              llm-gateway  (协议 + 观测层)                  │
                        │  · 虚拟 key 鉴权 / 配额 / 计费                             │
                        │  · normalize_usage(by provider.kind) → 写 cache 列         │
                        │  · affinity_mode != none 且有 session_id                   │
                        │       → 注入 header  X-Session-Id: <session_id>            │
                        │  · 转发到 provider.base_url (单值入口)                     │
                        └───────────────────────────────┬──────────────────────────┘
                                                        │  X-Session-Id 随请求透传
        ┌───────────────────────────────┬───────────────┴───────────────┬───────────────────────────────┐
        │  affinity_mode=external_lb     │  affinity_mode=engine_router  │  affinity_mode=none           │
        ▼                                ▼                               ▼
┌────────────────────┐        ┌────────────────────────┐        ┌────────────────────┐
│ 外部 consistent-   │        │  SGLang Router          │        │  DeepSeek (云)      │
│ hash LB            │        │  --policy=cache_aware   │        │  上游自管亲和+缓存  │
│ (Istio/Nginx/Envoy)│        │  按前缀内容匹配率选 worker│       └──────────┬─────────┘
│ hash(X-Session-Id) │        │  hash(X-Session-Id) 选  │                   │
└─────────┬──────────┘        │  路由前置一致性          │                   │
          │ 同 session→同副本 │  (多 router 副本时见 §4.3)│                  │
          │                   └───────────┬────────────┘                   │
  ┌───────┴───────┬───────┐       ┌───────┴───────┬───────┐                │
  ▼               ▼       ▼       ▼               ▼       ▼                ▼
┌──────┐      ┌──────┐ ┌──────┐ ┌──────┐      ┌──────┐ ┌──────┐     ┌──────────┐
│vLLM/ │      │vLLM/ │ │ ...  │ │SGLang│      │SGLang│ │ ...  │     │ DeepSeek │
│llama │      │llama │ │      │ │worker│      │worker│ │      │     │ endpoint │
│ rep0 │      │ rep1 │ │      │ │ w0   │      │ w1   │ │      │     │          │
└──┬───┘      └──┬───┘ └──────┘ └──┬───┘      └──┬───┘ └──────┘     └────┬─────┘
   │ APC/        │                 │ Radix        │                      │ 顶层
   │ cache-prompt│                 │ Attention    │                      │ cache_hit/
   │ 单实例 KV   │                 │ 单 worker    │                      │ miss_tokens
   ▼             ▼                 ▼ radix tree   ▼                      ▼
 命中只在"同一副本/同一 worker"内发生——这就是为什么必须做会话亲和。
```

> **一句话**：缓存命中是**单实例**的（无默认跨副本共享）。所以"同会话必须落同副本"是命中的前提；这件事网关不做，由 LB/router 做。

---

## 2. provider 注册指南

### 2.1 注册接口与 body 字段（以仓库实际为准）

`POST /api/llm-gateway/v1/providers`。请求体（`RegisterProviderRequest`，见 `api/v1/llm_gateway.py`）：

| 字段 | 含义 | 本文档关注点 |
|------|------|--------------|
| `name` | provider 显示名 | — |
| `api_base` | **= base_url**，指向 LB / engine router 入口 | 填 §4/§5 给出的 Service DNS 或 compose service 名 |
| `api_key` | 明文，注册时由 crypto service 加密落库 | 自建引擎无鉴权时填占位串（如 `"sk-noauth"`） |
| `provider_type` | 引擎类型，映射到 `ProviderKind` | 见 §0 的"目标值/当前可用值" |
| `models` | 模型 id 列表，`models[0]` 作 `default_model` | — |
| `model_type_map` | `{"llm": [...], "text_embedding": [...]}` | — |
| `model_settings` | 每模型设置 `{model: {...}}` | **cache/affinity 扩展位**见下 |

> **capabilities 扩展位的现实**：网关把 `capabilities` 落库为
> `{"model_type_map": ..., "model_settings": ...}`（见 `register_provider`）。
> 本文涉及的 `affinity_mode` / `cache_format` / `cache_metric_unreliable` 这些 **capabilities_extra** 键，
> 取决于 `normalize_usage` / 亲和注入任务最终把它们读在哪里。两种落地方式（实施时与该任务对齐，二选一）：
> 1. **顶层 capabilities**：扩展 `register_provider`，把这些键平铺进 `capabilities`（推荐，语义清晰）；
> 2. **借道 model_settings**：在 `model_settings["__provider__"]` 或每模型条目里携带，短期无需改 schema。
>
> 下面示例统一用 **`capabilities_extra` 占位块**表达意图，并在注释里标明它最终应落在 `capabilities.*`。

> **PATCH 更新语义（已修：merge，不再整体替换）**：`PATCH /providers/{pid}`（`UpdateProviderRequest`）对 `capabilities` 采用**浅层 merge-patch**——只传 `capabilities_extra`（如单改 `affinity_mode`）不会冲掉 `model_type_map`/`model_settings`，反之只改 `model_type_map` 也不会冲掉 cache/affinity 配置。规则：
> - 传入的顶层 key **覆盖**同名 key，未传的 key **保留**；
> - merge 是**浅层**的——传 `model_type_map` 会整块替换 `model_type_map` 的值（不会逐 key 合并子字典），`model_settings` 同理；
> - **删除某个 capability key**：在对应字段传 JSON `null`（如 `capabilities_extra: {"cache_metric_unreliable": null}`），网关据此 `pop` 掉该 key。
>
> 实现见 `services/llm_gateway_service.py` 的 `update_provider`（重新赋一个新 dict 以触发 JSONB dirty 跟踪）。

### 2.2 四引擎注册示例

所有请求都需带租户上下文 header（虚拟 key / tenant 注入，按底座既有约定）。下面只示意 body。

#### (a) DeepSeek（云，对照基线）

```jsonc
// POST /api/llm-gateway/v1/providers
{
  "name": "deepseek-prod",
  "api_base": "https://api.deepseek.com/v1",
  "api_key": "<deepseek-api-key>",
  "provider_type": "deepseek",
  "models": ["deepseek-chat", "deepseek-reasoner"],
  "model_type_map": { "llm": ["deepseek-chat", "deepseek-reasoner"] },
  "capabilities_extra": {                 // → 最终落 capabilities.*
    "cache_format": "deepseek_top_level", // 顶层 prompt_cache_hit_tokens/miss_tokens
    "affinity_mode": "none"               // 上游托管亲和+缓存，网关不注入 X-Session-Id
  }
}
```

#### (b) vLLM

```jsonc
{
  "name": "vllm-qwen-prod",
  "api_base": "http://vllm-lb.llm-engines.svc.cluster.local/v1",  // 指向外部 LB 入口，不是单个 pod
  "api_key": "sk-noauth",
  "provider_type": "vllm",
  "models": ["Qwen2.5-32B-Instruct"],
  "model_type_map": { "llm": ["Qwen2.5-32B-Instruct"] },
  "capabilities_extra": {
    "cache_format": "openai_prompt_tokens_details", // usage.prompt_tokens_details.cached_tokens
    "affinity_mode": "external_lb",                 // 网关注入 X-Session-Id，LB 哈希
    "metrics_endpoint": "/metrics"                  // 可选：抓 vllm:prefix_cache_hits/queries 兜底 null bug
  }
}
```

#### (c) SGLang

```jsonc
{
  "name": "sglang-qwen-prod",
  // 目标值: "provider_type": "sglang"（待枚举补齐）；当前可用:
  "provider_type": "openai_compatible",
  "api_base": "http://sglang-router.llm-engines.svc.cluster.local/v1", // 指向 SGLang Router（再前置一致性哈希，见 §4.3）
  "api_key": "sk-noauth",
  "models": ["Qwen2.5-32B-Instruct"],
  "model_type_map": { "llm": ["Qwen2.5-32B-Instruct"] },
  "capabilities_extra": {
    "cache_format": "openai_prompt_tokens_details",
    "affinity_mode": "engine_router",       // 由 SGLang Router 做 cache-aware 选 worker
    "cache_metric_unreliable": true,        // 开 MTP/投机解码时 cached_tokens 恒 0（已知 bug），改抓 Prometheus
    "metrics_endpoint": "/metrics"          // 需引擎侧 --enable-metrics
  }
}
```

#### (d) llama.cpp（官方 `llama-server`）

```jsonc
{
  "name": "llamacpp-gguf-prod",
  // 目标值: "provider_type": "llamacpp"（待枚举补齐）；当前可用:
  "provider_type": "openai_compatible",
  "api_base": "http://llamacpp-lb.llm-engines.svc.cluster.local/v1",   // 外部 LB 入口
  "api_key": "sk-noauth",
  "models": ["qwen2.5-32b-instruct-q4_k_m"],
  "model_type_map": { "llm": ["qwen2.5-32b-instruct-q4_k_m"] },
  "capabilities_extra": {
    "cache_format": "llamacpp_timings",  // 优先读私有 timings.cache_n（默认就有，最稳）
    "affinity_mode": "external_lb"
  }
}
```

### 2.3 四引擎注册关键差异（一句话版）

- **base_url 指向谁不同**：DeepSeek→云端点；vLLM/llama.cpp→外部 LB；SGLang→engine router（且 router 前再加一致性哈希）。
- **provider_type 可用性不同**：vLLM/DeepSeek 有原生枚举；SGLang/llama.cpp 当前回退 `openai_compatible`。
- **cache_format 不同**：DeepSeek 顶层字段；vLLM/SGLang 走 `prompt_tokens_details.cached_tokens`；llama.cpp 优先私有 `timings.cache_n`。
- **affinity_mode 不同**：DeepSeek=`none`；vLLM/llama.cpp=`external_lb`；SGLang=`engine_router`。
- **唯一需要 `cache_metric_unreliable=true` 的是 SGLang**（MTP/投机解码恒 0）。

---

## 3. 引擎启动参数清单

> 以下命令为**骨架**，模型路径、并行度、显存比例按你的卡/模型调。版本字段以你固定的引擎版本实测为准（截至 2026-06）。

### 3.1 vLLM

| 目的 | 参数 |
|------|------|
| (a) 开 prefix cache | V1 引擎**默认开**（APC）。关闭才需 `--no-enable-prefix-caching` |
| (b) 返回 cache 观测 | `--enable-prompt-tokens-details`（**默认关**，不加则 `usage.prompt_tokens_details.cached_tokens` 缺失） |
| 兜底观测 | 暴露 `/metrics`，抓 `vllm:prefix_cache_hits` / `vllm:prefix_cache_queries`（应对近版偶发 `cached_tokens=null`） |

```bash
vllm serve Qwen/Qwen2.5-32B-Instruct \
  --served-model-name Qwen2.5-32B-Instruct \
  --enable-prompt-tokens-details \
  --host 0.0.0.0 --port 8000
  # prefix caching 在 V1 默认开；如需关闭加 --no-enable-prefix-caching
  # 跨实例共享 KV 非默认，需另接 LMCache / kv_transfer
```

### 3.2 SGLang

| 目的 | 参数 |
|------|------|
| (a) 开 prefix cache | RadixAttention **默认开**。关闭才需 `--disable-radix-cache`；分层缓存 `--enable-hierarchical-cache`（HiCache，单实例分层） |
| (b) 返回 cache 观测 | `--enable-cache-report`（**默认关**） |
| 注意 | 开 **MTP / 投机解码**时 `cached_tokens` **恒 0**（已知 bug）→ 配 `--enable-metrics` 抓 Prometheus，并在 provider 标 `cache_metric_unreliable=true` |

```bash
python -m sglang.launch_server \
  --model-path Qwen/Qwen2.5-32B-Instruct \
  --served-model-name Qwen2.5-32B-Instruct \
  --enable-cache-report \
  --enable-metrics \
  --host 0.0.0.0 --port 30000
  # RadixAttention 默认开；如启用 MTP，cached_tokens 不可信，以 /metrics 为准
```

### 3.3 llama.cpp（官方 `llama-server`）

> **优先用官方 `llama-server`，不要用 `llama-cpp-python` 的 server**（后者 cache 观测弱）。

| 目的 | 参数 |
|------|------|
| (a) 开 prefix cache | `--cache-prompt` **默认开**；slot 数由 `-np` 控制，**slot 间 KV 不互通** |
| (b) 返回 cache 观测 | 默认即返回 `timings.cache_n`（私有，最稳）+ 标准 `prompt_tokens_details.cached_tokens`，**无需开关** |
| 可选 | `--cache-reuse N`（部分前缀复用阈值，按需） |

```bash
llama-server \
  -m /models/qwen2.5-32b-instruct-q4_k_m.gguf \
  --alias qwen2.5-32b-instruct-q4_k_m \
  -np 4 \
  --cache-reuse 256 \
  --host 0.0.0.0 --port 8080
  # --cache-prompt 默认开，无需显式加
```

### 3.4 流式 usage 注意（vLLM / SGLang）

流式请求要拿到 usage，必须带 `stream_options: {"include_usage": true}`；usage 出现在 `finish_reason` **之后的 trailing chunk**。
> 仓库现状：网关在 `body.stream` 时已自动注入 `payload["stream_options"] = {"include_usage": True}`（见 `api/v1/llm_gateway.py`），所以经网关的流式请求默认带 usage。

---

## 4. k8s 部署方案（生产）

命名空间约定：引擎放 `llm-engines`，网关放 `foundation`（或既有命名空间）。下文 YAML 为**骨架**，资源/亲和性/GPU `nodeSelector`/`tolerations` 按集群补全。

### 4.1 外部 consistent-hash LB（vLLM / llama.cpp）

拓扑：`Deployment`（N 副本，每副本一个引擎实例）+ 一个 headless 或 ClusterIP `Service` + LB 层做 `X-Session-Id` 一致性哈希。

#### 方案 A：Istio DestinationRule（consistentHash by header）

```yaml
apiVersion: networking.istio.io/v1
kind: DestinationRule
metadata:
  name: vllm-affinity
  namespace: llm-engines
spec:
  host: vllm.llm-engines.svc.cluster.local
  trafficPolicy:
    loadBalancer:
      consistentHash:
        httpHeaderName: x-session-id   # 网关注入的 header（大小写不敏感）
        # session 为空时：Istio 对缺失 header 退化为按连接/随机分布 →
        # 即"无亲和"，等同冷缓存，属正常降级（见 §7）。
---
apiVersion: v1
kind: Service
metadata:
  name: vllm
  namespace: llm-engines
spec:
  selector: { app: vllm }
  ports: [{ name: http, port: 80, targetPort: 8000 }]
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vllm
  namespace: llm-engines
spec:
  replicas: 3                          # 副本=并发亲和"桶"数；越多则单会话命中越集中、跨会话越分散
  selector: { matchLabels: { app: vllm } }
  template:
    metadata: { labels: { app: vllm } }
    spec:
      containers:
        - name: vllm
          image: vllm/vllm-openai:<pin-version>   # 版本以实测为准
          args: ["--served-model-name","Qwen2.5-32B-Instruct",
                 "--enable-prompt-tokens-details","--host","0.0.0.0","--port","8000"]
          ports: [{ containerPort: 8000 }]
```

> provider 注册时 `api_base` 填：`http://vllm.llm-engines.svc.cluster.local/v1`。
> Istio 在 sidecar 层做哈希，无需额外网关。

#### 方案 B：Nginx Ingress（upstream-hash-by header）

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: llamacpp-affinity
  namespace: llm-engines
  annotations:
    nginx.ingress.kubernetes.io/upstream-hash-by: "$http_x_session_id"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "600"   # LLM 响应慢，给够
    nginx.ingress.kubernetes.io/proxy-send-timeout: "600"
spec:
  ingressClassName: nginx
  rules:
    - host: llamacpp.internal
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: { service: { name: llamacpp, port: { number: 80 } } }
```

> `$http_x_session_id` 为空时，nginx 的 `upstream-hash-by` 退化为对空串哈希——所有空 session 会**集中到同一后端**。生产可改用 `upstream-hash-by: "$http_x_session_id$request_id"` 之类组合，或在 LB 前判空走轮询。这点**需实测确认**所选 nginx 版本的退化行为。

### 4.2 副本数与亲和桶的关系

- 副本数 = 一致性哈希环上的"桶"数。**同一 `session_id` 永远落同一副本**（前提是副本集稳定）。
- 副本扩缩容会引起哈希环重映射，**部分会话迁移到新副本 → 一次性冷缓存**，属预期。
- 引擎缓存是单实例的，所以"提高命中率"靠的是亲和稳定，不是堆副本。副本主要解决并发吞吐。

### 4.3 SGLang Router（cache-aware）

拓扑：**Router 作 `Deployment`（3 副本 HA）** + worker 作 `Deployment`/`StatefulSet`。

> **关键坑（必须做）**：SGLang 多 Router 副本时，各副本**各自维护 radix tree，不同步**——同一会话若打到不同 router 副本，命中率掉 10–20%。
> 因此**网关 → Router 这一跳也要 consistent-hash**（再加一个 DestinationRule，按 `x-session-id` 哈希），保证同会话固定打到同一 router 副本；router 再用 `cache_aware` 在它自己的 worker 集合里选。
> 即：**两级亲和** —— 第一级（网关→router）按 session 哈希定 router 副本；第二级（router→worker）按前缀内容匹配选 worker。

```yaml
# ---- Router 前置一致性哈希（解决"多 router 副本 radix tree 不同步"）----
apiVersion: networking.istio.io/v1
kind: DestinationRule
metadata: { name: sglang-router-affinity, namespace: llm-engines }
spec:
  host: sglang-router.llm-engines.svc.cluster.local
  trafficPolicy:
    loadBalancer:
      consistentHash:
        httpHeaderName: x-session-id    # 同 session → 同一 router 副本
---
apiVersion: v1
kind: Service
metadata: { name: sglang-router, namespace: llm-engines }
spec:
  selector: { app: sglang-router }
  ports: [{ name: http, port: 80, targetPort: 30000 }]
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: sglang-router, namespace: llm-engines }
spec:
  replicas: 3                            # HA；务必配 §上方 DestinationRule，否则副本间 radix tree 各冷
  selector: { matchLabels: { app: sglang-router } }
  template:
    metadata: { labels: { app: sglang-router } }
    spec:
      containers:
        - name: router
          image: lmsysorg/sglang:<pin-version>   # 版本以实测为准
          command: ["python","-m","sglang_router.launch_router"]
          args:
            - "--policy=cache_aware"             # 默认即 cache_aware，按前缀匹配率选 worker
            - "--worker-urls"                    # 指向 worker Service（或用服务发现/手动列表）
            - "http://sglang-worker.llm-engines.svc.cluster.local:30000"
            - "--host=0.0.0.0"
            - "--port=30000"
          ports: [{ containerPort: 30000 }]
---
apiVersion: v1
kind: Service
metadata: { name: sglang-worker, namespace: llm-engines }
spec:
  clusterIP: None                        # headless，便于 router 发现各 worker
  selector: { app: sglang-worker }
  ports: [{ name: http, port: 30000, targetPort: 30000 }]
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: sglang-worker, namespace: llm-engines }
spec:
  replicas: 4
  selector: { matchLabels: { app: sglang-worker } }
  template:
    metadata: { labels: { app: sglang-worker } }
    spec:
      containers:
        - name: worker
          image: lmsysorg/sglang:<pin-version>
          command: ["python","-m","sglang.launch_server"]
          args:
            - "--model-path=Qwen/Qwen2.5-32B-Instruct"
            - "--served-model-name=Qwen2.5-32B-Instruct"
            - "--enable-cache-report"
            - "--enable-metrics"
            - "--host=0.0.0.0"
            - "--port=30000"
          ports: [{ containerPort: 30000 }]
```

> provider 注册 `api_base` 填 **Router** 的 Service DNS：`http://sglang-router.llm-engines.svc.cluster.local/v1`。
> worker 列表交给 Router 管理（`--worker-urls` 或其服务发现），网关不感知 worker。

#### vLLM 大规模可选 router

vLLM 也有官方 Router（2025-12 较新，按 session id 一致性哈希）、production-stack、llm-d。
**生产建议先用外部 nginx/Envoy consistent-hash（§4.1）跑稳，再评估 vLLM Router**。其成熟度**需实测确认**。

### 4.4 provider base_url 在 k8s 里填什么（汇总）

| 引擎 | api_base（Service DNS） |
|------|--------------------------|
| vLLM（外部 LB） | `http://vllm.llm-engines.svc.cluster.local/v1`（经 Istio DR 哈希） |
| llama.cpp（外部 LB） | `http://llamacpp.internal/v1`（经 Nginx Ingress 哈希）或对应 Service |
| SGLang（Router） | `http://sglang-router.llm-engines.svc.cluster.local/v1`（Router 前置 DR 哈希） |
| DeepSeek | `https://api.deepseek.com/v1` |

---

## 5. docker-compose 部署方案（dev）

> **本节配置写在文档里作示例，不直接改 `dev.yml`**。实施时按需合并。

### 5.1 nginx consistent-hash LB + 多 worker（vLLM / llama.cpp）

`compose` 片段（示例）：

```yaml
# === dev.yml 片段（示例，勿直接覆盖现有文件）===
services:
  llamacpp-w0:
    image: ghcr.io/ggml-org/llama.cpp:server   # 版本以实测为准
    command: >
      -m /models/qwen2.5-7b-instruct-q4_k_m.gguf
      --alias qwen2.5-7b -np 4 --host 0.0.0.0 --port 8080
    volumes: ["./models:/models:ro"]
  llamacpp-w1:
    image: ghcr.io/ggml-org/llama.cpp:server
    command: >
      -m /models/qwen2.5-7b-instruct-q4_k_m.gguf
      --alias qwen2.5-7b -np 4 --host 0.0.0.0 --port 8080
    volumes: ["./models:/models:ro"]

  llamacpp-lb:
    image: nginx:1.27
    volumes: ["./nginx-llm.conf:/etc/nginx/nginx.conf:ro"]
    ports: ["18080:80"]
    depends_on: [llamacpp-w0, llamacpp-w1]
```

`nginx-llm.conf` 骨架：

```nginx
worker_processes auto;
events { worker_connections 1024; }
http {
  upstream llm_pool {
    hash $http_x_session_id consistent;   # 按会话一致性哈希；空 session → 退化集中到一台（dev 可接受）
    server llamacpp-w0:8080;
    server llamacpp-w1:8080;
  }
  server {
    listen 80;
    location / {
      proxy_pass http://llm_pool;
      proxy_set_header X-Session-Id $http_x_session_id;
      proxy_read_timeout 600s;            # LLM 响应慢，给够，否则长生成被切断
      proxy_send_timeout 600s;
      proxy_buffering off;                # 流式 SSE 不缓冲
    }
  }
}
```

> vLLM 同理：把 `llamacpp-w*` 换成 `vllm/vllm-openai` 镜像、worker 端口 8000、`upstream` 指向 8000，启动参数加 `--enable-prompt-tokens-details`。
> provider 注册 `api_base` 填：`http://llamacpp-lb/v1`（compose service 名）。

### 5.2 SGLang Router + 多 worker（dev 单 router 副本即可）

> dev 只起**单 router 副本**，**无跨副本 radix tree 不同步问题**，因此 dev 不需要 router 前置哈希。

```yaml
# === dev.yml 片段（示例）===
services:
  sglang-w0:
    image: lmsysorg/sglang:latest         # 版本以实测为准
    command: >
      python -m sglang.launch_server
      --model-path Qwen/Qwen2.5-7B-Instruct --served-model-name qwen2.5-7b
      --enable-cache-report --enable-metrics --host 0.0.0.0 --port 30000
  sglang-w1:
    image: lmsysorg/sglang:latest
    command: >
      python -m sglang.launch_server
      --model-path Qwen/Qwen2.5-7B-Instruct --served-model-name qwen2.5-7b
      --enable-cache-report --enable-metrics --host 0.0.0.0 --port 30000

  sglang-router:
    image: lmsysorg/sglang:latest
    command: >
      python -m sglang_router.launch_router
      --policy cache_aware
      --worker-urls http://sglang-w0:30000 http://sglang-w1:30000
      --host 0.0.0.0 --port 30000
    ports: ["13000:30000"]
    depends_on: [sglang-w0, sglang-w1]
```

> provider 注册 `api_base` 填：`http://sglang-router:30000/v1`（compose service 名）。

---

## 6. 验收 / 验证步骤

目标：证明（A）同 `session_id` 同前缀的请求**落同一 upstream**，（B）第二次请求 **cache hit > 0**。

### 6.1 连发两个同 session、同前缀请求

```bash
GW=http://localhost:8011/api/llm-gateway/v1     # 按本地端口
VKEY=<virtual-key>
SID=verify-sess-0001

for i in 1 2; do
  curl -s "$GW/chat/completions" \
    -H "Authorization: Bearer $VKEY" \
    -H "Content-Type: application/json" \
    -d '{
      "model": "Qwen2.5-32B-Instruct",
      "metadata": {"session_id": "'"$SID"'", "run_id": "'"$SID"'"},
      "messages": [
        {"role":"system","content":"You are a helpful assistant. <长且固定的前缀，≥512 tokens，确保进 prefix cache>"},
        {"role":"user","content":"第'$i'次提问，前缀完全相同"}
      ]
    }' | tee /tmp/resp_$i.json | python -m json.tool | grep -A4 '"usage"'
  echo "----- request $i done -----"
done
```

预期：
- 第 1 次 `cached_tokens`（或 `prompt_cache_hit_tokens`）≈ 0；
- 第 2 次 `cached_tokens` > 0（命中固定前缀）。

> 对 SGLang 开了 MTP 的情况，`cached_tokens` 可能恒 0——改看 `/metrics`（§6.4）。

### 6.2 验证落同一 upstream（看 LB access log）

```bash
# Nginx LB（compose）
docker compose logs llamacpp-lb | grep "$SID"        # 若日志格式含 upstream_addr，应两次同一台
# 建议在 nginx log_format 里加： upstream=$upstream_addr sid=$http_x_session_id

# Istio（k8s）
kubectl -n llm-engines logs deploy/istio-proxy ... | grep verify-sess-0001
# 或用 access log 的 upstream_host 字段确认两次相同
```

### 6.3 验证网关确实写了 cache 列（查 `llm_usage_record`）

cache 观测落在 `llm_gateway.llm_usage_record` 表的 `prompt_cache_hit_tokens` / `prompt_cache_miss_tokens` 列（migration `0003_usage_cache_tokens`）。

```sql
-- 在 llm-gateway 的 Postgres 上（注意 RLS：用对的 tenant 上下文或超级角色查）
SELECT id, model, prompt_tokens, total_tokens,
       prompt_cache_hit_tokens, prompt_cache_miss_tokens, created_at
FROM   llm_gateway.llm_usage_record
WHERE  created_at > now() - interval '10 minutes'
ORDER  BY created_at DESC
LIMIT  10;
```

预期：第 2 条记录的 `prompt_cache_hit_tokens > 0`。
> 注意：这些列只做**观测**，不进计费契约（计费只消费 `total_tokens`）。

### 6.4 引擎侧 Prometheus 兜底（vLLM / SGLang）

```bash
# vLLM
curl -s http://<vllm-pod>:8000/metrics | grep -E 'vllm:prefix_cache_(hits|queries)'
# SGLang（尤其开 MTP 时以此为准）
curl -s http://<sglang-worker>:30000/metrics | grep -iE 'cache'
```

---

## 7. 风险与注意

| # | 项 | 说明 | 处置 |
|---|----|------|------|
| 1 | **vLLM `cached_tokens=null` bug** | 近版偶发 usage 里 `cached_tokens` 为 null | 同时抓 `/metrics` 的 `vllm:prefix_cache_hits/queries` 兜底；**需在固定版本上实测确认** |
| 2 | **SGLang MTP 恒 0** | 开 MTP / 投机解码时 `cached_tokens` 恒 0（已知 bug） | provider 标 `cache_metric_unreliable=true`，以 Prometheus 为准 |
| 3 | **vLLM Router 成熟度** | 2025-12 较新 | 生产先用外部 nginx/Envoy 一致性哈希；vLLM Router **需实测确认**后再上 |
| 4 | **单实例命中粒度** | 四引擎缓存均为单实例（无默认跨副本共享）；vLLM 跨实例需 LMCache/kv_transfer，SGLang 有单实例 HiCache 分层 | 这就是**必须做会话亲和**的根因：不亲和 = 同会话散到多副本 = 几乎不命中 |
| 5 | **session 为空 = 正常降级** | metadata 无 `session_id` → 网关不注入 `X-Session-Id` → LB/router 无从哈希 → 退化为轮询/随机 → 不命中 | 这是**预期降级**，不是故障。但要确认 LB 对空 header 的退化行为（§4.1B / §5.1）**需实测** |
| 6 | **多 SGLang Router 副本 radix tree 不同步** | 同会话打到不同 router 副本 → 命中掉 10–20% | 必做 router 前置 consistent-hash（§4.3）；dev 单副本无此问题 |
| 7 | **provider_type 回退** | SGLang/llama.cpp 当前回退 `openai_compatible`，网关按 kind 的差异化归一化对它们不生效 | 待枚举补 `sglang`/`llamacpp` + `normalize_usage` 落地后切换；**实施前确认枚举与归一化任务状态** |
| 8 | **流式 trailing usage** | vLLM/SGLang 的 usage 在 `finish_reason` 之后的 trailing chunk | 需 `stream_options.include_usage=true`（网关流式已自动注入） |

### 需要在真引擎上实测确认的点（清单）

- vLLM `cached_tokens=null` 在你固定版本上是否复现，`/metrics` 兜底字段名是否一致。
- SGLang 是否启用 MTP；若启用，`cached_tokens` 恒 0 是否成立，Prometheus 对应指标名。
- Nginx `upstream-hash-by` / `hash ... consistent` 对**空 `X-Session-Id`** 的退化行为。
- Istio `consistentHash` 对缺失 header 的分布行为。
- vLLM Router（如评估）在 session 一致性哈希下的实际命中率与稳定性。
- llama.cpp `timings.cache_n` 与 `prompt_tokens_details.cached_tokens` 在你版本上是否都返回、哪个更准。
- 各引擎镜像 `<pin-version>` 与参数名是否随版本变动（参数名偶有重命名/默认值翻转）。

---

## 8. 来源（官方文档，截至 2026-06）

- **vLLM** Automatic Prefix Caching: https://docs.vllm.ai/en/latest/features/automatic_prefix_caching.html
- **vLLM** Metrics（`vllm:prefix_cache_*`）: https://docs.vllm.ai/en/latest/design/metrics.html
- **vLLM** OpenAI-compatible server / `prompt_tokens_details`: https://docs.vllm.ai/en/latest/serving/openai_compatible_server.html
- **SGLang** RadixAttention / cache: https://docs.sglang.ai/backend/radix_cache.html
- **SGLang** Router（cache-aware）: https://docs.sglang.ai/router/router.html
- **SGLang** Server arguments（`--enable-cache-report` / `--enable-metrics`）: https://docs.sglang.ai/backend/server_arguments.html
- **llama.cpp** server（`--cache-prompt` / `--cache-reuse` / `timings`）: https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md
- **DeepSeek** Context Caching（顶层 `prompt_cache_hit_tokens` / `miss_tokens`）: https://api-docs.deepseek.com/guides/kv_cache
- **Istio** DestinationRule `consistentHash`: https://istio.io/latest/docs/reference/config/networking/destination-rule/#LoadBalancerSettings-ConsistentHashLB
- **Nginx Ingress** `upstream-hash-by`: https://kubernetes.github.io/ingress-nginx/examples/affinity/cookie/ 及 annotations 文档

> 链接为官方文档入口，具体小节/参数名以你固定版本的对应文档为准。

---

**文档维护人**: 基础设施 / llm-gateway 团队
**编写日期**: 2026-06-12
**下次复审**: 引擎大版本升级或 `normalize_usage` / 亲和注入任务落地时
