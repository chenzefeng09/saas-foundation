"""Unit tests for multi-engine prompt-cache usage normalization.

Covers the four cache-report formats (deepseek top-level, deepseek nested,
vllm/sglang openai_nested, llamacpp timings fallback), the fail-open contract
(missing fields → 0), and the capabilities.cache_format override.
"""
from __future__ import annotations

from foundation_llm_gateway.services.cache_usage import (
    NormalizedUsage,
    normalize_usage,
)


class TestDeepSeekFormat:
    def test_top_level_fields(self):
        usage = {
            "prompt_tokens": 100,
            "completion_tokens": 20,
            "prompt_cache_hit_tokens": 80,
            "prompt_cache_miss_tokens": 20,
        }
        n = normalize_usage("deepseek", usage, {"usage": usage}, {})
        assert n.prompt_tokens == 100
        assert n.completion_tokens == 20
        assert n.prompt_cache_hit_tokens == 80
        assert n.prompt_cache_miss_tokens == 20

    def test_nested_fallback_when_no_top_level(self):
        """DeepSeek response carrying only OpenAI-nested cached_tokens."""
        usage = {
            "prompt_tokens": 100,
            "completion_tokens": 20,
            "prompt_tokens_details": {"cached_tokens": 60},
        }
        n = normalize_usage("deepseek", usage, {"usage": usage}, {})
        assert n.prompt_cache_hit_tokens == 60
        # miss derived: prompt - hit
        assert n.prompt_cache_miss_tokens == 40

    def test_top_level_preferred_over_nested(self):
        usage = {
            "prompt_tokens": 100,
            "prompt_cache_hit_tokens": 70,
            "prompt_tokens_details": {"cached_tokens": 10},
        }
        n = normalize_usage("deepseek", usage, {"usage": usage}, {})
        assert n.prompt_cache_hit_tokens == 70
        assert n.prompt_cache_miss_tokens == 30  # derived since miss absent


class TestOpenAINestedFormat:
    def test_vllm_nested_cached_tokens(self):
        usage = {
            "prompt_tokens": 50,
            "completion_tokens": 10,
            "prompt_tokens_details": {"cached_tokens": 30},
        }
        n = normalize_usage("vllm", usage, {"usage": usage}, {})
        assert n.prompt_cache_hit_tokens == 30
        assert n.prompt_cache_miss_tokens == 20

    def test_vllm_cached_tokens_null_falls_back_to_zero(self):
        """vLLM is observed to emit cached_tokens: null — must coerce to 0."""
        usage = {
            "prompt_tokens": 50,
            "completion_tokens": 10,
            "prompt_tokens_details": {"cached_tokens": None},
        }
        n = normalize_usage("vllm", usage, {"usage": usage}, {})
        assert n.prompt_cache_hit_tokens == 0
        assert n.prompt_cache_miss_tokens == 50

    def test_sglang_nested(self):
        usage = {
            "prompt_tokens": 200,
            "completion_tokens": 40,
            "prompt_tokens_details": {"cached_tokens": 150},
        }
        n = normalize_usage("sglang", usage, {"usage": usage}, {})
        assert n.prompt_cache_hit_tokens == 150
        assert n.prompt_cache_miss_tokens == 50

    def test_unknown_kind_defaults_to_openai_nested(self):
        usage = {"prompt_tokens": 10, "prompt_tokens_details": {"cached_tokens": 4}}
        n = normalize_usage("some-future-engine", usage, {"usage": usage}, {})
        assert n.prompt_cache_hit_tokens == 4
        assert n.prompt_cache_miss_tokens == 6


class TestLlamaCppFormat:
    def test_timings_cache_n_fallback(self):
        """No nested cached_tokens → read llama.cpp private timings.cache_n."""
        usage = {"prompt_tokens": 90, "completion_tokens": 15}
        response = {"usage": usage, "timings": {"cache_n": 64}}
        n = normalize_usage("llamacpp", usage, response, {})
        assert n.prompt_cache_hit_tokens == 64
        assert n.prompt_cache_miss_tokens == 26

    def test_nested_preferred_over_timings(self):
        usage = {
            "prompt_tokens": 90,
            "prompt_tokens_details": {"cached_tokens": 70},
        }
        response = {"usage": usage, "timings": {"cache_n": 10}}
        n = normalize_usage("llamacpp", usage, response, {})
        assert n.prompt_cache_hit_tokens == 70
        assert n.prompt_cache_miss_tokens == 20

    def test_no_cache_signal_at_all(self):
        usage = {"prompt_tokens": 90, "completion_tokens": 15}
        n = normalize_usage("llamacpp", usage, {"usage": usage}, {})
        assert n.prompt_cache_hit_tokens == 0
        assert n.prompt_cache_miss_tokens == 90


class TestFailOpen:
    def test_all_fields_missing(self):
        n = normalize_usage("deepseek", None, None, None)
        assert n == NormalizedUsage()
        assert n.prompt_tokens == 0
        assert n.completion_tokens == 0
        assert n.prompt_cache_hit_tokens == 0
        assert n.prompt_cache_miss_tokens == 0

    def test_empty_usage_dict(self):
        n = normalize_usage("vllm", {}, {}, {})
        assert n.prompt_cache_hit_tokens == 0
        assert n.prompt_cache_miss_tokens == 0

    def test_garbage_field_types_do_not_raise(self):
        usage = {
            "prompt_tokens": "not-a-number",
            "prompt_tokens_details": {"cached_tokens": "oops"},
        }
        n = normalize_usage("vllm", usage, {"usage": usage}, {})
        assert n.prompt_tokens == 0
        assert n.prompt_cache_hit_tokens == 0

    def test_hit_exceeding_prompt_is_clamped(self):
        usage = {"prompt_tokens": 10, "prompt_tokens_details": {"cached_tokens": 999}}
        n = normalize_usage("vllm", usage, {"usage": usage}, {})
        assert n.prompt_cache_hit_tokens == 10
        assert n.prompt_cache_miss_tokens == 0


class TestCapabilitiesOverride:
    def test_cache_format_overrides_kind(self):
        """A provider registered as vllm but flagged cache_format=deepseek
        must read DeepSeek top-level fields, not openai_nested."""
        usage = {
            "prompt_tokens": 100,
            "prompt_cache_hit_tokens": 88,
            "prompt_cache_miss_tokens": 12,
        }
        caps = {"cache_format": "deepseek"}
        n = normalize_usage("vllm", usage, {"usage": usage}, caps)
        assert n.prompt_cache_hit_tokens == 88
        assert n.prompt_cache_miss_tokens == 12

    def test_cache_metric_unreliable_flag_carried_through(self):
        usage = {"prompt_tokens": 10, "prompt_tokens_details": {"cached_tokens": 4}}
        caps = {"cache_metric_unreliable": True}
        n = normalize_usage("sglang", usage, {"usage": usage}, caps)
        assert n.cache_metric_unreliable is True
        # Still returns normal numbers — flag is advisory only.
        assert n.prompt_cache_hit_tokens == 4

    def test_unreliable_defaults_false(self):
        n = normalize_usage("vllm", {"prompt_tokens": 5}, {}, {})
        assert n.cache_metric_unreliable is False
