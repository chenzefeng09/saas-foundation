"""Multi-engine prompt-cache usage normalization.

Different OpenAI-compatible inference backends report prompt-cache statistics in
incompatible shapes.  This module collapses them into a single
:class:`NormalizedUsage` structure so the gateway records consistent
``prompt_cache_hit_tokens`` / ``prompt_cache_miss_tokens`` regardless of the
upstream engine.

Per-engine sources (the "format" each engine maps to):

* **deepseek** (``"deepseek"``):
  DeepSeek surfaces cache stats as *top-level* fields on the ``usage`` object:
  ``usage.prompt_cache_hit_tokens`` and ``usage.prompt_cache_miss_tokens``.
  Newer responses may additionally carry the OpenAI-style nested
  ``usage.prompt_tokens_details.cached_tokens``; we prefer the top-level value
  and fall back to the nested one.

* **vLLM / SGLang** (``"openai_nested"``):
  Both engines follow the OpenAI shape, reporting cached prompt tokens under
  ``usage.prompt_tokens_details.cached_tokens``.  This is only populated when the
  engine is launched with the relevant flag
  (vLLM ``--enable-prompt-tokens-details``; SGLang ``--enable-cache-report``).
  vLLM has been observed to emit ``cached_tokens: null`` even when the field is
  present, so we coerce ``None`` to ``0``.  Misses are derived as
  ``prompt_tokens - hit`` (never negative).

* **llama.cpp** (``"llamacpp"``):
  llama.cpp's OpenAI-compatible server may emit
  ``usage.prompt_tokens_details.cached_tokens``, but the most reliable signal is
  its private ``timings.cache_n`` field on the *response* object.  We prefer the
  OpenAI-nested value and fall back to ``response.timings.cache_n``.

Format selection (decided policy): a per-engine default is chosen from
``kind``; a provider may *override* it via ``capabilities["cache_format"]``.

**Fail-open contract:** any missing/unexpected field yields ``0`` for that
metric.  No engine quirk may raise — a cache stat is observability, never a
hard dependency of the request path.
"""
from __future__ import annotations

from dataclasses import dataclass

__all__ = ["NormalizedUsage", "normalize_usage"]


# Default engine-kind → cache-report format.  ``capabilities["cache_format"]``
# overrides this per provider when an operator knows better (e.g. a vLLM build
# patched to emit DeepSeek-style top-level fields).
_KIND_TO_FORMAT: dict[str, str] = {
    "deepseek": "deepseek",
    "vllm": "openai_nested",
    "sglang": "openai_nested",
    "llamacpp": "llamacpp",
}

_DEFAULT_FORMAT = "openai_nested"


@dataclass(frozen=True)
class NormalizedUsage:
    """Engine-agnostic prompt-cache usage.

    ``cache_metric_unreliable`` is surfaced (copied from
    ``capabilities["cache_metric_unreliable"]``) so the caller may emit a
    warning — e.g. SGLang with MTP/speculative decoding reports cache numbers
    that do not reconcile cleanly.  This module never logs; it only carries the
    flag through.
    """

    prompt_tokens: int = 0
    completion_tokens: int = 0
    prompt_cache_hit_tokens: int = 0
    prompt_cache_miss_tokens: int = 0
    cache_metric_unreliable: bool = False


def _as_int(value: object) -> int:
    """Coerce a possibly-``None``/garbage usage field to a non-negative int."""
    if value is None:
        return 0
    try:
        n = int(value)
    except (TypeError, ValueError):
        return 0
    return n if n > 0 else 0


def normalize_usage(
    kind: str,
    raw_usage: dict | None,
    raw_response: dict | None,
    capabilities: dict | None,
) -> NormalizedUsage:
    """Normalize an engine's usage payload into :class:`NormalizedUsage`.

    Args:
        kind: provider kind string (e.g. ``"deepseek"``, ``"vllm"``,
            ``"sglang"``, ``"llamacpp"``). Unknown kinds default to
            ``openai_nested``.
        raw_usage: the upstream ``usage`` object (``response["usage"]``), or
            ``None``.
        raw_response: the full upstream JSON response, needed for
            llama.cpp's ``timings.cache_n`` fallback. May be ``None``.
        capabilities: the provider's ``capabilities`` dict. Recognized keys:
            ``cache_format`` (overrides the kind-derived format) and
            ``cache_metric_unreliable`` (copied onto the result for the caller).

    Returns:
        A :class:`NormalizedUsage`. All fields default to ``0`` when absent
        (fail-open). Never raises.
    """
    usage = raw_usage or {}
    caps = capabilities or {}

    prompt_tokens = _as_int(usage.get("prompt_tokens"))
    completion_tokens = _as_int(usage.get("completion_tokens"))

    effective_format = caps.get("cache_format") or _KIND_TO_FORMAT.get(kind, _DEFAULT_FORMAT)
    details = usage.get("prompt_tokens_details") or {}
    nested_cached = _as_int(details.get("cached_tokens"))

    if effective_format == "deepseek":
        # Prefer DeepSeek's top-level fields; fall back to OpenAI-nested.
        hit = _as_int(usage.get("prompt_cache_hit_tokens")) or nested_cached
        miss_top = usage.get("prompt_cache_miss_tokens")
        if miss_top is not None:
            miss = _as_int(miss_top)
        else:
            miss = max(0, prompt_tokens - hit)
    elif effective_format == "llamacpp":
        # OpenAI-nested first; fall back to llama.cpp's private timings.cache_n.
        hit = nested_cached
        if hit == 0:
            timings = (raw_response or {}).get("timings") or {}
            hit = _as_int(timings.get("cache_n"))
        miss = max(0, prompt_tokens - hit)
    else:
        # openai_nested (vllm / sglang / unknown): cached_tokens or 0.
        hit = nested_cached
        miss = max(0, prompt_tokens - hit)

    # Never let a bogus hit exceed prompt_tokens (keeps hit+miss == prompt_tokens
    # when prompt_tokens is known).
    if prompt_tokens and hit > prompt_tokens:
        hit = prompt_tokens
        if effective_format != "deepseek" or usage.get("prompt_cache_miss_tokens") is None:
            miss = 0

    return NormalizedUsage(
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        prompt_cache_hit_tokens=hit,
        prompt_cache_miss_tokens=miss,
        cache_metric_unreliable=bool(caps.get("cache_metric_unreliable", False)),
    )
