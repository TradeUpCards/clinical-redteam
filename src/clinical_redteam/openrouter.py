"""OpenRouter client wrapper (ARCH §8.2.6).

Single auth + telemetry surface for every LLM call from every agent. Reads
model IDs from env vars (ARCH §8.2) — model choice is configurable, not
hard-coded; the SELECTION CRITERIA are the architectural commitment.

Fallback chain triggers on rate-limit (429) and server-error (5xx). Returns
a structured CompletionResult so the Orchestrator's cost ledger and the
Langfuse trace layer can read per-call cost + latency + token counts
without re-parsing OpenAI response shapes.

NOT included here (intentionally):
- Langfuse instrumentation — composed on top in observability.py (Phase 1a #12)
- Retry-with-backoff — handled by the openai SDK's default retry behavior;
  fallback to next model is OUR responsibility, retries on the same model are
  the SDK's
- Streaming — MVP runs single-shot; streaming is Phase 2

Env vars (subset, full list in .env.example):
  OPENROUTER_API_KEY (required)
  OPENROUTER_BASE_URL (default: https://openrouter.ai/api/v1)
  RED_TEAM_MODEL / RED_TEAM_FALLBACK_MODELS (comma-separated)
  JUDGE_MODEL / JUDGE_FALLBACK_MODEL
  DOCUMENTATION_MODEL / DOCUMENTATION_FALLBACK_MODEL
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Literal

import httpx
from openai import APIStatusError, OpenAI, RateLimitError

logger = logging.getLogger(__name__)


Tier = Literal["red_team", "judge", "documentation"]
"""Routing tier. Maps to one primary model + a fallback chain via env vars."""


# ---------------------------------------------------------------------------
# Tier → env var resolution
# ---------------------------------------------------------------------------


_PRIMARY_VAR_BY_TIER: dict[Tier, str] = {
    "red_team": "RED_TEAM_MODEL",
    "judge": "JUDGE_MODEL",
    "documentation": "DOCUMENTATION_MODEL",
}

_FALLBACK_VAR_BY_TIER: dict[Tier, str] = {
    "red_team": "RED_TEAM_FALLBACK_MODELS",
    "judge": "JUDGE_FALLBACK_MODEL",
    "documentation": "DOCUMENTATION_FALLBACK_MODEL",
}


def _resolve_model_chain(tier: Tier, env: dict[str, str] | None = None) -> list[str]:
    """Read primary + fallback model IDs for a tier from env vars.

    Returns ordered list `[primary, *fallbacks]`. Comma-separated fallback
    lists are split + stripped. Empty entries are dropped. Raises if no
    primary model is configured.
    """
    e = env if env is not None else os.environ
    primary = e.get(_PRIMARY_VAR_BY_TIER[tier], "").strip()
    if not primary:
        raise OpenRouterConfigError(
            f"Missing required env var {_PRIMARY_VAR_BY_TIER[tier]!r} for tier {tier!r}. "
            f"See .env.example for the per-tier model selection criteria (ARCH §8.2)."
        )
    raw_fallbacks = e.get(_FALLBACK_VAR_BY_TIER[tier], "")
    fallbacks = [m.strip() for m in raw_fallbacks.split(",") if m.strip()]
    return [primary, *fallbacks]


# ---------------------------------------------------------------------------
# Result + error types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CompletionResult:
    """One LLM completion's worth of substrate for the cost ledger + Langfuse."""

    text: str
    model_used: str
    cost_usd: float
    tokens_input: int
    tokens_output: int
    latency_ms: int
    finish_reason: str | None


class OpenRouterError(Exception):
    """Base class for OpenRouter wrapper errors."""


class OpenRouterConfigError(OpenRouterError):
    """Missing or malformed configuration (env vars)."""


class AllModelsFailedError(OpenRouterError):
    """Every model in the fallback chain failed (429 / 5xx / network)."""

    def __init__(self, tier: Tier, attempts: list[tuple[str, str]]) -> None:
        self.tier = tier
        self.attempts = attempts
        formatted = "; ".join(f"{m}: {err}" for m, err in attempts)
        super().__init__(
            f"All models in tier {tier!r} failed. Attempts: {formatted}"
        )


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class OpenRouterClient:
    """Synchronous OpenRouter client over the OpenAI-compatible API.

    OpenRouter is OpenAI-compatible (ARCH §8.2.6) so we use the upstream
    `openai` SDK with `base_url` pointed at OpenRouter. This keeps the call
    surface familiar and means the SDK's own retry / timeout machinery
    handles transient failures within a single model attempt; our wrapper
    only handles fallback to the NEXT model.
    """

    DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        env: dict[str, str] | None = None,
        client: OpenAI | None = None,
    ) -> None:
        e = env if env is not None else os.environ
        self._env = e
        resolved_key = api_key or e.get("OPENROUTER_API_KEY", "").strip()
        if not resolved_key:
            raise OpenRouterConfigError(
                "OPENROUTER_API_KEY is required (see .env.example)."
            )
        resolved_base = base_url or e.get("OPENROUTER_BASE_URL", self.DEFAULT_BASE_URL)
        self._client = client or OpenAI(
            api_key=resolved_key,
            base_url=resolved_base,
            default_headers={
                "HTTP-Referer": "https://github.com/TradeUpCards/clinical-redteam",
                "X-Title": "Clinical Red Team Platform",
            },
        )

    def complete(
        self,
        messages: list[dict[str, str]],
        *,
        tier: Tier,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> CompletionResult:
        """Run a chat completion against the tier's model chain.

        Tries primary first; on 429 / 5xx / connection error, tries each
        fallback in order. Raises AllModelsFailedError if every model fails.
        """
        chain = _resolve_model_chain(tier, env=self._env)
        attempts: list[tuple[str, str]] = []

        for model in chain:
            started = time.perf_counter()
            try:
                response = self._client.chat.completions.create(
                    model=model,
                    messages=messages,  # type: ignore[arg-type]
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
            except (RateLimitError, httpx.ConnectError, httpx.ReadTimeout) as exc:
                attempts.append((model, type(exc).__name__))
                logger.warning("OpenRouter model %s failed (%s); trying next", model, exc)
                continue
            except APIStatusError as exc:
                if 500 <= exc.status_code < 600:
                    attempts.append((model, f"HTTP {exc.status_code}"))
                    logger.warning(
                        "OpenRouter model %s returned %s; trying next", model, exc.status_code
                    )
                    continue
                raise

            latency_ms = int((time.perf_counter() - started) * 1000)
            choice = response.choices[0]
            usage = response.usage
            return CompletionResult(
                text=(choice.message.content or "").strip(),
                model_used=model,
                cost_usd=_extract_cost_usd(response),
                tokens_input=usage.prompt_tokens if usage else 0,
                tokens_output=usage.completion_tokens if usage else 0,
                latency_ms=latency_ms,
                finish_reason=choice.finish_reason,
            )

        raise AllModelsFailedError(tier=tier, attempts=attempts)


def _extract_cost_usd(response: object) -> float:
    """Read the per-call cost from OpenRouter's response extension.

    OpenRouter exposes `usage.cost` in its OpenAI-compatible responses; for
    older surfaces it may appear under `usage["cost"]` or be absent (in which
    case we return 0.0 and rely on the cost ledger's per-model fallback
    pricing — implemented in cost_ledger.py at Phase 1a #11).
    """
    usage = getattr(response, "usage", None)
    if usage is None:
        return 0.0
    cost = getattr(usage, "cost", None)
    if cost is None and isinstance(usage, dict):
        cost = usage.get("cost")
    return float(cost) if cost is not None else 0.0


__all__ = [
    "AllModelsFailedError",
    "CompletionResult",
    "OpenRouterClient",
    "OpenRouterConfigError",
    "OpenRouterError",
    "Tier",
]
