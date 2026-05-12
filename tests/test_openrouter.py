"""OpenRouter client wrapper tests (ARCH §8.2.6).

All HTTP is mocked — no live OpenRouter calls in CI. The mocks return
OpenAI-shaped chat-completion responses (with the OpenRouter-specific
`usage.cost` field) so we exercise the real openai SDK parsing path.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import pytest
from openai import APIStatusError, RateLimitError

from clinical_redteam.openrouter import (
    AllModelsFailedError,
    CompletionResult,
    OpenRouterClient,
    OpenRouterConfigError,
    _resolve_model_chain,
)


def _fake_response(text: str, model: str, cost: float = 0.0023) -> SimpleNamespace:
    """Build an OpenAI-shaped chat-completion response with OpenRouter cost."""
    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(content=text),
                finish_reason="stop",
            )
        ],
        usage=SimpleNamespace(
            prompt_tokens=42,
            completion_tokens=17,
            cost=cost,
        ),
        model=model,
    )


def _client_with_stub(stub_response_fn, env: dict[str, str]) -> OpenRouterClient:
    """Construct OpenRouterClient backed by a MagicMock for the openai SDK."""
    stub = MagicMock()
    stub.chat.completions.create.side_effect = stub_response_fn
    return OpenRouterClient(env=env, client=stub)


# ---------------------------------------------------------------------------
# Env-var resolution
# ---------------------------------------------------------------------------


def test_resolve_model_chain_red_team_with_fallbacks() -> None:
    env = {
        "RED_TEAM_MODEL": "primary",
        "RED_TEAM_FALLBACK_MODELS": "fallback1, fallback2 ,fallback3",
    }
    chain = _resolve_model_chain("red_team", env=env)
    assert chain == ["primary", "fallback1", "fallback2", "fallback3"]


def test_resolve_model_chain_judge_single_fallback() -> None:
    env = {"JUDGE_MODEL": "claude-sonnet-4", "JUDGE_FALLBACK_MODEL": "gpt-4o"}
    chain = _resolve_model_chain("judge", env=env)
    assert chain == ["claude-sonnet-4", "gpt-4o"]


def test_resolve_model_chain_documentation_no_fallback() -> None:
    env = {"DOCUMENTATION_MODEL": "claude-sonnet-4"}
    chain = _resolve_model_chain("documentation", env=env)
    assert chain == ["claude-sonnet-4"]


def test_resolve_model_chain_missing_primary_raises() -> None:
    with pytest.raises(OpenRouterConfigError, match="RED_TEAM_MODEL"):
        _resolve_model_chain("red_team", env={})


# ---------------------------------------------------------------------------
# Client init
# ---------------------------------------------------------------------------


def test_client_requires_api_key() -> None:
    with pytest.raises(OpenRouterConfigError, match="OPENROUTER_API_KEY"):
        OpenRouterClient(env={})


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_complete_happy_path_returns_completion_result() -> None:
    env = {
        "OPENROUTER_API_KEY": "test-key",
        "RED_TEAM_MODEL": "primary-model",
    }
    client = _client_with_stub(
        lambda **kwargs: _fake_response("hello world", model="primary-model"),
        env=env,
    )
    result = client.complete([{"role": "user", "content": "hi"}], tier="red_team")
    assert isinstance(result, CompletionResult)
    assert result.text == "hello world"
    assert result.model_used == "primary-model"
    assert result.cost_usd == 0.0023
    assert result.tokens_input == 42
    assert result.tokens_output == 17
    assert result.latency_ms >= 0
    assert result.finish_reason == "stop"


# ---------------------------------------------------------------------------
# Fallback on 429 + 5xx + connection error
# ---------------------------------------------------------------------------


def _rate_limit_error(model: str) -> RateLimitError:
    """Build a RateLimitError matching openai SDK's __init__ shape."""
    request = httpx.Request("POST", "https://openrouter.ai/api/v1/chat/completions")
    response = httpx.Response(429, request=request)
    return RateLimitError(
        message=f"rate limited on {model}", response=response, body=None
    )


def _server_error(model: str, status: int = 502) -> APIStatusError:
    request = httpx.Request("POST", "https://openrouter.ai/api/v1/chat/completions")
    response = httpx.Response(status, request=request)
    return APIStatusError(
        message=f"server error on {model}", response=response, body=None
    )


def test_complete_falls_back_on_rate_limit() -> None:
    env = {
        "OPENROUTER_API_KEY": "k",
        "RED_TEAM_MODEL": "primary",
        "RED_TEAM_FALLBACK_MODELS": "secondary",
    }
    calls: list[str] = []

    def stub(**kwargs):
        model = kwargs["model"]
        calls.append(model)
        if model == "primary":
            raise _rate_limit_error("primary")
        return _fake_response("via fallback", model=model)

    client = _client_with_stub(stub, env=env)
    result = client.complete([{"role": "user", "content": "x"}], tier="red_team")
    assert calls == ["primary", "secondary"]
    assert result.model_used == "secondary"
    assert result.text == "via fallback"


def test_complete_falls_back_on_5xx() -> None:
    env = {
        "OPENROUTER_API_KEY": "k",
        "RED_TEAM_MODEL": "primary",
        "RED_TEAM_FALLBACK_MODELS": "secondary",
    }

    def stub(**kwargs):
        if kwargs["model"] == "primary":
            raise _server_error("primary", status=503)
        return _fake_response("ok", model=kwargs["model"])

    client = _client_with_stub(stub, env=env)
    result = client.complete([{"role": "user", "content": "x"}], tier="red_team")
    assert result.model_used == "secondary"


def test_complete_falls_back_on_connect_error() -> None:
    env = {
        "OPENROUTER_API_KEY": "k",
        "RED_TEAM_MODEL": "primary",
        "RED_TEAM_FALLBACK_MODELS": "secondary",
    }

    def stub(**kwargs):
        if kwargs["model"] == "primary":
            raise httpx.ConnectError("boom")
        return _fake_response("ok", model=kwargs["model"])

    client = _client_with_stub(stub, env=env)
    result = client.complete([{"role": "user", "content": "x"}], tier="red_team")
    assert result.model_used == "secondary"


def test_complete_all_models_fail_raises() -> None:
    env = {
        "OPENROUTER_API_KEY": "k",
        "RED_TEAM_MODEL": "primary",
        "RED_TEAM_FALLBACK_MODELS": "secondary,tertiary",
    }

    def stub(**kwargs):
        raise _rate_limit_error(kwargs["model"])

    client = _client_with_stub(stub, env=env)
    with pytest.raises(AllModelsFailedError) as info:
        client.complete([{"role": "user", "content": "x"}], tier="red_team")
    assert info.value.tier == "red_team"
    assert [m for m, _ in info.value.attempts] == ["primary", "secondary", "tertiary"]


def test_complete_falls_back_on_404() -> None:
    """A 404 from OpenRouter means the named model has been delisted /
    renamed in the catalog. The fallback chain should be tried before
    propagating — otherwise a stale model ID in .env wedges the daemon.

    Regression test for Tate's openrouter-404-fallback-tate-to-aria.md
    coordination ticket (LOW; surfaced during B6 run-1).
    """
    env = {
        "OPENROUTER_API_KEY": "k",
        "RED_TEAM_MODEL": "delisted-primary",
        "RED_TEAM_FALLBACK_MODELS": "live-secondary",
    }
    calls: list[str] = []

    def stub(**kwargs):
        calls.append(kwargs["model"])
        if kwargs["model"] == "delisted-primary":
            raise _server_error("delisted-primary", status=404)
        return _fake_response("via fallback", model=kwargs["model"])

    client = _client_with_stub(stub, env=env)
    result = client.complete([{"role": "user", "content": "x"}], tier="red_team")
    assert calls == ["delisted-primary", "live-secondary"]
    assert result.model_used == "live-secondary"


def test_complete_4xx_other_than_429_does_not_fallback() -> None:
    """A 400/401/403 means the request itself is bad — fallback won't help.

    The error should propagate so the caller can fix the request.
    """
    env = {
        "OPENROUTER_API_KEY": "k",
        "RED_TEAM_MODEL": "primary",
        "RED_TEAM_FALLBACK_MODELS": "secondary",
    }

    def stub(**kwargs):
        raise _server_error(kwargs["model"], status=400)

    client = _client_with_stub(stub, env=env)
    with pytest.raises(APIStatusError):
        client.complete([{"role": "user", "content": "x"}], tier="red_team")


def test_complete_401_does_not_fallback() -> None:
    """401 = bad API key. Fallback won't help — every model uses the same
    key. Regression guard added per audit R3 (quality-pass-1).
    """
    env = {
        "OPENROUTER_API_KEY": "k",
        "RED_TEAM_MODEL": "primary",
        "RED_TEAM_FALLBACK_MODELS": "secondary",
    }
    calls: list[str] = []

    def stub(**kwargs):
        calls.append(kwargs["model"])
        raise _server_error(kwargs["model"], status=401)

    client = _client_with_stub(stub, env=env)
    with pytest.raises(APIStatusError):
        client.complete([{"role": "user", "content": "x"}], tier="red_team")
    # Primary attempted exactly once; no fallback retry
    assert calls == ["primary"]


def test_complete_403_does_not_fallback() -> None:
    """403 = forbidden (account suspended, model unavailable to this key).
    Same reasoning as 401. Regression guard per audit R3.
    """
    env = {
        "OPENROUTER_API_KEY": "k",
        "RED_TEAM_MODEL": "primary",
        "RED_TEAM_FALLBACK_MODELS": "secondary",
    }
    calls: list[str] = []

    def stub(**kwargs):
        calls.append(kwargs["model"])
        raise _server_error(kwargs["model"], status=403)

    client = _client_with_stub(stub, env=env)
    with pytest.raises(APIStatusError):
        client.complete([{"role": "user", "content": "x"}], tier="red_team")
    assert calls == ["primary"]


# ---------------------------------------------------------------------------
# Cost extraction
# ---------------------------------------------------------------------------


def test_complete_handles_missing_cost_field() -> None:
    """Older OpenRouter responses may omit `usage.cost`; treat as 0.0
    (cost_ledger.py will fill in via per-model pricing tables)."""
    env = {"OPENROUTER_API_KEY": "k", "RED_TEAM_MODEL": "primary"}

    response = SimpleNamespace(
        choices=[
            SimpleNamespace(message=SimpleNamespace(content="x"), finish_reason="stop")
        ],
        usage=SimpleNamespace(prompt_tokens=1, completion_tokens=1),
        model="primary",
    )
    client = _client_with_stub(lambda **kwargs: response, env=env)
    result = client.complete([{"role": "user", "content": "x"}], tier="red_team")
    assert result.cost_usd == 0.0
