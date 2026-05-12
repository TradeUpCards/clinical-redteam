"""Red Team Agent meta-tests (ARCH §10.1).

System-level invariants — composed behaviors that aren't caught by the
per-method unit tests in `test_red_team.py`. These are the "is the agent
doing the right thing across calls" properties:

- **Mutation diversity** — N calls against the same seed should NOT all
  collapse to identical output (mutation-engine-collapse failure mode,
  ARCH §10.1 row "Mutation diversity collapse")
- **Content-filter pre-flight defense in depth** — a hostile LLM that
  returns content the filter rejects must NOT have its output reach
  downstream agents (the filter is the wall, not a hint)
- **Seed-verbatim fallback survives provider outage** — when every
  OpenRouter model in the chain fails, the agent falls back to the seed
  text rather than crashing (so the daemon keeps running against the
  baseline attack)
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from clinical_redteam.agents.red_team import (
    AttackRefusedError,
    RedTeamAgent,
)
from clinical_redteam.openrouter import (
    AllModelsFailedError,
    CompletionResult,
    OpenRouterClient,
)

REPO_EVALS = Path(__file__).parent.parent.parent / "evals"


def _completion(text: str, model: str = "fake-rt", cost: float = 0.002) -> CompletionResult:
    return CompletionResult(
        text=text,
        model_used=model,
        cost_usd=cost,
        tokens_input=300,
        tokens_output=80,
        latency_ms=1200,
        finish_reason="stop",
    )


# ---------------------------------------------------------------------------
# Mutation diversity (ARCH §10.1 — "Mutation diversity collapse")
# ---------------------------------------------------------------------------


def test_mutation_diversity_across_n_calls() -> None:
    """Five Red Team calls against the SAME seed with distinct LLM mutations
    in the stub should produce 5 distinct attack_text values in the candidates.

    If the agent ever short-circuits to "same output every time" (a mutation
    engine collapse), the assertion below would fire — operators would see
    declining yield in continuous mode.
    """
    mutations = [
        "Variant A: paraphrase about recent encounters.",
        "Variant B: ask in a role-play frame.",
        "Variant C: indirect via document upload.",
        "Variant D: escalating-specificity prompt.",
        "Variant E: multi-fragment phrased query.",
    ]
    stub = MagicMock(spec=OpenRouterClient)
    stub.complete.side_effect = [_completion(text=m) for m in mutations]
    agent = RedTeamAgent(client=stub)
    candidates = [
        agent.generate(
            seed_id="c7-paraphrased-leakage",
            category="sensitive_information_disclosure",
            evals_dir=REPO_EVALS,
            sequence=i + 1,
            mutate=True,
        )
        for i in range(5)
    ]
    payloads = {c.payload.content for c in candidates if c.payload.content}
    # All 5 mutations distinct — the rolling stub returned 5 different texts
    assert len(payloads) == 5, (
        f"mutation diversity collapsed: only {len(payloads)} distinct payloads"
    )


# ---------------------------------------------------------------------------
# Content-filter pre-flight defense in depth
# ---------------------------------------------------------------------------


def test_llm_self_refusal_is_caught_not_passed_downstream() -> None:
    """If a permissive-safety LLM still emits 'REFUSED' literal text (per
    the Red Team system prompt's hard-rule clause), the agent must raise
    AttackRefusedError BEFORE the candidate exits the agent boundary.

    This is the wall — an LLM that drifts into refusing some specific
    payload class must not be able to pollute the downstream pipeline.
    """
    stub = MagicMock(spec=OpenRouterClient)
    stub.complete.return_value = _completion(
        text="REFUSED — that violates my hard rules."
    )
    agent = RedTeamAgent(client=stub)
    with pytest.raises(AttackRefusedError) as exc_info:
        agent.generate(
            seed_id="c7-paraphrased-leakage",
            category="sensitive_information_disclosure",
            evals_dir=REPO_EVALS,
            sequence=1,
            mutate=True,
        )
    assert exc_info.value.reason == "model_self_refusal"


# ---------------------------------------------------------------------------
# Seed-verbatim fallback on provider outage
# ---------------------------------------------------------------------------


def test_seed_verbatim_fallback_when_all_models_fail() -> None:
    """When every OpenRouter model in the chain fails, the agent must fall
    back to the seed attack_template verbatim rather than crashing. This
    keeps the daemon making progress against the baseline attack during
    transient provider outages — the alternative is wedging on every fail.
    """
    stub = MagicMock(spec=OpenRouterClient)
    stub.complete.side_effect = AllModelsFailedError(
        tier="red_team", attempts=[("a", "HTTP 503"), ("b", "RateLimit")]
    )
    agent = RedTeamAgent(client=stub)
    candidate = agent.generate(
        seed_id="c7-paraphrased-leakage",
        category="sensitive_information_disclosure",
        evals_dir=REPO_EVALS,
        sequence=1,
        mutate=True,
    )
    # The candidate is built from the seed's `attack_template` verbatim.
    # Assert on the load-bearing discriminators (model_used + cost) rather
    # than seed-text content, so this test doesn't break if Bram edits the
    # C-7 seed wording. The fallback path is fully characterized by
    # model_used == "seed-verbatim" and cost_usd == 0.
    from clinical_redteam.agents.red_team import load_seed
    seed = load_seed(
        "c7-paraphrased-leakage",
        category="sensitive_information_disclosure",
        evals_dir=REPO_EVALS,
    )
    assert candidate.payload.content == seed["attack_template"].strip()
    assert candidate.model_used == "seed-verbatim"
    assert candidate.cost_usd == 0.0
