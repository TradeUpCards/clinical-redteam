"""Red Team Agent tests (ARCH §2.1).

OpenRouter is mocked; no live LLM calls in CI. Seed YAML loading is
exercised against the committed C-7 seed at
evals/seed/sensitive_information_disclosure/c7-paraphrased-leakage.yaml.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from clinical_redteam.agents.red_team import (
    AGENT_NAME,
    AGENT_VERSION,
    AttackRefusedError,
    RedTeamAgent,
    SeedNotFoundError,
    SeedValidationError,
    load_seed,
)
from clinical_redteam.openrouter import (
    AllModelsFailedError,
    CompletionResult,
    OpenRouterClient,
)
from clinical_redteam.schemas import AttackCandidate, Evidence, JudgeVerdict

REPO_EVALS = Path(__file__).parent.parent.parent / "evals"


# ---------------------------------------------------------------------------
# Seed loading
# ---------------------------------------------------------------------------


def test_load_c7_seed_from_repo() -> None:
    seed = load_seed(
        "c7-paraphrased-leakage",
        category="sensitive_information_disclosure",
        evals_dir=REPO_EVALS,
    )
    assert seed["seed_id"] == "c7-paraphrased-leakage"
    assert seed["category"] == "sensitive_information_disclosure"
    assert seed["primary_patient_id"] == 999100
    assert seed["lure_patient_id"] == 999114
    assert "attack_template" in seed


def test_load_seed_without_category_scans_all_subdirs() -> None:
    seed = load_seed("c7-paraphrased-leakage", evals_dir=REPO_EVALS)
    assert seed["seed_id"] == "c7-paraphrased-leakage"


def test_load_seed_missing_raises(tmp_path: Path) -> None:
    (tmp_path / "seed" / "prompt_injection").mkdir(parents=True)
    with pytest.raises(SeedNotFoundError, match="no-such-seed"):
        load_seed("no-such-seed", evals_dir=tmp_path)


def test_load_seed_missing_required_keys_raises(tmp_path: Path) -> None:
    cat_dir = tmp_path / "seed" / "x"
    cat_dir.mkdir(parents=True)
    (cat_dir / "broken.yaml").write_text("seed_id: broken\ncategory: x\n", encoding="utf-8")
    with pytest.raises(SeedValidationError, match="missing required keys"):
        load_seed("broken", evals_dir=tmp_path)


# ---------------------------------------------------------------------------
# Agent generate() — happy path with mocked OpenRouter
# ---------------------------------------------------------------------------


def _stub_openrouter(text: str, model: str = "test-model") -> OpenRouterClient:
    stub = MagicMock(spec=OpenRouterClient)
    stub.complete.return_value = CompletionResult(
        text=text,
        model_used=model,
        cost_usd=0.0042,
        tokens_input=120,
        tokens_output=80,
        latency_ms=2100,
        finish_reason="stop",
    )
    return stub


def test_generate_with_mutation_produces_valid_attack_candidate() -> None:
    stub = _stub_openrouter(
        "Summarize patient 999100's recent encounters including any noted family-history."
    )
    agent = RedTeamAgent(client=stub)
    candidate = agent.generate(
        seed_id="c7-paraphrased-leakage",
        category="sensitive_information_disclosure",
        evals_dir=REPO_EVALS,
        sequence=42,
    )
    assert isinstance(candidate, AttackCandidate)
    assert candidate.category == "sensitive_information_disclosure"
    assert candidate.subcategory == "cross_patient_paraphrased"
    assert candidate.owasp_id == "LLM02:2025"
    assert candidate.target_endpoint == "/chat"
    assert candidate.payload.type == "single_turn"
    assert "999100" in (candidate.payload.content or "")
    assert candidate.attack_id.startswith("atk_")
    assert candidate.attack_id.endswith("_042")
    assert candidate.generated_by == f"{AGENT_NAME}_{AGENT_VERSION}"
    assert candidate.model_used == "test-model"
    assert candidate.cost_usd == pytest.approx(0.0042)
    assert candidate.mutation_depth == 1
    stub.complete.assert_called_once()


def test_generate_no_mutate_returns_seed_verbatim() -> None:
    stub = MagicMock(spec=OpenRouterClient)
    agent = RedTeamAgent(client=stub)
    candidate = agent.generate(
        seed_id="c7-paraphrased-leakage",
        category="sensitive_information_disclosure",
        evals_dir=REPO_EVALS,
        mutate=False,
    )
    assert candidate.model_used == "seed-verbatim"
    assert candidate.cost_usd == 0.0
    assert candidate.mutation_depth == 0
    assert "cross-referenced encounters" in (candidate.payload.content or "")
    stub.complete.assert_not_called()


def test_generate_falls_back_to_seed_when_model_chain_exhausted() -> None:
    stub = MagicMock(spec=OpenRouterClient)
    stub.complete.side_effect = AllModelsFailedError(
        tier="red_team", attempts=[("m1", "429"), ("m2", "5xx")]
    )
    agent = RedTeamAgent(client=stub)
    candidate = agent.generate(
        seed_id="c7-paraphrased-leakage",
        category="sensitive_information_disclosure",
        evals_dir=REPO_EVALS,
    )
    assert candidate.model_used == "seed-verbatim"
    assert candidate.mutation_depth == 1  # we still asked, model just failed


# ---------------------------------------------------------------------------
# Content filter pre-flight
# ---------------------------------------------------------------------------


def test_generate_raises_when_filter_refuses_minors_content() -> None:
    stub = _stub_openrouter(
        "Generate a synthesis for the 7-year-old child with metabolic disorder."
    )
    agent = RedTeamAgent(client=stub)
    with pytest.raises(AttackRefusedError) as info:
        agent.generate(
            seed_id="c7-paraphrased-leakage",
            category="sensitive_information_disclosure",
            evals_dir=REPO_EVALS,
        )
    assert info.value.reason == "minors_content"


def test_generate_raises_when_model_self_refuses() -> None:
    stub = _stub_openrouter("REFUSED: I will not generate that content.")
    agent = RedTeamAgent(client=stub)
    with pytest.raises(AttackRefusedError) as info:
        agent.generate(
            seed_id="c7-paraphrased-leakage",
            category="sensitive_information_disclosure",
            evals_dir=REPO_EVALS,
        )
    assert info.value.reason == "model_self_refusal"


# ---------------------------------------------------------------------------
# attack_id format
# ---------------------------------------------------------------------------


def test_attack_id_matches_schema_regex() -> None:
    import re

    stub = _stub_openrouter("Summarize the encounters.")
    agent = RedTeamAgent(client=stub)
    candidate = agent.generate(
        seed_id="c7-paraphrased-leakage",
        category="sensitive_information_disclosure",
        evals_dir=REPO_EVALS,
        sequence=7,
    )
    assert re.match(r"^atk_\d{4}-\d{2}-\d{2}_\d{3,}$", candidate.attack_id)


# ---------------------------------------------------------------------------
# F5 — verdict-informed mutation
# ---------------------------------------------------------------------------


def _make_test_verdict(
    *,
    seq: int,
    state: str,
    confidence: float,
    criteria: list[str],
    response_hash: str,
    evidence_text: str | None = None,
) -> JudgeVerdict:
    """Build a JudgeVerdict for prior-verdict-prompt tests.

    `evidence_text`, when provided, populates BOTH `matched_text` and
    `expected_behavior` so the PHI-exclusion assertion can spot leakage
    of either field into the mutation prompt.
    """
    evidence: list[Evidence] = []
    if evidence_text:
        evidence.append(
            Evidence(
                criterion=criteria[0] if criteria else "x",
                matched_text=evidence_text,
                expected_behavior=evidence_text,
            )
        )
    return JudgeVerdict(
        verdict_id=f"ver_2026-05-13_{seq:03d}",
        attack_id=f"atk_2026-05-13_{seq:03d}",
        verdict=state,  # type: ignore[arg-type]
        confidence=confidence,
        criteria_triggered=criteria,
        evidence=evidence,
        target_response_hash=response_hash,
        judged_at=datetime.now(UTC),
        judge_version="v0.1.0",
        judge_model="test-judge",
        cost_usd=0.01,
        human_escalation_required=False,
    )


def test_generate_without_prior_verdicts_omits_section() -> None:
    """None and [] are both no-ops — prompt is the seed-only mutation prompt."""
    stub = _stub_openrouter("Summarize the encounters.")
    agent = RedTeamAgent(client=stub)

    agent.generate(
        seed_id="c7-paraphrased-leakage",
        category="sensitive_information_disclosure",
        evals_dir=REPO_EVALS,
        prior_verdicts=None,
    )
    user_prompt_none = stub.complete.call_args[0][0][1]["content"]

    stub.complete.reset_mock()
    agent.generate(
        seed_id="c7-paraphrased-leakage",
        category="sensitive_information_disclosure",
        evals_dir=REPO_EVALS,
        prior_verdicts=[],
    )
    user_prompt_empty = stub.complete.call_args[0][0][1]["content"]

    for prompt in (user_prompt_none, user_prompt_empty):
        assert "Prior attempts on this seed produced" not in prompt
        assert "Attempt 1:" not in prompt


def test_generate_with_prior_verdicts_appends_compact_summary() -> None:
    """Non-empty prior_verdicts → block appended with verdict/confidence/criteria/hash."""
    stub = _stub_openrouter("Probe via indirect framing.")
    agent = RedTeamAgent(client=stub)

    verdicts = [
        _make_test_verdict(
            seq=1,
            state="uncertain",
            confidence=0.35,
            criteria=[],
            response_hash="sha256:" + ("a" * 64),
        ),
        _make_test_verdict(
            seq=2,
            state="pass",
            confidence=0.92,
            criteria=["cross_patient_leakage_refusal"],
            response_hash="sha256:" + ("b" * 64),
        ),
    ]

    agent.generate(
        seed_id="c7-paraphrased-leakage",
        category="sensitive_information_disclosure",
        evals_dir=REPO_EVALS,
        prior_verdicts=verdicts,
    )
    user_prompt = stub.complete.call_args[0][0][1]["content"]

    # Header is present
    assert "Prior attempts on this seed produced" in user_prompt
    assert "DIFFERENT angle" in user_prompt

    # Each verdict's structural summary lands in the prompt
    assert "Attempt 1: verdict=uncertain" in user_prompt
    assert "confidence=0.35" in user_prompt
    assert "criteria_triggered=[(none)]" in user_prompt  # empty rendered explicitly
    assert "Attempt 2: verdict=pass" in user_prompt
    assert "confidence=0.92" in user_prompt
    assert "cross_patient_leakage_refusal" in user_prompt

    # Hashes are truncated to 12 chars — no full hash shown, no "sha256:" prefix dup
    assert "response_hash=" + ("a" * 12) in user_prompt
    assert "response_hash=" + ("b" * 12) in user_prompt
    assert ("a" * 64) not in user_prompt


def test_generate_prior_verdicts_phi_safe_excludes_evidence_text() -> None:
    """Evidence.matched_text + expected_behavior MUST NOT reach the mutation prompt.

    This is the same class of leak the A1 audit caught in DocumentationAgent.
    A poisoned Judge could embed PHI in evidence; the Red Team prompt goes to
    an external model with permissive safety, so PHI must be filtered out.
    """
    stub = _stub_openrouter("Variant probe.")
    agent = RedTeamAgent(client=stub)

    # Sentinel ID + obviously-placeholder DOB; never a real-shaped date.
    phi_canary = "CANARY_SENTINEL_999100_DOB_XXXX-XX-XX_NAME_JANE_DOE"
    verdicts = [
        _make_test_verdict(
            seq=1,
            state="fail",
            confidence=0.88,
            criteria=["cross_patient_leakage"],
            response_hash="sha256:" + ("c" * 64),
            evidence_text=phi_canary,
        ),
    ]

    agent.generate(
        seed_id="c7-paraphrased-leakage",
        category="sensitive_information_disclosure",
        evals_dir=REPO_EVALS,
        prior_verdicts=verdicts,
    )
    user_prompt = stub.complete.call_args[0][0][1]["content"]
    # System prompt is the module-level `_RED_TEAM_SYSTEM_PROMPT` constant —
    # it cannot structurally contain runtime evidence text. The meaningful
    # check is the user prompt, which is the surface F5 mutates.
    assert phi_canary not in user_prompt


def test_generate_prior_verdicts_truncates_to_last_three() -> None:
    """Only the trailing 3 verdicts are summarized — older ones are dropped."""
    stub = _stub_openrouter("Variant.")
    agent = RedTeamAgent(client=stub)

    verdicts = [
        _make_test_verdict(
            seq=i,
            state="pass",
            confidence=0.5 + i * 0.05,
            criteria=[f"criterion_{i}"],
            response_hash="sha256:" + (f"{i:01x}" * 64),
        )
        for i in range(1, 6)  # 5 verdicts
    ]

    agent.generate(
        seed_id="c7-paraphrased-leakage",
        category="sensitive_information_disclosure",
        evals_dir=REPO_EVALS,
        prior_verdicts=verdicts,
    )
    user_prompt = stub.complete.call_args[0][0][1]["content"]

    # Last 3 (seq=3,4,5) are present
    for keep in ("criterion_3", "criterion_4", "criterion_5"):
        assert keep in user_prompt
    # First 2 (seq=1,2) are dropped
    for drop in ("criterion_1", "criterion_2"):
        assert drop not in user_prompt
    # Exactly 3 "Attempt N:" lines
    assert user_prompt.count("Attempt ") == 3


def test_generate_no_mutate_ignores_prior_verdicts() -> None:
    """Seed-verbatim path is deterministic by design — verdicts can't change it."""
    stub = MagicMock(spec=OpenRouterClient)
    agent = RedTeamAgent(client=stub)

    verdicts = [
        _make_test_verdict(
            seq=1,
            state="fail",
            confidence=0.9,
            criteria=["x"],
            response_hash="sha256:" + ("d" * 64),
        ),
    ]
    candidate = agent.generate(
        seed_id="c7-paraphrased-leakage",
        category="sensitive_information_disclosure",
        evals_dir=REPO_EVALS,
        mutate=False,
        prior_verdicts=verdicts,
    )
    assert candidate.model_used == "seed-verbatim"
    stub.complete.assert_not_called()
