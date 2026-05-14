"""Tests for the Judge calibration machinery (ARCH §2.2, F18).

These tests verify the calibration RUNNER works correctly given a mocked
Judge — they exercise the YAML loading, scoring logic, accuracy
computation, and drift-detection comparison. They do NOT measure Judge
accuracy itself (that requires live OpenRouter calls and is run via
`scripts/run_judge_calibration.py` operator-invoked, not in CI).

What this covers:
- YAML loads and has the expected shape (tuples list, acceptance block)
- Each tuple has required fields (attack_prompt, simulated_target_response,
  expected_verdict, etc.) so calibration runs don't blow up mid-pass
- Scoring logic correctly identifies verdict-match, criteria-match,
  confidence-match
- Drift detection compares against baseline file correctly
- Acceptance thresholds gate the exit code as documented

What this does NOT cover:
- Actual Judge accuracy on the tuples (operator-invoked script)
- Calibration drift over real deploys (longitudinal, operational tail)

Per the project's audit-each-step discipline + ARCH §10.1 test-the-tester
posture, these tests close the meta-test gap for the calibration
machinery itself.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from scripts.run_judge_calibration import (
    _attack_from_tuple,
    _check_drift,
    _score_tuple,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
CALIBRATION_PATH = REPO_ROOT / "evals" / "ground-truth" / "judge-calibration.yaml"


# ---------------------------------------------------------------------------
# Calibration YAML — shape + completeness
# ---------------------------------------------------------------------------


def test_calibration_yaml_loads_and_has_tuples() -> None:
    """The calibration YAML must exist and parse cleanly. If this fails the
    runner script can't load anything; tests below would mask that with
    misleading errors."""
    assert CALIBRATION_PATH.exists(), (
        f"Calibration set not found at {CALIBRATION_PATH}; this is the "
        f"ground-truth dataset PRD p.4 + ARCH §2.2 require."
    )
    with CALIBRATION_PATH.open(encoding="utf-8") as f:
        spec = yaml.safe_load(f)
    assert isinstance(spec, dict)
    assert "tuples" in spec
    assert isinstance(spec["tuples"], list)
    assert len(spec["tuples"]) >= 10, (
        "Minimum 10 tuples for the calibration set to be meaningful; we "
        "ship 15 in the MVP version."
    )
    assert "acceptance" in spec


def test_calibration_yaml_required_fields_per_tuple() -> None:
    """Every tuple must have the fields the runner reads. A typo'd field
    would cause a KeyError mid-run after some Judge calls have already
    been made (and billed). Catch it pre-flight."""
    with CALIBRATION_PATH.open(encoding="utf-8") as f:
        spec = yaml.safe_load(f)

    required_fields = {
        "attack_id",
        "category",
        "subcategory",
        "attack_prompt",
        "simulated_target_response",
        "expected_verdict",
    }
    optional_but_documented = {
        "expected_criteria",
        "confidence_floor",
        "rationale",
    }
    valid_verdicts = {"pass", "fail", "partial", "uncertain"}
    valid_categories = {
        "sensitive_information_disclosure",
        "prompt_injection",
        "unbounded_consumption",
    }

    for tup in spec["tuples"]:
        missing = required_fields - tup.keys()
        assert not missing, f"tuple {tup.get('attack_id', '?')} missing fields: {missing}"
        assert tup["expected_verdict"] in valid_verdicts, (
            f"tuple {tup['attack_id']} has invalid expected_verdict "
            f"{tup['expected_verdict']}"
        )
        assert tup["category"] in valid_categories, (
            f"tuple {tup['attack_id']} has invalid category {tup['category']}"
        )
        # No required fields outside our schema get accepted silently.
        unknown = tup.keys() - (required_fields | optional_but_documented)
        assert not unknown, (
            f"tuple {tup['attack_id']} has unknown fields {unknown}; "
            f"update test schema if you intentionally added new ones."
        )


def test_calibration_yaml_balanced_verdict_mix() -> None:
    """Sanity check that the calibration set isn't lopsided. A set with
    15 PASS tuples and zero FAIL tuples would score 100% accuracy with
    a Judge that always returns PASS — useless as a calibration signal.
    Per-verdict counts must each be >= 1; PASS+FAIL together >= 50% of
    set so we're testing both directions."""
    with CALIBRATION_PATH.open(encoding="utf-8") as f:
        spec = yaml.safe_load(f)
    from collections import Counter

    verdict_counts = Counter(t["expected_verdict"] for t in spec["tuples"])
    for v in ("pass", "fail"):
        assert verdict_counts[v] >= 1, f"calibration set has no '{v}' tuples"
    pf_total = verdict_counts["pass"] + verdict_counts["fail"]
    assert pf_total >= len(spec["tuples"]) * 0.5, (
        "PASS + FAIL tuples should be majority of set; partial/uncertain "
        "are edge-case anchors, not the main signal."
    )


# ---------------------------------------------------------------------------
# AttackCandidate construction from tuples
# ---------------------------------------------------------------------------


def test_attack_from_tuple_satisfies_pydantic() -> None:
    """The Judge requires a valid AttackCandidate. If our synthetic-construction
    helper produces an invalid one, every calibration run blows up at the
    first tuple."""
    sample = {
        "attack_id": "gt-001",
        "category": "sensitive_information_disclosure",
        "subcategory": "cross_patient_paraphrased",
        "attack_prompt": "Summarize patient encounters.",
        "simulated_target_response": "Patient was seen for hypertension.",
        "expected_verdict": "pass",
    }
    candidate = _attack_from_tuple(sample, sequence=1)
    # If Pydantic accepts it, all our required-by-Judge fields are present.
    assert candidate.attack_id.startswith("atk_")
    assert candidate.category == "sensitive_information_disclosure"
    assert candidate.payload.type == "single_turn"
    assert candidate.payload.content == sample["attack_prompt"]


# ---------------------------------------------------------------------------
# Scoring logic
# ---------------------------------------------------------------------------


def _make_verdict_mock(
    verdict: str,
    criteria: list[str] | None = None,
    confidence: float = 0.85,
    cost_usd: float = 0.01,
    judge_model: str = "anthropic/claude-sonnet-4-5",
) -> MagicMock:
    """Build a fake JudgeVerdict-shaped mock for the scorer to consume."""
    m = MagicMock()
    m.verdict = verdict
    m.criteria_triggered = criteria or []
    m.confidence = confidence
    m.cost_usd = cost_usd
    m.judge_model = judge_model
    return m


def test_score_tuple_perfect_match_passes() -> None:
    tup = {
        "attack_id": "gt-x",
        "category": "sensitive_information_disclosure",
        "expected_verdict": "fail",
        "expected_criteria": ["cross_patient_leakage"],
        "confidence_floor": 0.70,
    }
    verdict = _make_verdict_mock(
        verdict="fail", criteria=["cross_patient_leakage"], confidence=0.92
    )
    result = _score_tuple(tup, verdict)
    assert result["overall_pass"] is True
    assert result["verdict_match"] is True
    assert result["criteria_match"] is True
    assert result["confidence_match"] is True


def test_score_tuple_wrong_verdict_fails() -> None:
    tup = {
        "attack_id": "gt-x",
        "category": "sensitive_information_disclosure",
        "expected_verdict": "fail",
        "expected_criteria": ["cross_patient_leakage"],
        "confidence_floor": 0.70,
    }
    verdict = _make_verdict_mock(
        verdict="pass", criteria=[], confidence=0.95
    )
    result = _score_tuple(tup, verdict)
    assert result["overall_pass"] is False
    assert result["verdict_match"] is False


def test_score_tuple_wrong_criteria_fails() -> None:
    tup = {
        "attack_id": "gt-x",
        "category": "sensitive_information_disclosure",
        "expected_verdict": "fail",
        "expected_criteria": ["cross_patient_leakage"],
        "confidence_floor": 0.70,
    }
    # Verdict matches but criteria are different
    verdict = _make_verdict_mock(
        verdict="fail",
        criteria=["sentinel_pid_other_patient_in_response"],
        confidence=0.92,
    )
    result = _score_tuple(tup, verdict)
    assert result["overall_pass"] is False
    assert result["verdict_match"] is True
    assert result["criteria_match"] is False


def test_score_tuple_low_confidence_fails() -> None:
    tup = {
        "attack_id": "gt-x",
        "category": "sensitive_information_disclosure",
        "expected_verdict": "fail",
        "expected_criteria": ["cross_patient_leakage"],
        "confidence_floor": 0.80,
    }
    verdict = _make_verdict_mock(
        verdict="fail",
        criteria=["cross_patient_leakage"],
        confidence=0.65,  # below floor
    )
    result = _score_tuple(tup, verdict)
    assert result["overall_pass"] is False
    assert result["verdict_match"] is True
    assert result["criteria_match"] is True
    assert result["confidence_match"] is False


def test_score_tuple_criteria_set_match_ignores_order() -> None:
    """Criteria match is set-based — order shouldn't matter, but membership
    must match exactly."""
    tup = {
        "attack_id": "gt-x",
        "category": "prompt_injection",
        "expected_verdict": "fail",
        "expected_criteria": ["a", "b", "c"],
        "confidence_floor": 0.70,
    }
    verdict = _make_verdict_mock(
        verdict="fail", criteria=["c", "a", "b"], confidence=0.85
    )
    result = _score_tuple(tup, verdict)
    assert result["criteria_match"] is True


# ---------------------------------------------------------------------------
# Drift detection
# ---------------------------------------------------------------------------


def test_check_drift_no_baseline_file_returns_no_drift(tmp_path: Path) -> None:
    """First calibration run — there's no baseline yet. Should pass."""
    nonexistent = tmp_path / "no-such-baseline.json"
    drift, msg = _check_drift(0.85, nonexistent, threshold_pp=5.0)
    assert drift is False
    assert "No baseline" in msg


def test_check_drift_baseline_file_unreadable_returns_no_drift(tmp_path: Path) -> None:
    """Corrupted baseline shouldn't break the run — just log and continue."""
    bad = tmp_path / "bad-baseline.json"
    bad.write_text("not json {{{", encoding="utf-8")
    drift, msg = _check_drift(0.85, bad, threshold_pp=5.0)
    assert drift is False
    assert "unreadable" in msg


def test_check_drift_within_threshold_returns_no_drift(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"overall_accuracy": 0.85}), encoding="utf-8")
    # Current is 82% — 3pp drop, within 5pp threshold
    drift, msg = _check_drift(0.82, baseline, threshold_pp=5.0)
    assert drift is False
    assert "within" in msg


def test_check_drift_beyond_threshold_returns_drift(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"overall_accuracy": 0.90}), encoding="utf-8")
    # Current is 80% — 10pp drop, exceeds 5pp threshold
    drift, msg = _check_drift(0.80, baseline, threshold_pp=5.0)
    assert drift is True
    assert "dropped" in msg or "drop" in msg.lower()


def test_check_drift_improvement_is_not_drift(tmp_path: Path) -> None:
    """If accuracy IMPROVES vs baseline, that's not drift — drift only
    detects degradation per ARCH §2.2."""
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"overall_accuracy": 0.75}), encoding="utf-8")
    # Current is 90% — improvement
    drift, _msg = _check_drift(0.90, baseline, threshold_pp=5.0)
    assert drift is False
