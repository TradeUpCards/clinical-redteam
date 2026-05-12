"""Coverage tracker tests (ARCH §3.6.1 + §12.3)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from clinical_redteam.coverage import (
    COVERAGE_FILENAME,
    CoverageError,
    CoverageTracker,
)
from clinical_redteam.schemas import CoverageState


def test_create_persists_empty_coverage(tmp_path: Path) -> None:
    tracker = CoverageTracker.create(
        run_dir=tmp_path, target_version_sha="abc123", cost_cap_usd=10.0
    )
    assert tracker.coverage_path == tmp_path / COVERAGE_FILENAME
    assert tracker.coverage_path.exists()
    state = tracker.to_state(session_cost_usd=0.0)
    assert state.target_version_sha == "abc123"
    for cat in ("sensitive_information_disclosure", "prompt_injection", "unbounded_consumption"):
        assert cat in state.categories
        assert state.categories[cat].attack_count == 0
        assert state.categories[cat].open_findings == 0


def test_record_attack_bumps_count(tmp_path: Path) -> None:
    tracker = CoverageTracker.create(
        run_dir=tmp_path, target_version_sha="abc", cost_cap_usd=10.0
    )
    tracker.record_attack(category="prompt_injection")
    tracker.record_attack(category="prompt_injection")
    state = tracker.to_state(session_cost_usd=1.0)
    assert state.categories["prompt_injection"].attack_count == 2
    assert state.categories["prompt_injection"].last_attack_at is not None


def test_record_verdict_updates_buckets(tmp_path: Path) -> None:
    tracker = CoverageTracker.create(
        run_dir=tmp_path, target_version_sha="abc", cost_cap_usd=10.0
    )
    tracker.record_verdict(
        category="sensitive_information_disclosure",
        verdict="fail",
        session_cost_usd=0.5,
    )
    tracker.record_verdict(
        category="sensitive_information_disclosure",
        verdict="pass",
        session_cost_usd=0.7,
    )
    state = tracker.to_state(session_cost_usd=0.7)
    sid = state.categories["sensitive_information_disclosure"]
    assert sid.verdicts.fail == 1
    assert sid.verdicts.pass_ == 1
    assert sid.open_findings == 1  # one FAIL increments


def test_record_verdict_unknown_category_raises(tmp_path: Path) -> None:
    tracker = CoverageTracker.create(
        run_dir=tmp_path, target_version_sha="abc", cost_cap_usd=10.0
    )
    with pytest.raises(CoverageError, match="Unknown category"):
        tracker.record_verdict(
            category="rogue_category", verdict="fail", session_cost_usd=0.1
        )


def test_signal_to_cost_ratio(tmp_path: Path) -> None:
    tracker = CoverageTracker.create(
        run_dir=tmp_path, target_version_sha="abc", cost_cap_usd=10.0
    )
    # No findings, no cost → 0
    assert tracker.signal_to_cost_ratio(0.0) == 0.0

    # 2 findings, $0.5 spent → 4.0 findings per dollar
    tracker.record_verdict(
        category="prompt_injection", verdict="fail", session_cost_usd=0.5
    )
    tracker.record_verdict(
        category="prompt_injection", verdict="fail", session_cost_usd=0.5
    )
    assert tracker.signal_to_cost_ratio(0.5) == pytest.approx(4.0)

    # Same findings, $5 spent → 0.4
    assert tracker.signal_to_cost_ratio(5.0) == pytest.approx(0.4)


def test_least_covered_category(tmp_path: Path) -> None:
    tracker = CoverageTracker.create(
        run_dir=tmp_path, target_version_sha="abc", cost_cap_usd=10.0
    )
    # All zero → first MVP category wins on tie
    assert tracker.least_covered_category() == "sensitive_information_disclosure"

    tracker.record_attack(category="sensitive_information_disclosure")
    # Now SID has 1 attack, PI and UC have 0 — PI wins on tie (declared first)
    assert tracker.least_covered_category() == "prompt_injection"

    tracker.record_attack(category="prompt_injection")
    # SID=1, PI=1, UC=0 → UC
    assert tracker.least_covered_category() == "unbounded_consumption"


def test_to_state_validates_against_schema(tmp_path: Path) -> None:
    """Coverage tracker emits a real CoverageState (ARCH §12.3)."""
    tracker = CoverageTracker.create(
        run_dir=tmp_path, target_version_sha="abc", cost_cap_usd=10.0
    )
    tracker.record_attack(category="prompt_injection")
    tracker.record_verdict(
        category="prompt_injection", verdict="pass", session_cost_usd=0.1
    )

    state = tracker.to_state(session_cost_usd=0.1)
    assert isinstance(state, CoverageState)
    # Round-trip through the Pydantic model proves schema conformance
    raw = state.model_dump(mode="json")
    CoverageState.model_validate(raw)


def test_load_reads_back_state(tmp_path: Path) -> None:
    tracker = CoverageTracker.create(
        run_dir=tmp_path, target_version_sha="abc", cost_cap_usd=10.0
    )
    tracker.record_attack(category="prompt_injection")
    tracker.record_verdict(
        category="prompt_injection", verdict="fail", session_cost_usd=0.5
    )

    loaded = CoverageTracker.load(run_dir=tmp_path)
    state = loaded.to_state(session_cost_usd=0.5)
    pi = state.categories["prompt_injection"]
    assert pi.attack_count == 1
    assert pi.verdicts.fail == 1
    assert pi.open_findings == 1


def test_load_missing_raises(tmp_path: Path) -> None:
    with pytest.raises(CoverageError, match="No coverage state"):
        CoverageTracker.load(run_dir=tmp_path)


def test_load_schema_mismatch_raises(tmp_path: Path) -> None:
    tracker = CoverageTracker.create(
        run_dir=tmp_path, target_version_sha="abc", cost_cap_usd=10.0
    )
    raw = json.loads(tracker.coverage_path.read_text())
    raw["schema_version"] = 99
    tracker.coverage_path.write_text(json.dumps(raw))
    with pytest.raises(CoverageError, match="schema_version"):
        CoverageTracker.load(run_dir=tmp_path)
