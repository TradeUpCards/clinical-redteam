"""Orchestrator daemon tests (ARCH §2.3, §3.6.1, §10.2).

Coverage:
- `evaluate_halt` — every halt reason fires under its precondition
- `select_category` — each ARCH §3.6.1 rule wins under the right state
- `OrchestratorDaemon.run_until_halt` — full loop with fake agents (no LLM,
  no HTTP), exercising:
    * normal pass-only iteration → halts on max_iterations
    * fail verdict → Documentation Agent invoked, vuln draft on disk
    * AttackRefused → iteration skipped without persisting attack
    * TargetUnavailable repeated → circuit-open halt
    * HmacRejected → immediate hmac_rejected halt
    * KeyboardInterrupt → signal_interrupt halt with manifest intact
    * cost cap → halts cleanly on next pass
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from clinical_redteam.agents.documentation import (
    DocumentationAgent,
    DraftResult,
    NoDraftNeededError,
)
from clinical_redteam.agents.judge import JudgeAgent
from clinical_redteam.agents.orchestrator import (
    DEFAULT_SEEDS_BY_CATEGORY,
    HaltReason,
    OrchestratorConfig,
    OrchestratorDaemon,
    RecentSignalWindow,
    SelectionResult,
    evaluate_halt,
    select_category,
)
from clinical_redteam.agents.red_team import (
    AttackRefusedError,
    RedTeamAgent,
)
from clinical_redteam.cost_ledger import CostLedger
from clinical_redteam.coverage import CoverageTracker
from clinical_redteam.observability import Observability
from clinical_redteam.persistence import resume_run, start_run
from clinical_redteam.schemas import (
    AttackCandidate,
    Evidence,
    FixValidation,
    HumanReview,
    JudgeVerdict,
    Payload,
    VulnerabilityReportFrontmatter,
)
from clinical_redteam.target_client import (
    HmacRejectedError,
    Message,
    TargetClient,
    TargetResponse,
    TargetUnavailableError,
)

REPO_EVALS = Path(__file__).parent.parent.parent / "evals"


# ---------------------------------------------------------------------------
# Helpers / fakes
# ---------------------------------------------------------------------------


def _make_attack(seq: int, category: str = "sensitive_information_disclosure") -> AttackCandidate:
    return AttackCandidate(
        attack_id=f"atk_2026-05-12_{seq:03d}",
        category=category,  # type: ignore[arg-type]
        subcategory="cross_patient_paraphrased",
        owasp_id="LLM02:2025",
        asi_id="ASI03:2026",
        atlas_technique_id="AML.T0024",
        target_endpoint="/chat",
        payload=Payload(type="single_turn", content=f"attack body {seq}"),
        generated_by="red_team_v0.1.0",
        generated_at=datetime.now(UTC),
        model_used="fake-rt",
        cost_usd=0.001,
    )


def _make_verdict(
    seq: int,
    attack_id: str,
    state: str = "pass",
    *,
    cost: float = 0.005,
) -> JudgeVerdict:
    return JudgeVerdict(
        verdict_id=f"ver_2026-05-12_{seq:03d}",
        attack_id=attack_id,
        verdict=state,  # type: ignore[arg-type]
        confidence=0.9,
        criteria_triggered=["cross_patient_leakage"] if state == "fail" else [],
        evidence=(
            [
                Evidence(
                    criterion="cross_patient_leakage",
                    matched_text="a quoted span",
                    expected_behavior="refuse cross-patient narrative",
                )
            ]
            if state == "fail"
            else []
        ),
        target_response_hash="sha256:" + ("a" * 64),
        judged_at=datetime.now(UTC),
        judge_version="v0.1.0",
        judge_model="fake-judge",
        cost_usd=cost,
        human_escalation_required=False,
    )


@dataclass
class _FakeRedTeam:
    """Returns sequential AttackCandidates. `refuse_after` raises after N."""

    sequence: int = 0
    refuse_after: int | None = None
    raise_on_call: Exception | None = None

    def generate(self, *, seed_id: str, category: str, evals_dir: Path,
                 sequence: int, mutate: bool) -> AttackCandidate:
        if self.raise_on_call is not None:
            raise self.raise_on_call
        # Honor the caller-supplied sequence so daemon-driven runs and
        # resumed runs get distinct attack_ids even across restarts.
        self.sequence = max(self.sequence + 1, sequence)
        if self.refuse_after is not None and self.sequence > self.refuse_after:
            raise AttackRefusedError(
                reason="fake_refusal", label=None, matched_text=None
            )
        return _make_attack(sequence, category=category)


@dataclass
class _FakeJudge:
    """Returns canned verdicts. `verdicts` is a list of (verdict_state, cost) tuples."""

    verdicts: list[tuple[str, float]] = field(default_factory=list)
    sequence: int = 0

    def evaluate(self, *, attack: AttackCandidate, target_response_text: str,
                 sequence: int, evals_dir: Path) -> JudgeVerdict:
        # Honor caller-supplied sequence so resumed daemons emit distinct
        # verdict_ids even when the fake's internal counter starts at 0.
        self.sequence = max(self.sequence + 1, sequence)
        if self.verdicts:
            state, cost = self.verdicts[(self.sequence - 1) % len(self.verdicts)]
        else:
            state, cost = "pass", 0.005
        return _make_verdict(self.sequence, attack.attack_id, state, cost=cost)


@dataclass
class _FakeDocumentation:
    """Records calls; produces a DraftResult without touching OpenRouter."""

    draft_calls: list[dict[str, Any]] = field(default_factory=list)
    raise_on_call: Exception | None = None

    def draft(self, **kwargs: Any) -> DraftResult:
        if self.raise_on_call is not None:
            raise self.raise_on_call
        self.draft_calls.append(kwargs)
        verdict_state = kwargs["verdict"].verdict
        if verdict_state not in ("fail", "partial"):
            raise NoDraftNeededError(f"verdict={verdict_state!r}")
        fm = VulnerabilityReportFrontmatter(
            vuln_id=f"VULN-{len(self.draft_calls):03d}",
            title="Fake",
            severity="high",
            status="draft-pending-review",
            discovered_at=datetime.now(UTC),
            discovered_by_attack_id=kwargs["attack"].attack_id,
            target_version_sha="fake",
            target_endpoint="/chat",
            owasp_classification=[],
            asi_classification=[],
            atlas_techniques=[],
            human_review=HumanReview(),
            fix_validation=FixValidation(regression_test_path="fake"),
        )
        return DraftResult(
            vuln_id=fm.vuln_id,
            severity="high",
            canonical_path=Path("/tmp/fake"),
            snapshot_path=None,
            frontmatter=fm,
            cost_usd=0.025,
            model_used="fake-doc",
        )


@dataclass
class _FakeTarget:
    """Returns canned TargetResponse; supports configurable failure injection."""

    raise_on_call: Exception | None = None
    response_text: str = "fake response"
    fingerprint: str = "sha256:fake0000000000aa"

    def chat(self, *, messages: list[Message], patient_id: int, session_id: str) -> TargetResponse:
        if self.raise_on_call is not None:
            raise self.raise_on_call
        return TargetResponse(
            status_code=200,
            assistant_text=self.response_text,
            raw_body={"choices": [{"message": {"content": self.response_text}}]},
            latency_ms=42,
            request_id="req-fake",
            trace_id="trace-fake",
        )

    def health_fingerprint(self) -> str:
        """F7 — daemon calls this on __post_init__ to detect target change."""
        return self.fingerprint


# ---------------------------------------------------------------------------
# Daemon construction helpers
# ---------------------------------------------------------------------------


def _build_daemon(
    tmp_path: Path,
    *,
    red_team: Any | None = None,
    judge: Any | None = None,
    documentation: Any | None = None,
    target: Any | None = None,
    cost_cap_usd: float = 5.0,
    config_overrides: dict[str, Any] | None = None,
) -> OrchestratorDaemon:
    results_dir = tmp_path / "results"
    handle = start_run(
        run_id="testrun-001",
        results_dir=results_dir,
        target_url="http://localhost:8000",
    )
    coverage = CoverageTracker.create(
        run_dir=handle.run_dir,
        target_version_sha="abc1234",
        cost_cap_usd=cost_cap_usd,
    )
    ledger = CostLedger.create(run_dir=handle.run_dir, cost_cap_usd=cost_cap_usd)
    obs = Observability.from_env(session_id="testrun-001", env={})  # type: ignore[arg-type]
    config_kwargs = {
        "evals_dir": REPO_EVALS,
        "canonical_vuln_dir": tmp_path / "vulnerabilities",
        "coverage_floor": 2,  # tiny floor so tests don't need 30 attacks
        "per_iteration_cost_budget_usd": 0.10,
    }
    if config_overrides:
        config_kwargs.update(config_overrides)
    config = OrchestratorConfig(**config_kwargs)  # type: ignore[arg-type]
    return OrchestratorDaemon(
        red_team=red_team or _FakeRedTeam(),
        judge=judge or _FakeJudge(),
        documentation=documentation or _FakeDocumentation(),
        target=target or _FakeTarget(),
        coverage=coverage,
        ledger=ledger,
        handle=handle,
        obs=obs,
        config=config,
        session_id="testrun-001",
        target_version_sha="abc1234",
    )


# ---------------------------------------------------------------------------
# Pure-function tests — evaluate_halt
# ---------------------------------------------------------------------------


def test_halt_cost_cap_reached(tmp_path: Path) -> None:
    d = _build_daemon(tmp_path, cost_cap_usd=0.01)
    # Push ledger total above cap
    d.ledger.record(
        tier="red_team",
        model_used="fake",
        cost_usd=0.05,
        tokens_input=0,
        tokens_output=0,
    )
    decision = evaluate_halt(
        coverage=d.coverage,
        ledger=d.ledger,
        config=d.config,
        recent_signal=d.signal_window,
        iteration=0,
        max_iterations=None,
        target_unavailable_streak=0,
        refusal_streak=0,
        provider_outage_streak=0,
    )
    assert decision.is_halt
    assert decision.reason == HaltReason.COST_CAP_REACHED


def test_halt_cost_cap_projected_breach(tmp_path: Path) -> None:
    d = _build_daemon(tmp_path, cost_cap_usd=0.10)
    # Just under cap; next-iter projection blows it
    d.ledger.record(
        tier="red_team",
        model_used="fake",
        cost_usd=0.04,
        tokens_input=0,
        tokens_output=0,
    )
    decision = evaluate_halt(
        coverage=d.coverage, ledger=d.ledger, config=d.config,
        recent_signal=d.signal_window, iteration=0, max_iterations=None,
        target_unavailable_streak=0, refusal_streak=0, provider_outage_streak=0,
    )
    assert decision.is_halt
    assert decision.reason == HaltReason.COST_CAP_PROJECTED_BREACH


def test_halt_max_iterations(tmp_path: Path) -> None:
    d = _build_daemon(tmp_path)
    decision = evaluate_halt(
        coverage=d.coverage, ledger=d.ledger, config=d.config,
        recent_signal=d.signal_window, iteration=5, max_iterations=5,
        target_unavailable_streak=0, refusal_streak=0, provider_outage_streak=0,
    )
    assert decision.is_halt
    assert decision.reason == HaltReason.MAX_ITERATIONS_REACHED


def test_halt_signal_to_cost_collapse(tmp_path: Path) -> None:
    d = _build_daemon(
        tmp_path,
        config_overrides={"signal_floor": 1.0, "recent_k": 3},
    )
    # Three iterations of pass at non-zero cost → signal_to_cost = 0 < 1.0
    for _ in range(3):
        d.signal_window.push(
            category="sensitive_information_disclosure",
            verdict="pass",
            cost_usd=0.01,
        )
    decision = evaluate_halt(
        coverage=d.coverage, ledger=d.ledger, config=d.config,
        recent_signal=d.signal_window, iteration=10, max_iterations=None,
        target_unavailable_streak=0, refusal_streak=0, provider_outage_streak=0,
    )
    assert decision.is_halt
    assert decision.reason == HaltReason.SIGNAL_TO_COST_COLLAPSED


def test_halt_coverage_floor_met_no_open(tmp_path: Path) -> None:
    d = _build_daemon(tmp_path, config_overrides={"coverage_floor": 1})
    # Bump every category to 1 attack with a pass verdict (no open finding)
    for cat in ("sensitive_information_disclosure", "prompt_injection",
                "unbounded_consumption"):
        d.coverage.record_attack(category=cat)
        d.coverage.record_verdict(category=cat, verdict="pass", session_cost_usd=0.0)
    decision = evaluate_halt(
        coverage=d.coverage, ledger=d.ledger, config=d.config,
        recent_signal=d.signal_window, iteration=10, max_iterations=None,
        target_unavailable_streak=0, refusal_streak=0, provider_outage_streak=0,
    )
    assert decision.is_halt
    assert decision.reason == HaltReason.COVERAGE_FLOOR_MET_NO_OPEN


def test_halt_target_circuit_open(tmp_path: Path) -> None:
    d = _build_daemon(tmp_path)
    decision = evaluate_halt(
        coverage=d.coverage, ledger=d.ledger, config=d.config,
        recent_signal=d.signal_window, iteration=1, max_iterations=None,
        target_unavailable_streak=3, refusal_streak=0, provider_outage_streak=0,
    )
    assert decision.is_halt
    assert decision.reason == HaltReason.TARGET_CIRCUIT_OPEN


def test_halt_content_filter_jammed(tmp_path: Path) -> None:
    d = _build_daemon(tmp_path)
    decision = evaluate_halt(
        coverage=d.coverage, ledger=d.ledger, config=d.config,
        recent_signal=d.signal_window, iteration=1, max_iterations=None,
        target_unavailable_streak=0, refusal_streak=5, provider_outage_streak=0,
    )
    assert decision.is_halt
    assert decision.reason == HaltReason.CONTENT_FILTER_JAMMED


def test_halt_provider_outage_persistent(tmp_path: Path) -> None:
    d = _build_daemon(tmp_path)
    decision = evaluate_halt(
        coverage=d.coverage, ledger=d.ledger, config=d.config,
        recent_signal=d.signal_window, iteration=1, max_iterations=None,
        target_unavailable_streak=0, refusal_streak=0, provider_outage_streak=5,
    )
    assert decision.is_halt
    assert decision.reason == HaltReason.PROVIDER_OUTAGE_PERSISTENT


def test_run_next_when_no_condition_fires(tmp_path: Path) -> None:
    d = _build_daemon(tmp_path)
    decision = evaluate_halt(
        coverage=d.coverage, ledger=d.ledger, config=d.config,
        recent_signal=d.signal_window, iteration=0, max_iterations=None,
        target_unavailable_streak=0, refusal_streak=0, provider_outage_streak=0,
    )
    assert decision.is_halt is False
    assert decision.reason == HaltReason.RUN_NEXT


def test_soft_cap_flag_surfaces_without_halting(tmp_path: Path) -> None:
    d = _build_daemon(tmp_path, cost_cap_usd=1.00)
    d.ledger.record(
        tier="red_team", model_used="fake", cost_usd=0.60,
        tokens_input=0, tokens_output=0,
    )  # 0.6 >= 50% of 1.0 — soft cap tripped, but well below hard cap
    decision = evaluate_halt(
        coverage=d.coverage, ledger=d.ledger, config=d.config,
        recent_signal=d.signal_window, iteration=0, max_iterations=None,
        target_unavailable_streak=0, refusal_streak=0, provider_outage_streak=0,
    )
    assert decision.flags["soft_cap_tripped"] is True
    # 0.60 + 0.10 projected = 0.70 < 1.00 cap, so not yet a halt
    assert decision.is_halt is False


# ---------------------------------------------------------------------------
# select_category tests
# ---------------------------------------------------------------------------


def test_select_category_floor_picks_lowest_coverage(tmp_path: Path) -> None:
    d = _build_daemon(tmp_path, config_overrides={"coverage_floor": 5})
    # SID has 3 attacks, PI/UC have 0
    for _ in range(3):
        d.coverage.record_attack(category="sensitive_information_disclosure")
    sel = select_category(
        coverage=d.coverage,
        recent_signal=d.signal_window,
        available_categories={
            "sensitive_information_disclosure": True,
            "prompt_injection": False,
            "unbounded_consumption": False,
        },
        replayed_attack_ids=set(),
        open_findings_by_category={},
        config=d.config,
    )
    # PI/UC unseeded but below-floor; SID is below floor too (3 < 5) AND seeded.
    # Rule 3 picks lowest-coverage SEEDED. Result: SID.
    assert sel.category == "sensitive_information_disclosure"
    assert sel.rule == "rule_3_coverage_floor"


def test_select_category_halt_on_empty_below_floor(tmp_path: Path) -> None:
    d = _build_daemon(
        tmp_path,
        config_overrides={"coverage_floor": 5, "halt_on_empty_categories": True},
    )
    sel = select_category(
        coverage=d.coverage,
        recent_signal=d.signal_window,
        available_categories={
            "sensitive_information_disclosure": False,
            "prompt_injection": False,
            "unbounded_consumption": False,
        },
        replayed_attack_ids=set(),
        open_findings_by_category={},
        config=d.config,
    )
    # All categories below floor but none seeded → halt-on-empty fires
    assert sel.category is None


def test_select_category_replays_open_finding(tmp_path: Path) -> None:
    d = _build_daemon(tmp_path, config_overrides={"coverage_floor": 0})
    sel = select_category(
        coverage=d.coverage,
        recent_signal=d.signal_window,
        available_categories={
            "sensitive_information_disclosure": True,
            "prompt_injection": False,
            "unbounded_consumption": False,
        },
        replayed_attack_ids=set(),
        open_findings_by_category={
            "sensitive_information_disclosure": ["atk_2026-05-12_007"],
        },
        config=d.config,
    )
    assert sel.category == "sensitive_information_disclosure"
    assert sel.replay_attack_id == "atk_2026-05-12_007"
    assert sel.rule == "rule_2_replay_open_finding"


def test_select_category_signal_momentum(tmp_path: Path) -> None:
    d = _build_daemon(
        tmp_path,
        config_overrides={"coverage_floor": 0, "signal_momentum_threshold": 0.5},
    )
    # Fake "we've already covered floor"; now push high-fail-rate signal in PI
    for _ in range(3):
        d.signal_window.push(
            category="prompt_injection", verdict="fail", cost_usd=0.01
        )
    sel = select_category(
        coverage=d.coverage,
        recent_signal=d.signal_window,
        # Pass seed-id strings (the new richer form the daemon supplies).
        # True alone wouldn't resolve a seed for PI/UC because they aren't
        # in DEFAULT_SEEDS_BY_CATEGORY yet (Bram's seeds land in B-track).
        available_categories={
            "sensitive_information_disclosure": "c7-paraphrased-leakage",
            "prompt_injection": "fake-pi-seed",
            "unbounded_consumption": "fake-uc-seed",
        },
        replayed_attack_ids=set(),
        open_findings_by_category={},
        config=d.config,
    )
    assert sel.category == "prompt_injection"
    assert sel.rule == "rule_4_signal_momentum"


def test_select_category_round_robin_falls_back_to_stalest(tmp_path: Path) -> None:
    d = _build_daemon(tmp_path, config_overrides={"coverage_floor": 0})
    # Stamp SID with an attack; others have None last_attack_at
    d.coverage.record_attack(category="sensitive_information_disclosure")
    sel = select_category(
        coverage=d.coverage,
        recent_signal=d.signal_window,
        available_categories={
            "sensitive_information_disclosure": "c7-paraphrased-leakage",
            "prompt_injection": "fake-pi-seed",
            "unbounded_consumption": "fake-uc-seed",
        },
        replayed_attack_ids=set(),
        open_findings_by_category={},
        config=d.config,
    )
    # PI/UC have None last_attack_at → sort first; tiebreak picks PI (or UC)
    assert sel.category in ("prompt_injection", "unbounded_consumption")
    assert sel.rule == "rule_5_round_robin"


# ---------------------------------------------------------------------------
# RecentSignalWindow tests
# ---------------------------------------------------------------------------


def test_signal_window_rolls_at_capacity() -> None:
    win = RecentSignalWindow(k=2)
    win.push(category="a", verdict="fail", cost_usd=0.01)
    win.push(category="a", verdict="pass", cost_usd=0.01)
    win.push(category="a", verdict="pass", cost_usd=0.01)
    # First fail evicted; rate is now 0/2
    assert win.fail_partial_rate("a") == 0.0


def test_signal_window_signal_to_cost_zero_when_no_cost() -> None:
    win = RecentSignalWindow(k=5)
    assert win.signal_to_cost() == 0.0


# ---------------------------------------------------------------------------
# Full-loop integration tests with fake agents
# ---------------------------------------------------------------------------


def test_run_until_halt_max_iterations(tmp_path: Path) -> None:
    daemon = _build_daemon(tmp_path)
    report = daemon.run_until_halt(max_iterations=2)
    assert report.reason == HaltReason.MAX_ITERATIONS_REACHED
    assert report.iterations == 2
    assert report.attacks_attempted == 2
    # Two attack files + two verdict files on disk
    assert len(list(daemon.handle.attacks_dir.glob("*.json"))) == 2
    assert len(list(daemon.handle.verdicts_dir.glob("*.json"))) == 2


def test_run_until_halt_writes_vuln_draft_on_fail(tmp_path: Path) -> None:
    judge = _FakeJudge(verdicts=[("fail", 0.01)])
    documentation = _FakeDocumentation()
    daemon = _build_daemon(
        tmp_path, judge=judge, documentation=documentation
    )
    daemon.run_until_halt(max_iterations=1)
    assert len(documentation.draft_calls) == 1
    # Documentation cost was recorded on the ledger
    assert daemon.ledger.by_tier_usd["documentation"] == pytest.approx(0.025)


def test_run_until_halt_skips_iteration_on_attack_refused(tmp_path: Path) -> None:
    """AttackRefused → no attack persisted, no target call, no verdict."""
    rt = _FakeRedTeam(refuse_after=0)  # ALL attacks refused
    daemon = _build_daemon(
        tmp_path,
        red_team=rt,
        # Lower refusal halt-after so the test terminates
        config_overrides={"refusal_halt_after": 3},
    )
    report = daemon.run_until_halt(max_iterations=10)
    assert report.reason == HaltReason.CONTENT_FILTER_JAMMED
    assert report.attacks_skipped_refused >= 3
    # No attacks should have been persisted
    assert list(daemon.handle.attacks_dir.glob("*.json")) == []


def test_run_until_halt_target_circuit_open(tmp_path: Path) -> None:
    target = _FakeTarget(
        raise_on_call=TargetUnavailableError("simulated outage")
    )
    daemon = _build_daemon(
        tmp_path,
        target=target,
        config_overrides={"target_outage_halt_after": 2},
    )
    report = daemon.run_until_halt(max_iterations=10)
    assert report.reason == HaltReason.TARGET_CIRCUIT_OPEN
    assert report.target_unavailable_count >= 2


def test_run_until_halt_hmac_rejected_immediate(tmp_path: Path) -> None:
    target = _FakeTarget(raise_on_call=HmacRejectedError("simulated 401"))
    daemon = _build_daemon(tmp_path, target=target)
    report = daemon.run_until_halt(max_iterations=10)
    assert report.reason == HaltReason.HMAC_REJECTED
    # Should halt on the FIRST iteration — no retry on bad config
    assert report.iterations == 1


def test_run_until_halt_keyboard_interrupt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Sending KeyboardInterrupt mid-iteration finalizes with signal_interrupt."""
    rt = _FakeRedTeam(raise_on_call=KeyboardInterrupt())
    daemon = _build_daemon(tmp_path, red_team=rt)
    report = daemon.run_until_halt(max_iterations=10)
    assert report.reason == HaltReason.SIGNAL_INTERRUPT
    # Manifest still exists + is readable after the interrupt
    manifest = daemon.handle.load_manifest()
    assert "run_id" in manifest


def test_run_until_halt_cost_cap_haltsnext_iteration(tmp_path: Path) -> None:
    """A high-cost verdict pushes the ledger past cap; next-iter halt fires."""
    judge = _FakeJudge(verdicts=[("pass", 0.50)])  # one iter = 0.50 USD on Judge
    daemon = _build_daemon(
        tmp_path, judge=judge, cost_cap_usd=0.40,
        config_overrides={"per_iteration_cost_budget_usd": 0.01},
    )
    report = daemon.run_until_halt(max_iterations=10)
    assert report.reason == HaltReason.COST_CAP_REACHED
    # One iteration completed BEFORE halt — the verdict that pushed us over
    # was persisted before the next-pass halt evaluation.
    assert report.iterations == 1


def test_run_until_halt_resets_refusal_streak_on_success(tmp_path: Path) -> None:
    """Refusal streak resets when an iteration completes successfully."""
    @dataclass
    class _RTAlternating:
        calls: int = 0
        def generate(self, **kw: Any) -> AttackCandidate:
            self.calls += 1
            if self.calls % 2 == 1:
                raise AttackRefusedError(
                    reason="alternating", label=None, matched_text=None
                )
            return _make_attack(self.calls, category=kw["category"])

    daemon = _build_daemon(
        tmp_path,
        red_team=_RTAlternating(),
        config_overrides={"refusal_halt_after": 2},
    )
    # 6 attempts: refuse, succeed, refuse, succeed, refuse, succeed
    # Never two refusals in a row → no halt on filter jam
    report = daemon.run_until_halt(max_iterations=3)
    assert report.reason == HaltReason.MAX_ITERATIONS_REACHED


# ---------------------------------------------------------------------------
# Open-findings index integration
# ---------------------------------------------------------------------------


def test_open_findings_index_picks_up_fail_verdicts_on_disk(tmp_path: Path) -> None:
    """The daemon discovers open findings from persisted verdicts (A4-ready)."""
    daemon = _build_daemon(tmp_path)
    # Manually persist one attack + fail verdict before running
    attack = _make_attack(1)
    daemon.handle.save_attack(attack)
    fail_verdict = _make_verdict(1, attack.attack_id, "fail")
    daemon.handle.save_verdict(fail_verdict)

    index = daemon._open_findings_index()
    assert "sensitive_information_disclosure" in index
    assert attack.attack_id in index["sensitive_information_disclosure"]


# ---------------------------------------------------------------------------
# Seed-cache + category-discovery integration
# ---------------------------------------------------------------------------


def test_discover_seed_ids_against_repo_evals(tmp_path: Path) -> None:
    daemon = _build_daemon(tmp_path)
    seeds = daemon._seed_id_by_category
    # SID has the c7 seed; PI/UC do not (yet — Bram is writing them in parallel)
    assert seeds["sensitive_information_disclosure"] == "c7-paraphrased-leakage"


def test_primary_pid_for_seed_caches_disk_read(tmp_path: Path) -> None:
    daemon = _build_daemon(tmp_path)
    pid1 = daemon._primary_pid_for_seed(
        "c7-paraphrased-leakage", "sensitive_information_disclosure"
    )
    pid2 = daemon._primary_pid_for_seed(
        "c7-paraphrased-leakage", "sensitive_information_disclosure"
    )
    assert pid1 == 999100
    assert pid1 == pid2
    # Cache hit — exactly one entry
    assert (
        len([k for k in daemon._seed_cache if k.endswith("c7-paraphrased-leakage")])
        == 1
    )


# ---------------------------------------------------------------------------
# DEFAULT_SEEDS_BY_CATEGORY single-source-of-truth check
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Audit-driven invariant tests (added in response to A2 audit findings)
# ---------------------------------------------------------------------------


def test_no_red_team_cost_recorded_on_attack_refused(tmp_path: Path) -> None:
    """Hard rule #7: no ledger entry when the call did not produce a value.

    AttackRefused fires BEFORE the Red Team call returns a candidate, so the
    cost ledger's red_team bucket must remain at 0.
    """
    rt = _FakeRedTeam(refuse_after=0)  # all attacks refused
    daemon = _build_daemon(
        tmp_path, red_team=rt,
        config_overrides={"refusal_halt_after": 2},
    )
    daemon.run_until_halt(max_iterations=10)
    assert daemon.ledger.by_tier_usd["red_team"] == 0.0
    assert daemon.ledger.by_tier_calls["red_team"] == 0


def test_no_judge_cost_recorded_on_target_unavailable(tmp_path: Path) -> None:
    """Hard rule #7: a target failure means the Judge never ran; no Judge entry."""
    target = _FakeTarget(raise_on_call=TargetUnavailableError("simulated"))
    daemon = _build_daemon(
        tmp_path, target=target,
        config_overrides={"target_outage_halt_after": 2},
    )
    daemon.run_until_halt(max_iterations=10)
    assert daemon.ledger.by_tier_usd["judge"] == 0.0
    assert daemon.ledger.by_tier_calls["judge"] == 0


def test_coverage_not_incremented_on_attack_refused(tmp_path: Path) -> None:
    """Hard rule #3: AttackRefused → no `attack_count` bump."""
    rt = _FakeRedTeam(refuse_after=0)
    daemon = _build_daemon(
        tmp_path, red_team=rt,
        config_overrides={"refusal_halt_after": 2},
    )
    daemon.run_until_halt(max_iterations=10)
    state = daemon.coverage.to_state(session_cost_usd=0.0)
    assert state.categories["sensitive_information_disclosure"].attack_count == 0


def test_coverage_not_incremented_on_target_unavailable(tmp_path: Path) -> None:
    """Audit HIGH-1: TargetUnavailable mid-iteration must NOT count toward
    the coverage floor — the attack reached the target but the target didn't
    respond, so no verdict will ever be produced.
    """
    target = _FakeTarget(raise_on_call=TargetUnavailableError("simulated"))
    daemon = _build_daemon(
        tmp_path, target=target,
        config_overrides={"target_outage_halt_after": 2},
    )
    daemon.run_until_halt(max_iterations=10)
    state = daemon.coverage.to_state(session_cost_usd=0.0)
    assert state.categories["sensitive_information_disclosure"].attack_count == 0


def test_save_attack_called_before_ledger_record(tmp_path: Path) -> None:
    """Audit CRITICAL-1: artifact must reach disk BEFORE its cost entry, or
    a crash between the two writes leaves an orphan ledger entry referencing
    a nonexistent attack file."""
    call_order: list[str] = []

    class _OrderedHandle:
        """Wraps the real RunHandle, recording call order."""

        def __init__(self, inner: Any) -> None:
            self._inner = inner

        def __getattr__(self, name: str) -> Any:
            attr = getattr(self._inner, name)
            if name == "save_attack":
                def wrapped(*args: Any, **kw: Any) -> Any:
                    call_order.append("save_attack")
                    return attr(*args, **kw)
                return wrapped
            return attr

    class _OrderedLedger:
        def __init__(self, inner: Any) -> None:
            self._inner = inner

        def __getattr__(self, name: str) -> Any:
            attr = getattr(self._inner, name)
            if name == "record":
                def wrapped(*args: Any, **kw: Any) -> Any:
                    if kw.get("tier") == "red_team":
                        call_order.append("ledger_record_red_team")
                    return attr(*args, **kw)
                return wrapped
            return attr

    daemon = _build_daemon(tmp_path)
    daemon.handle = _OrderedHandle(daemon.handle)  # type: ignore[assignment]
    daemon.ledger = _OrderedLedger(daemon.ledger)  # type: ignore[assignment]

    daemon.run_until_halt(max_iterations=1)

    # save_attack precedes the first ledger_record_red_team in the call order
    assert "save_attack" in call_order
    assert "ledger_record_red_team" in call_order
    assert call_order.index("save_attack") < call_order.index(
        "ledger_record_red_team"
    )


def test_documentation_skipped_when_projected_to_breach_cap(tmp_path: Path) -> None:
    """Audit HIGH-2 (ASI06): even on FAIL verdicts, the Documentation Agent
    is NOT invoked if its projected cost would breach the hard cap on this
    iteration. The next-iter halt fires cleanly without burning Doc budget.
    """
    judge = _FakeJudge(verdicts=[("fail", 0.10)])
    documentation = _FakeDocumentation()

    daemon = _build_daemon(
        tmp_path,
        judge=judge,
        documentation=documentation,
        cost_cap_usd=0.20,
        config_overrides={"per_iteration_cost_budget_usd": 0.10},
    )
    # First iteration: red_team(0.001) + judge(0.10) = 0.101 USD total.
    # 0.101 + 0.10 budget = 0.201 > 0.20 cap → halt fires before Doc invoke.
    report = daemon.run_until_halt(max_iterations=5)

    # Either halt reason is acceptable — both correspond to "cost cap fired
    # before Doc Agent could be invoked again." Projected-breach fires first
    # because the next iteration's projected cost exceeds the cap.
    assert report.reason in (
        HaltReason.COST_CAP_REACHED,
        HaltReason.COST_CAP_PROJECTED_BREACH,
    )
    # Critical: Documentation Agent was NOT invoked on the FAIL verdict
    assert documentation.draft_calls == []
    assert daemon.ledger.by_tier_usd["documentation"] == 0.0


def test_no_seeded_categories_halts_cleanly(tmp_path: Path) -> None:
    """Audit medium gap: select_category now returns category=None when
    no seeded categories exist (rather than infinite-looping on no-progress)."""
    sel = select_category(
        coverage=_build_daemon(tmp_path).coverage,
        recent_signal=RecentSignalWindow(5),
        available_categories={
            "sensitive_information_disclosure": None,
            "prompt_injection": None,
            "unbounded_consumption": None,
        },
        replayed_attack_ids=set(),
        open_findings_by_category={},
        config=OrchestratorConfig(
            evals_dir=REPO_EVALS,
            canonical_vuln_dir=tmp_path / "v",
        ),
    )
    assert sel.category is None
    assert sel.rule == "no_seeded_categories_remain"


# ---------------------------------------------------------------------------
# A4: resume-after-restart — signal_window rehydration from disk
# ---------------------------------------------------------------------------


def test_resumed_daemon_rehydrates_signal_window_from_disk(tmp_path: Path) -> None:
    """Build a daemon, run 3 iterations (writing verdicts), abandon it,
    build a NEW daemon against the SAME run-dir. The fresh daemon should
    have a non-empty signal window populated from the persisted verdicts.

    Total-coverage check rather than per-category: now that Bram has
    seeded PI + UC, the daemon's category-selection distributes attacks
    across seeded categories. The load-bearing invariant is that the
    SUM of attacks across categories matches the run length.
    """
    # First daemon — runs 3 iterations
    judge1 = _FakeJudge(verdicts=[("fail", 0.005), ("pass", 0.005), ("fail", 0.005)])
    daemon1 = _build_daemon(tmp_path, judge=judge1)
    daemon1.run_until_halt(max_iterations=3)
    assert daemon1.signal_window.attempts == 3

    # SECOND daemon — same run-dir; should rehydrate signal_window from disk
    # without running any iterations.
    handle = resume_run(run_id="testrun-001", results_dir=tmp_path / "results")
    ledger = CostLedger.load(run_dir=handle.run_dir)
    coverage = CoverageTracker.load(run_dir=handle.run_dir)
    obs = Observability.from_env(session_id="testrun-001", env={})  # type: ignore[arg-type]
    config = OrchestratorConfig(
        evals_dir=REPO_EVALS,
        canonical_vuln_dir=tmp_path / "vulnerabilities",
        coverage_floor=2,
        per_iteration_cost_budget_usd=0.10,
        recent_k=10,
    )
    daemon2 = OrchestratorDaemon(
        red_team=_FakeRedTeam(),
        judge=_FakeJudge(),
        documentation=_FakeDocumentation(),
        target=_FakeTarget(),
        coverage=coverage,
        ledger=ledger,
        handle=handle,
        obs=obs,
        config=config,
        session_id="testrun-001",
    )
    # Rehydrated from the 3 prior verdicts
    assert daemon2.signal_window.attempts == 3
    # And the prior cost/coverage state is preserved (via *.load)
    assert daemon2.ledger.total_usd == pytest.approx(daemon1.ledger.total_usd)
    # Total attack count across all categories should equal the run length
    state = daemon2.coverage.to_state(session_cost_usd=0.0)
    total_attacks = sum(c.attack_count for c in state.categories.values())
    assert total_attacks == 3


def test_coverage_reconciled_from_disk_when_daemon_resumes(tmp_path: Path) -> None:
    """A4 polish (Tate B6 coordination ticket): if the daemon dies between
    save_verdict and coverage.record_verdict, coverage.json is stale.
    On resume, __post_init__ must reconcile coverage from on-disk verdicts.

    Setup: run daemon1 for 2 iterations (writes coverage cleanly to 2).
    Then SIMULATE the desync: directly write a 3rd attack + verdict pair
    to disk WITHOUT going through coverage.record_*.
    Build daemon2 (resume). __post_init__ should detect the gap and
    bump coverage from 2 → 3.
    """
    daemon1 = _build_daemon(tmp_path)
    daemon1.run_until_halt(max_iterations=2)
    # Total across categories (PI/UC may also be hit now that Bram seeded them).
    state1 = daemon1.coverage.to_state(session_cost_usd=0.0)
    total_before = sum(c.attack_count for c in state1.categories.values())
    sid_before = state1.categories["sensitive_information_disclosure"].attack_count
    assert total_before == 2

    # Simulate the desync: write attack #3 + verdict #3 to disk WITHOUT
    # calling coverage.record_*. This mimics the failure mode where the
    # daemon was killed between save_verdict and the coverage update.
    # _make_attack hardcodes category=SID, so the simulated 3rd verdict
    # lands in SID's bucket on reconciliation.
    third_attack = _make_attack(sid_before + 100)  # unique attack_id
    daemon1.handle.save_attack(third_attack)
    third_verdict = _make_verdict(sid_before + 100, third_attack.attack_id, state="pass")
    daemon1.handle.save_verdict(third_verdict)

    # Build daemon2 (resume). __post_init__ should reconcile.
    handle = resume_run(run_id="testrun-001", results_dir=tmp_path / "results")
    ledger = CostLedger.load(run_dir=handle.run_dir)
    coverage = CoverageTracker.load(run_dir=handle.run_dir)
    obs = Observability.from_env(session_id="testrun-001", env={})  # type: ignore[arg-type]
    config = OrchestratorConfig(
        evals_dir=REPO_EVALS,
        canonical_vuln_dir=tmp_path / "vulnerabilities",
        coverage_floor=2,
        per_iteration_cost_budget_usd=0.10,
    )
    daemon2 = OrchestratorDaemon(
        red_team=_FakeRedTeam(),
        judge=_FakeJudge(),
        documentation=_FakeDocumentation(),
        target=_FakeTarget(),
        coverage=coverage, ledger=ledger, handle=handle, obs=obs,
        config=config, session_id="testrun-001",
    )
    # Coverage reconciled: SID's count bumps by 1 (the manually-injected
    # verdict goes into SID's bucket). Total across categories goes up by 1.
    state2 = daemon2.coverage.to_state(session_cost_usd=0.0)
    total_after = sum(c.attack_count for c in state2.categories.values())
    assert total_after == total_before + 1
    assert (
        state2.categories["sensitive_information_disclosure"].attack_count
        == sid_before + 1
    )


def test_resumed_daemon_continues_attack_id_sequence(tmp_path: Path) -> None:
    """`_next_sequence` reads manifest['attack_ids'] — so a resumed daemon's
    next attack gets the correct sequence number across restart."""
    daemon1 = _build_daemon(tmp_path)
    daemon1.run_until_halt(max_iterations=2)

    # Re-attach (resume) and run one more iteration. The next attack should
    # be sequence=3 → atk_*_003.
    handle = resume_run(run_id="testrun-001", results_dir=tmp_path / "results")
    ledger = CostLedger.load(run_dir=handle.run_dir)
    coverage = CoverageTracker.load(run_dir=handle.run_dir)
    obs = Observability.from_env(session_id="testrun-001", env={})  # type: ignore[arg-type]
    config = OrchestratorConfig(
        evals_dir=REPO_EVALS,
        canonical_vuln_dir=tmp_path / "vulnerabilities",
        coverage_floor=2,
        per_iteration_cost_budget_usd=0.10,
    )
    daemon2 = OrchestratorDaemon(
        red_team=_FakeRedTeam(),
        judge=_FakeJudge(),
        documentation=_FakeDocumentation(),
        target=_FakeTarget(),
        coverage=coverage,
        ledger=ledger,
        handle=handle,
        obs=obs,
        config=config,
        session_id="testrun-001",
    )
    assert daemon2._next_sequence() == 3
    daemon2.run_until_halt(max_iterations=1)

    attack_files = sorted((handle.run_dir / "attacks").glob("*.json"))
    assert len(attack_files) == 3
    # Last attack file is sequence 003
    assert attack_files[-1].stem.endswith("_003")


def test_default_seeds_mapping_matches_run_module() -> None:
    """orchestrator.DEFAULT_SEEDS_BY_CATEGORY is the source of truth that A3
    extends. Verify it stays in sync with run.py's own copy until A3 lifts it."""
    from clinical_redteam.run import DEFAULT_SEEDS_BY_CATEGORY as RUN_DEFAULTS
    # A3 will remove run.py's copy and import from orchestrator; until then
    # they must agree on the entries they share.
    for cat, seed in RUN_DEFAULTS.items():
        assert DEFAULT_SEEDS_BY_CATEGORY.get(cat) == seed


# ---------------------------------------------------------------------------
# F7 — target-change regression replay
# ---------------------------------------------------------------------------


def test_daemon_writes_target_fingerprint_to_manifest(tmp_path: Path) -> None:
    """At construction, daemon persists the current target fingerprint."""
    target = _FakeTarget(fingerprint="sha256:abc123def4567890")
    daemon = _build_daemon(tmp_path, target=target)
    manifest = daemon.handle.load_manifest()
    assert manifest["target_fingerprint"] == "sha256:abc123def4567890"
    assert daemon._target_fingerprint == "sha256:abc123def4567890"


def test_daemon_fingerprint_unchanged_when_no_prior_run(tmp_path: Path) -> None:
    """First run → no prior fingerprint → fingerprint_changed=False, no replay."""
    daemon = _build_daemon(tmp_path)
    assert daemon._previous_target_fingerprint is None
    assert daemon._fingerprint_changed is False
    # Run loop completes; no regression replay attempts recorded
    daemon.run_until_halt(max_iterations=1)
    assert daemon._regression_replays_run == 0


def test_daemon_fingerprint_unchanged_skips_replay(tmp_path: Path) -> None:
    """Same fingerprint between runs → no replay fires."""
    results_dir = tmp_path / "results"
    # First run
    h1 = start_run(
        run_id="run-001",
        results_dir=results_dir,
        target_url="http://localhost:8000",
    )
    h1.update_target_fingerprint("sha256:samesame12345678")

    # Second daemon starts; same target fingerprint
    target = _FakeTarget(fingerprint="sha256:samesame12345678")
    handle2 = start_run(
        run_id="run-002",
        results_dir=results_dir,
        target_url="http://localhost:8000",
    )
    coverage = CoverageTracker.create(
        run_dir=handle2.run_dir,
        target_version_sha="x",
        cost_cap_usd=5.0,
    )
    ledger = CostLedger.create(run_dir=handle2.run_dir, cost_cap_usd=5.0)
    obs = Observability.from_env(session_id="run-002", env={})  # type: ignore[arg-type]
    config = OrchestratorConfig(
        evals_dir=REPO_EVALS,
        canonical_vuln_dir=tmp_path / "vulnerabilities",
        coverage_floor=2,
        per_iteration_cost_budget_usd=0.10,
    )
    daemon = OrchestratorDaemon(
        red_team=_FakeRedTeam(),
        judge=_FakeJudge(),
        documentation=_FakeDocumentation(),
        target=target,
        coverage=coverage,
        ledger=ledger,
        handle=handle2,
        obs=obs,
        config=config,
        session_id="run-002",
    )
    assert daemon._previous_target_fingerprint == "sha256:samesame12345678"
    assert daemon._fingerprint_changed is False


def test_daemon_fingerprint_changed_triggers_replay(tmp_path: Path) -> None:
    """Fingerprint delta → regression replay fires for every committed case."""
    results_dir = tmp_path / "results"
    # Seed a prior run with a different fingerprint
    h1 = start_run(
        run_id="run-001",
        results_dir=results_dir,
        target_url="http://localhost:8000",
    )
    h1.update_target_fingerprint("sha256:oldoldoldoldoldol")

    # New target fingerprint
    target = _FakeTarget(fingerprint="sha256:newnewnewnewnewne")
    handle2 = start_run(
        run_id="run-002",
        results_dir=results_dir,
        target_url="http://localhost:8000",
    )
    coverage = CoverageTracker.create(
        run_dir=handle2.run_dir,
        target_version_sha="x",
        cost_cap_usd=5.0,
    )
    ledger = CostLedger.create(run_dir=handle2.run_dir, cost_cap_usd=5.0)
    obs = Observability.from_env(session_id="run-002", env={})  # type: ignore[arg-type]
    config = OrchestratorConfig(
        evals_dir=REPO_EVALS,  # repo has evals/regression/sid/REGR-001.yaml
        canonical_vuln_dir=tmp_path / "vulnerabilities",
        coverage_floor=2,
        per_iteration_cost_budget_usd=0.10,
    )
    daemon = OrchestratorDaemon(
        red_team=_FakeRedTeam(),
        judge=_FakeJudge(verdicts=[("pass", 0.001)]),
        documentation=_FakeDocumentation(),
        target=target,
        coverage=coverage,
        ledger=ledger,
        handle=handle2,
        obs=obs,
        config=config,
        session_id="run-002",
    )
    assert daemon._previous_target_fingerprint == "sha256:oldoldoldoldoldol"
    assert daemon._fingerprint_changed is True

    daemon.run_until_halt(max_iterations=0)  # only the replay should fire

    # Replay artifacts exist
    assert daemon._regression_replays_run >= 1
    manifest = handle2.load_manifest()
    assert len(manifest.get("regression_replay_attack_ids", [])) >= 1
    assert len(manifest.get("regression_replay_verdict_ids", [])) >= 1

    # Replay outputs land in regression_replay/ — NOT in attacks/ + verdicts/
    main_attacks = list(handle2.attacks_dir.glob("*.json"))
    replay_attacks = list(handle2.regression_replay_attacks_dir.glob("*.json"))
    assert len(replay_attacks) >= 1
    # max_iterations=0 means the main loop wouldn't actually run; this
    # assertion guards that regression replay does NOT contaminate the
    # main `attacks/` directory.
    assert all("regression_replay" not in str(p) for p in main_attacks)


def test_evaluate_fingerprint_change_no_previous_is_no_change() -> None:
    assert (
        OrchestratorDaemon._evaluate_fingerprint_change(
            previous=None, current="sha256:abc"
        )
        is False
    )


def test_evaluate_fingerprint_change_unreachable_pair_is_no_change() -> None:
    assert (
        OrchestratorDaemon._evaluate_fingerprint_change(
            previous="unreachable", current="unreachable"
        )
        is False
    )


def test_evaluate_fingerprint_change_real_delta_triggers() -> None:
    assert (
        OrchestratorDaemon._evaluate_fingerprint_change(
            previous="sha256:aaa", current="sha256:bbb"
        )
        is True
    )
    # transition out of unreachable also counts as change
    assert (
        OrchestratorDaemon._evaluate_fingerprint_change(
            previous="unreachable", current="sha256:abc"
        )
        is True
    )
    assert (
        OrchestratorDaemon._evaluate_fingerprint_change(
            previous="sha256:abc", current="unreachable"
        )
        is True
    )


def test_regression_replay_with_no_regression_dir_is_no_op(tmp_path: Path) -> None:
    """No `evals/regression/` directory → replay logs and returns cleanly."""
    target = _FakeTarget(fingerprint="sha256:newaaaaaaaaaaaaaa")
    # Seed prior fingerprint
    results_dir = tmp_path / "results"
    h1 = start_run(
        run_id="run-001",
        results_dir=results_dir,
        target_url="http://localhost:8000",
    )
    h1.update_target_fingerprint("sha256:oldaaaaaaaaaaaaaa")

    handle2 = start_run(
        run_id="run-002",
        results_dir=results_dir,
        target_url="http://localhost:8000",
    )
    coverage = CoverageTracker.create(
        run_dir=handle2.run_dir,
        target_version_sha="x",
        cost_cap_usd=5.0,
    )
    ledger = CostLedger.create(run_dir=handle2.run_dir, cost_cap_usd=5.0)
    obs = Observability.from_env(session_id="run-002", env={})  # type: ignore[arg-type]
    # Point evals_dir at an empty tmp tree → no `regression/` subdir
    empty_evals = tmp_path / "empty_evals"
    (empty_evals / "seed").mkdir(parents=True)
    config = OrchestratorConfig(
        evals_dir=empty_evals,
        canonical_vuln_dir=tmp_path / "vulnerabilities",
        coverage_floor=2,
        per_iteration_cost_budget_usd=0.10,
    )
    daemon = OrchestratorDaemon(
        red_team=_FakeRedTeam(),
        judge=_FakeJudge(),
        documentation=_FakeDocumentation(),
        target=target,
        coverage=coverage,
        ledger=ledger,
        handle=handle2,
        obs=obs,
        config=config,
        session_id="run-002",
    )
    assert daemon._fingerprint_changed is True
    daemon.run_until_halt(max_iterations=0)
    assert daemon._regression_replays_run == 0


def test_replay_records_regression_subtree_not_main_dirs(tmp_path: Path) -> None:
    """Replay attacks/verdicts land ONLY under regression_replay/ — the
    main coverage/halt/select_category logic must not see them."""
    results_dir = tmp_path / "results"
    h1 = start_run(
        run_id="run-001",
        results_dir=results_dir,
        target_url="http://localhost:8000",
    )
    h1.update_target_fingerprint("sha256:oldoldoldoldoldol")
    target = _FakeTarget(fingerprint="sha256:newnewnewnewnewne")
    handle2 = start_run(
        run_id="run-002",
        results_dir=results_dir,
        target_url="http://localhost:8000",
    )
    coverage = CoverageTracker.create(
        run_dir=handle2.run_dir,
        target_version_sha="x",
        cost_cap_usd=5.0,
    )
    ledger = CostLedger.create(run_dir=handle2.run_dir, cost_cap_usd=5.0)
    obs = Observability.from_env(session_id="run-002", env={})  # type: ignore[arg-type]
    config = OrchestratorConfig(
        evals_dir=REPO_EVALS,
        canonical_vuln_dir=tmp_path / "vulnerabilities",
        coverage_floor=2,
        per_iteration_cost_budget_usd=0.10,
    )
    daemon = OrchestratorDaemon(
        red_team=_FakeRedTeam(),
        judge=_FakeJudge(),
        documentation=_FakeDocumentation(),
        target=target,
        coverage=coverage,
        ledger=ledger,
        handle=handle2,
        obs=obs,
        config=config,
        session_id="run-002",
    )
    daemon.run_until_halt(max_iterations=0)

    # Coverage state should NOT reflect any replay attacks
    state = coverage.to_state(session_cost_usd=ledger.total_usd)
    for cat_cov in state.categories.values():
        assert cat_cov.attack_count == 0


def test_replay_continues_after_one_case_fails(tmp_path: Path) -> None:
    """A target outage on one replay case must not stop the rest of replay."""
    # Make target raise on chat() but still report fingerprint
    target = _FakeTarget(
        fingerprint="sha256:newnewnewnewnewne",
        raise_on_call=TargetUnavailableError("simulated outage"),
    )

    results_dir = tmp_path / "results"
    h1 = start_run(
        run_id="run-001",
        results_dir=results_dir,
        target_url="http://localhost:8000",
    )
    h1.update_target_fingerprint("sha256:oldoldoldoldoldol")
    handle2 = start_run(
        run_id="run-002",
        results_dir=results_dir,
        target_url="http://localhost:8000",
    )
    coverage = CoverageTracker.create(
        run_dir=handle2.run_dir,
        target_version_sha="x",
        cost_cap_usd=5.0,
    )
    ledger = CostLedger.create(run_dir=handle2.run_dir, cost_cap_usd=5.0)
    obs = Observability.from_env(session_id="run-002", env={})  # type: ignore[arg-type]
    config = OrchestratorConfig(
        evals_dir=REPO_EVALS,
        canonical_vuln_dir=tmp_path / "vulnerabilities",
        coverage_floor=2,
        per_iteration_cost_budget_usd=0.10,
    )
    daemon = OrchestratorDaemon(
        red_team=_FakeRedTeam(),
        judge=_FakeJudge(),
        documentation=_FakeDocumentation(),
        target=target,
        coverage=coverage,
        ledger=ledger,
        handle=handle2,
        obs=obs,
        config=config,
        session_id="run-002",
    )
    daemon.run_until_halt(max_iterations=0)
    # _regression_replays_run only increments on successful completion, but
    # `_replay_one_case` returns cleanly (no raise) on TargetUnavailableError.
    # The attack file is still saved (pre-target-call write).
    replay_attacks = list(handle2.regression_replay_attacks_dir.glob("*.json"))
    assert len(replay_attacks) >= 1
    # No verdict file because the target call failed
    replay_verdicts = list(handle2.regression_replay_verdicts_dir.glob("*.json"))
    assert replay_verdicts == []
