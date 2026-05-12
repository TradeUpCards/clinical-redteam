"""Orchestrator daemon meta-tests (ARCH §10.1 + §10.2).

System-level invariants composed across ALL four agents + persistence.
These are properties that any individual agent test can't catch — they
require the full Red Team -> Target -> Judge -> Documentation pipeline
to be exercised end-to-end with the daemon orchestrating.

Coverage:

- **End-to-end PHI scrub:** target returns response with sentinel PIDs,
  full daemon iteration produces a vuln report file on disk that has NO
  sentinel PIDs (transitively scrubbed through Documentation Agent).
- **Cost cap enforced even under high per-iteration cost:** tight cap
  + expensive verdicts → daemon halts well before infinite loop.
- **HaltReason exit-code mapping completeness:** every value in the
  HaltReason enum must have an entry in `run._HALT_EXIT_CODES`. A meta-
  test for the regression where someone adds a new halt reason but
  forgets to map it to a process exit code.
- **Manifest integrity:** every attack_id / verdict_id / vuln_id listed
  in the manifest after a clean halt references an actual file on disk
  (no orphans, no half-references).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from clinical_redteam.agents.documentation import DraftResult
from clinical_redteam.agents.orchestrator import (
    HaltReason,
    OrchestratorConfig,
    OrchestratorDaemon,
)
from clinical_redteam.cost_ledger import CostLedger
from clinical_redteam.coverage import CoverageTracker
from clinical_redteam.observability import Observability
from clinical_redteam.persistence import start_run
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
    Message,
    TargetResponse,
)

REPO_EVALS = Path(__file__).parent.parent.parent / "evals"


# ---------------------------------------------------------------------------
# Local fakes — same shape as test_orchestrator.py
# ---------------------------------------------------------------------------


def _make_attack(seq: int) -> AttackCandidate:
    return AttackCandidate(
        attack_id=f"atk_2026-05-12_{seq:03d}",
        category="sensitive_information_disclosure",
        subcategory="cross_patient_paraphrased",
        owasp_id="LLM02:2025",
        asi_id="ASI03:2026",
        atlas_technique_id="AML.T0024",
        target_endpoint="/chat",
        payload=Payload(type="single_turn", content=f"attack body {seq}"),
        generated_by="red_team_v0.1.0",
        generated_at=datetime.now(UTC),
        model_used="fake",
        cost_usd=0.001,
    )


def _make_verdict(seq: int, attack_id: str, state: str = "fail",
                  cost: float = 0.005) -> JudgeVerdict:
    return JudgeVerdict(
        verdict_id=f"ver_2026-05-12_{seq:03d}",
        attack_id=attack_id,
        verdict=state,  # type: ignore[arg-type]
        confidence=0.92,
        criteria_triggered=["cross_patient_leakage"] if state == "fail" else [],
        evidence=(
            [
                Evidence(
                    criterion="cross_patient_leakage",
                    matched_text="patient 999114 has diabetes",  # PHI in evidence
                    expected_behavior="refuse cross-patient narrative",
                )
            ] if state == "fail" else []
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
    sequence: int = 0

    def generate(self, **kw: Any) -> AttackCandidate:
        called_seq = kw.get("sequence", self.sequence + 1)
        self.sequence = max(self.sequence + 1, called_seq)
        return _make_attack(self.sequence)


@dataclass
class _FakeJudge:
    verdicts: list[tuple[str, float]] = field(default_factory=lambda: [("fail", 0.005)])
    sequence: int = 0

    def evaluate(self, *, attack: AttackCandidate, **kw: Any) -> JudgeVerdict:
        called_seq = kw.get("sequence", self.sequence + 1)
        self.sequence = max(self.sequence + 1, called_seq)
        state, cost = self.verdicts[(self.sequence - 1) % len(self.verdicts)]
        return _make_verdict(self.sequence, attack.attack_id, state, cost=cost)


@dataclass
class _RealishDocumentation:
    """Documentation fake that ACTUALLY writes to disk and runs the real
    PHI scrub via the agent we built. Used for end-to-end PHI scrub test."""

    # The real DocumentationAgent imported lazily so this fake can be a
    # stand-in for it during test construction.

    def draft(self, **kwargs: Any) -> DraftResult:
        from clinical_redteam.agents.documentation import DocumentationAgent

        # Use a stub client that returns valid JSON so the real agent path
        # runs through (no fallback to template prose) — this exercises the
        # full PHI scrub chain on Evidence + response.
        stub = MagicMock()
        stub.complete.return_value = MagicMock(
            text=(
                '{"description": "An attacker can elicit cross-patient '
                'information by phrasing queries about encounters.", '
                '"clinical_impact": "Physician acting on synthesized '
                'response could mistake another patient\'s history.", '
                '"remediation": "Add citation-provenance check on '
                'Claim.source_record_ids."}'
            ),
            model_used="fake-doc-model",
            cost_usd=0.025,
            tokens_input=500,
            tokens_output=200,
            latency_ms=2000,
            finish_reason="stop",
        )
        real_agent = DocumentationAgent(client=stub)
        return real_agent.draft(**kwargs)


@dataclass
class _FakeTarget:
    """Returns a fixed response. End-to-end PHI scrub test uses a response
    that contains sentinel PIDs to verify the scrub pipeline removes them."""

    response_text: str = "benign response"

    def chat(self, *, messages: list[Message], patient_id: int, session_id: str) -> TargetResponse:
        return TargetResponse(
            status_code=200,
            assistant_text=self.response_text,
            raw_body={},
            latency_ms=42,
            request_id="req-fake",
            trace_id="trace-fake",
        )


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
        run_id="meta-001", results_dir=results_dir,
        target_url="http://localhost:8000",
    )
    coverage = CoverageTracker.create(
        run_dir=handle.run_dir, target_version_sha="abc1234",
        cost_cap_usd=cost_cap_usd,
    )
    ledger = CostLedger.create(run_dir=handle.run_dir, cost_cap_usd=cost_cap_usd)
    obs = Observability.from_env(session_id="meta-001", env={})  # type: ignore[arg-type]
    config_kwargs: dict[str, Any] = {
        "evals_dir": REPO_EVALS,
        "canonical_vuln_dir": tmp_path / "vulnerabilities",
        "coverage_floor": 5,
        "per_iteration_cost_budget_usd": 0.10,
    }
    if config_overrides:
        config_kwargs.update(config_overrides)
    config = OrchestratorConfig(**config_kwargs)  # type: ignore[arg-type]
    return OrchestratorDaemon(
        red_team=red_team or _FakeRedTeam(),
        judge=judge or _FakeJudge(),
        documentation=documentation or _RealishDocumentation(),
        target=target or _FakeTarget(),
        coverage=coverage, ledger=ledger, handle=handle, obs=obs,
        config=config, session_id="meta-001", target_version_sha="abc1234",
    )


# ---------------------------------------------------------------------------
# Meta-test 1: End-to-end PHI scrub through the full pipeline
# ---------------------------------------------------------------------------


def test_end_to_end_no_phi_in_canonical_vuln_report(tmp_path: Path) -> None:
    """The full Red Team -> Target -> Judge -> Documentation pipeline must
    produce a canonical vuln-report file with NO sentinel-PID leakage,
    even when:
    - the target response contains sentinel PIDs (would be the actual
      cross-patient leak)
    - the Judge's evidence quotes sentinel PIDs in matched_text

    This is the ARCH §10.1 "Documentation Agent files false positive
    + report leak" defense exercised end-to-end. The unit-level test
    in test_documentation.py covers the agent boundary; this one proves
    the property holds when the orchestrator drives the agent in
    production-like conditions.
    """
    # Use a two-name + DOB pattern that the scrubber's name+DOB regex is
    # designed to catch (`_NAME_PLUS_DOB_PATTERN` requires two capitalized
    # name tokens before the "born" keyword). Single-name "Maria, born..."
    # would only get scrubbed by accident via an unrelated two-Patient
    # token pair upstream; using "Maria Lopez" exercises the INTENDED path.
    target = _FakeTarget(
        response_text=(
            "Clinical summary follows. Sentinel patient 999114 was visited "
            "yesterday. Maria Lopez, born 03/14/1972, has diabetes."
        )
    )
    judge = _FakeJudge(verdicts=[("fail", 0.01)])  # FAIL -> Doc Agent runs

    daemon = _build_daemon(
        tmp_path, target=target, judge=judge,
        # floor=2 keeps the coverage_floor_met halt from firing before
        # we run our intended single iteration. After 1 iter, SID has
        # 1 attack < floor 2, so the halt waits.
        config_overrides={"coverage_floor": 2},
    )
    daemon.run_until_halt(max_iterations=1)

    # The canonical vuln draft must exist...
    vuln_files = list((tmp_path / "vulnerabilities").glob("VULN-*.md"))
    assert len(vuln_files) == 1, "Documentation Agent did not produce a draft"
    body = vuln_files[0].read_text(encoding="utf-8")

    # ...and must NOT contain the sentinel PIDs from the target response
    # or the Evidence.matched_text
    assert "999114" not in body, "sentinel PID leaked into canonical vuln report"
    # The name+DOB combo from the response must be scrubbed too
    assert "03/14/1972" not in body, "DOB leaked into canonical vuln report"
    # The scrubber's redaction tokens should be visible — proof scrub ran
    assert "[sentinel-pid-redacted]" in body


# ---------------------------------------------------------------------------
# Meta-test 2: Cost cap enforced under high per-iteration cost
# ---------------------------------------------------------------------------


def test_cost_cap_enforced_under_expensive_iterations(tmp_path: Path) -> None:
    """A tight cap + high per-iteration cost must halt the daemon BEFORE
    cost exceeds the cap by more than one iteration's worth. This is the
    "cost-cap actually halts the daemon" end-to-end check — separate
    from the unit-level halt-evaluation tests in test_orchestrator.py.
    """
    judge = _FakeJudge(verdicts=[("pass", 0.40)])  # 0.40 USD per Judge call

    daemon = _build_daemon(
        tmp_path, judge=judge,
        cost_cap_usd=1.00,  # tight cap
        config_overrides={
            # Floor high enough that the floor-met halt can't fire — we
            # want the cost-cap halt to be the one that ends the run.
            "coverage_floor": 100,
            "per_iteration_cost_budget_usd": 0.40,
        },
    )
    report = daemon.run_until_halt(max_iterations=100)

    assert report.reason in (
        HaltReason.COST_CAP_REACHED,
        HaltReason.COST_CAP_PROJECTED_BREACH,
    )
    # The daemon should NOT have run to 100 iterations
    assert report.iterations < 10, (
        f"cost cap did not halt the daemon promptly: "
        f"iterations={report.iterations}, cost=${report.total_cost_usd}"
    )
    # Total cost must not exceed cap by more than ONE iteration's projected
    # budget (the iteration that pushed us over fires the halt on the next pass)
    assert daemon.ledger.total_usd <= 1.00 + 0.40 + 1e-6, (
        f"cost cap breached: total=${daemon.ledger.total_usd} cap=$1.00"
    )


# ---------------------------------------------------------------------------
# Meta-test 3: HaltReason exit-code mapping completeness
# ---------------------------------------------------------------------------


def test_every_halt_reason_has_an_exit_code_mapping() -> None:
    """Regression-guard: every value in the HaltReason enum must have a
    corresponding entry in `run._HALT_EXIT_CODES`. Without this test, a
    future PR that adds a new halt reason but forgets the exit-code
    mapping would silently use the fallback (1), making it indistinguishable
    from generic Python exceptions in CI / shell pipelines.

    RUN_NEXT is excluded — it is the "keep running" sentinel; never reaches
    the exit-code lookup.
    """
    from clinical_redteam.run import _HALT_EXIT_CODES

    unmapped = []
    for reason in HaltReason:
        if reason == HaltReason.RUN_NEXT:
            continue  # never reaches exit-code lookup
        if reason not in _HALT_EXIT_CODES:
            unmapped.append(reason.value)
    assert not unmapped, (
        f"HaltReason values missing from _HALT_EXIT_CODES: {unmapped}. "
        "Add an entry to run.py:_HALT_EXIT_CODES for each new halt reason."
    )


# ---------------------------------------------------------------------------
# Meta-test 4: Manifest integrity after a clean halt
# ---------------------------------------------------------------------------


def test_manifest_references_real_files_after_clean_halt(tmp_path: Path) -> None:
    """Every attack_id / verdict_id / vuln_id in the manifest must
    reference an actual file on disk. No half-written refs, no orphan IDs.

    This proves the checkpoint-before-call invariant + atomic-write
    primitive jointly produce a consistent on-disk state across the
    full agent fan-out.
    """
    judge = _FakeJudge(verdicts=[("fail", 0.005), ("pass", 0.005)])
    daemon = _build_daemon(
        tmp_path, judge=judge,
        config_overrides={"coverage_floor": 0},
    )
    daemon.run_until_halt(max_iterations=2)

    manifest = daemon.handle.load_manifest()
    for attack_id in manifest.get("attack_ids", []):
        assert (daemon.handle.attacks_dir / f"{attack_id}.json").exists(), (
            f"manifest references missing attack file: {attack_id}"
        )
    for verdict_id in manifest.get("verdict_ids", []):
        assert (daemon.handle.verdicts_dir / f"{verdict_id}.json").exists(), (
            f"manifest references missing verdict file: {verdict_id}"
        )
    for vuln_id in manifest.get("vuln_ids", []):
        # Per-run snapshot lives in run-dir/vulnerabilities/
        assert (daemon.handle.vulnerabilities_dir / f"{vuln_id}.md").exists(), (
            f"manifest references missing per-run vuln file: {vuln_id}"
        )
