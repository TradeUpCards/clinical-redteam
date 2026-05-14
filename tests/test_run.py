"""CLI tests for `clinical_redteam.run` (A3).

Covers:
- argument parsing: --continuous, --max-budget, --max-iterations,
  --halt-on-empty-categories, --signal-floor flags exist + parse
- single-shot vs continuous dispatch
- continuous mode happy path with fully-injected fake agents (no LLM,
  no HTTP, no network)
- error-path exit codes for missing env, invalid combos
- iteration emitter + halt report shapes on stdout
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from clinical_redteam.agents.documentation import DraftResult
from clinical_redteam.agents.orchestrator import HaltReason
from clinical_redteam.agents.red_team import AttackRefusedError
from clinical_redteam.run import (
    DEFAULT_SEEDS_BY_CATEGORY,
    _build_parser,
    _exit_code_for_halt,
    _run_continuous,
    main,
)
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
    TargetResponse,
    TargetUnavailableError,
)


REPO_EVALS = Path(__file__).parent.parent / "evals"


# ---------------------------------------------------------------------------
# Fakes — same shape as tests/agents/test_orchestrator.py
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


def _make_verdict(seq: int, attack_id: str, state: str = "pass") -> JudgeVerdict:
    return JudgeVerdict(
        verdict_id=f"ver_2026-05-12_{seq:03d}",
        attack_id=attack_id,
        verdict=state,  # type: ignore[arg-type]
        confidence=0.9,
        criteria_triggered=[],
        evidence=[],
        target_response_hash="sha256:" + ("a" * 64),
        judged_at=datetime.now(UTC),
        judge_version="v0.1.0",
        judge_model="fake",
        cost_usd=0.005,
        human_escalation_required=False,
    )


@dataclass
class _FakeRedTeam:
    sequence: int = 0

    @classmethod
    def from_env(cls, env: Any = None) -> "_FakeRedTeam":
        return cls()

    def generate(self, **kw: Any) -> AttackCandidate:
        # Honor caller-supplied sequence so daemon resume yields fresh IDs.
        called_seq = kw.get("sequence", self.sequence + 1)
        self.sequence = max(self.sequence + 1, called_seq)
        return _make_attack(self.sequence)


@dataclass
class _FakeJudge:
    sequence: int = 0

    @classmethod
    def from_env(cls, env: Any = None) -> "_FakeJudge":
        return cls()

    def evaluate(self, *, attack: AttackCandidate, **kw: Any) -> JudgeVerdict:
        called_seq = kw.get("sequence", self.sequence + 1)
        self.sequence = max(self.sequence + 1, called_seq)
        return _make_verdict(self.sequence, attack.attack_id)


@dataclass
class _FakeDocumentation:
    draft_calls: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_env(cls, env: Any = None) -> "_FakeDocumentation":
        return cls()

    def draft(self, **kw: Any) -> DraftResult:
        self.draft_calls.append(kw)
        fm = VulnerabilityReportFrontmatter(
            vuln_id="VULN-001",
            title="Fake",
            severity="high",
            status="draft-pending-review",
            discovered_at=datetime.now(UTC),
            discovered_by_attack_id=kw["attack"].attack_id,
            target_version_sha="fake",
            target_endpoint="/chat",
            owasp_classification=[],
            asi_classification=[],
            atlas_techniques=[],
            human_review=HumanReview(),
            fix_validation=FixValidation(regression_test_path="fake"),
        )
        return DraftResult(
            vuln_id="VULN-001", severity="high",
            canonical_path=Path("/tmp/fake"), snapshot_path=None,
            frontmatter=fm, cost_usd=0.0, model_used="fake-doc",
        )


@dataclass
class _FakeTarget:
    base_url: str = "http://localhost:8000"

    @classmethod
    def from_env(cls, env: Any = None) -> "_FakeTarget":
        return cls()

    def chat(self, *, messages: list[Message], patient_id: int, session_id: str) -> TargetResponse:
        return TargetResponse(
            status_code=200,
            assistant_text="benign response",
            raw_body={},
            latency_ms=12,
            request_id="req-fake",
            trace_id="trace-fake",
        )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def env_with_target(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, str]:
    """Set the env vars the run loop reads — pointing at fakes via patching."""
    monkeypatch.setenv("RED_TEAM_TARGET_URL", "http://localhost:8000")
    monkeypatch.setenv("RESULTS_DIR", str(tmp_path / "results"))
    monkeypatch.setenv("EVALS_DIR", str(REPO_EVALS))
    monkeypatch.setenv("MAX_SESSION_COST_USD", "5.0")
    return dict(os.environ)


@contextmanager
def _patch_agents() -> Any:
    """Replace all four agents + target client with fakes that don't need keys."""
    with (
        patch("clinical_redteam.run.RedTeamAgent", _FakeRedTeam),
        patch("clinical_redteam.run.JudgeAgent", _FakeJudge),
        patch("clinical_redteam.run.DocumentationAgent", _FakeDocumentation),
        patch("clinical_redteam.run.TargetClient", _FakeTarget),
    ):
        yield


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def test_parser_accepts_continuous_flag() -> None:
    parser = _build_parser()
    args = parser.parse_args(["--continuous"])
    assert args.continuous is True


def test_parser_defaults_to_single_shot() -> None:
    parser = _build_parser()
    args = parser.parse_args([])
    assert args.continuous is False
    assert args.max_attacks == 1


def test_parser_accepts_max_budget() -> None:
    parser = _build_parser()
    args = parser.parse_args(["--continuous", "--max-budget", "1.50"])
    assert args.max_budget == pytest.approx(1.50)


def test_parser_accepts_max_iterations() -> None:
    parser = _build_parser()
    args = parser.parse_args(["--continuous", "--max-iterations", "5"])
    assert args.max_iterations == 5


def test_parser_accepts_halt_on_empty_categories() -> None:
    parser = _build_parser()
    args = parser.parse_args(["--continuous", "--halt-on-empty-categories"])
    assert args.halt_on_empty_categories is True


def test_parser_accepts_signal_floor() -> None:
    parser = _build_parser()
    args = parser.parse_args(["--continuous", "--signal-floor", "0.5"])
    assert args.signal_floor == pytest.approx(0.5)


def test_parser_rejects_invalid_category() -> None:
    parser = _build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--category", "totally_made_up"])


# ---------------------------------------------------------------------------
# Continuous-mode error paths (rejected combinations)
# ---------------------------------------------------------------------------


def test_continuous_rejects_seed_flag(env_with_target: dict[str, str]) -> None:
    """--seed is single-shot only — Orchestrator picks seeds in continuous."""
    code = main(["--continuous", "--seed", "c7-paraphrased-leakage"])
    assert code == 2


def test_continuous_rejects_no_mutate_flag(env_with_target: dict[str, str]) -> None:
    """--no-mutate is single-shot only — soft cap controls mutation in continuous."""
    code = main(["--continuous", "--no-mutate"])
    assert code == 2


def test_continuous_rejects_zero_budget(
    env_with_target: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    code = main(["--continuous", "--max-budget", "0.0", "--max-iterations", "1"])
    assert code == 2


def test_continuous_errors_when_target_url_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Daemon refuses to start without a configured target. load_dotenv is
    patched out so the repo's .env file doesn't re-supply the var.
    """
    monkeypatch.setenv("RED_TEAM_TARGET_URL", "")
    monkeypatch.setattr("clinical_redteam.run.load_dotenv", lambda: None)
    code = main(["--continuous", "--max-iterations", "1"])
    assert code == 2


# ---------------------------------------------------------------------------
# Continuous-mode happy path
# ---------------------------------------------------------------------------


def test_continuous_happy_path_writes_per_iteration_lines(
    env_with_target: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    """Daemon runs N iterations, prints one JSON line per iteration + final report."""
    with _patch_agents():
        code = main(["--continuous", "--max-iterations", "2", "--halt-on-empty-categories"])
    captured = capsys.readouterr().out

    # 2 iteration lines + 1 final halt-report payload (indented over multiple lines)
    # Parse: the indented multi-line report block is the last JSON value.
    # Iteration lines are single-line JSON each.
    # We're tolerant — just assert key content shape:
    assert '"iteration": 1' in captured
    assert '"iteration": 2' in captured
    assert '"halt_reason"' in captured
    assert HaltReason.MAX_ITERATIONS_REACHED.value in captured

    # Exit code 0 for clean iteration-bound halt
    assert code == 0


def test_iteration_lines_do_not_contain_assistant_text(
    env_with_target: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    """ARCH §10.1 enforced at the CLI boundary: no raw target response text
    in any per-iteration stdout JSON line. `assistant_text_len` (an int)
    is permitted; `assistant_text` (the actual string) is NOT.
    """
    with _patch_agents():
        main(["--continuous", "--max-iterations", "2", "--halt-on-empty-categories"])
    captured = capsys.readouterr().out

    # Parse each iteration line individually. Iteration lines are single-
    # line compact JSON; the final halt-report is multi-line indented JSON.
    for line in captured.splitlines():
        line = line.strip()
        if not line.startswith("{") or '"iteration"' not in line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue  # might be partial line from indented halt report
        assert "assistant_text" not in obj, (
            f"raw target response text in iteration line: {obj!r}"
        )


def test_single_shot_save_attack_precedes_ledger_record(
    env_with_target: dict[str, str], tmp_path: Path
) -> None:
    """Audit test-gap fix: single-shot mode must enforce the same
    save-before-record invariant the daemon does (audit CRITICAL-1 in A2).
    """
    call_order: list[str] = []

    real_save_attack = None
    real_record = None

    def _wrapped_save(self: Any, attack: Any) -> Any:  # type: ignore[no-untyped-def]
        call_order.append("save_attack")
        return real_save_attack(self, attack)

    def _wrapped_record(self: Any, **kw: Any) -> Any:  # type: ignore[no-untyped-def]
        if kw.get("tier") == "red_team":
            call_order.append("ledger_record_red_team")
        return real_record(self, **kw)

    from clinical_redteam.cost_ledger import CostLedger
    from clinical_redteam.persistence import RunHandle

    real_save_attack = RunHandle.save_attack
    real_record = CostLedger.record

    with _patch_agents():
        with patch.object(RunHandle, "save_attack", _wrapped_save):
            with patch.object(CostLedger, "record", _wrapped_record):
                # Single-shot mode (no --continuous flag)
                main([])

    assert "save_attack" in call_order
    assert "ledger_record_red_team" in call_order
    assert call_order.index("save_attack") < call_order.index(
        "ledger_record_red_team"
    ), f"call order violated: {call_order}"


def test_single_shot_rejects_continuous_only_flags(
    env_with_target: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    """Audit MEDIUM-2: continuous-only flags must be rejected with exit 2
    when run WITHOUT --continuous (symmetric to --seed / --no-mutate
    rejection inside --continuous)."""
    for flag, value in [
        ("--max-iterations", ["3"]),
        ("--max-budget", ["1.0"]),
        ("--signal-floor", ["0.5"]),
    ]:
        code = main([flag, *value])
        assert code == 2, f"single-shot did not reject {flag}"
    # boolean flag form
    assert main(["--halt-on-empty-categories"]) == 2


def test_continuous_writes_run_artifacts_to_disk(
    env_with_target: dict[str, str], tmp_path: Path
) -> None:
    with _patch_agents():
        main(["--continuous", "--max-iterations", "1", "--halt-on-empty-categories"])
    results = tmp_path / "results"
    run_dirs = list(results.iterdir())
    assert len(run_dirs) == 1
    run_dir = run_dirs[0]
    assert (run_dir / "manifest.json").exists()
    assert any((run_dir / "attacks").glob("*.json"))
    assert any((run_dir / "verdicts").glob("*.json"))


# ---------------------------------------------------------------------------
# Exit-code mapping
# ---------------------------------------------------------------------------


def test_exit_code_zero_for_all_intentional_halts() -> None:
    """F9 V2: every halt reason exits 0 — the orchestrator's decision to
    halt is BY DEFINITION intentional. Non-zero exits are reserved for
    actual Python crashes (uncaught exceptions, OOM). This lets the
    Docker compose `restart: on-failure` policy distinguish "operator
    should resume" from "Docker should auto-retry."

    Operators read the halt reason from the HaltReport JSON or run
    manifest, not from the exit code.
    """
    for reason in (
        HaltReason.COST_CAP_REACHED,
        HaltReason.COST_CAP_PROJECTED_BREACH,
        HaltReason.MAX_ITERATIONS_REACHED,
        HaltReason.SIGNAL_TO_COST_COLLAPSED,
        HaltReason.COVERAGE_FLOOR_MET_NO_OPEN,
        HaltReason.NO_ELIGIBLE_CATEGORIES,
        HaltReason.SIGNAL_INTERRUPT,
        HaltReason.HMAC_REJECTED,
        HaltReason.TARGET_CIRCUIT_OPEN,
        HaltReason.CONTENT_FILTER_JAMMED,
        HaltReason.PROVIDER_OUTAGE_PERSISTENT,
    ):
        assert _exit_code_for_halt(reason) == 0, (
            f"HaltReason.{reason.name} should exit 0 per F9 V2 design"
        )


def test_exit_code_default_nonzero_for_unmapped_reason() -> None:
    """The fallback in `_exit_code_for_halt` returns 1 for any halt
    reason not in `_HALT_EXIT_CODES`. This defends against a future
    HaltReason being added without an explicit exit-code entry — Docker
    treats it as a failure and the meta-test in `test_orchestrator_meta`
    catches the mapping gap on next run.
    """
    from unittest.mock import MagicMock

    fake_reason = MagicMock(spec=HaltReason)
    assert _exit_code_for_halt(fake_reason) == 1


# ---------------------------------------------------------------------------
# Default-seeds export — single source of truth (lives in orchestrator now)
# ---------------------------------------------------------------------------


def test_default_seeds_re_export_matches_orchestrator() -> None:
    from clinical_redteam.agents.orchestrator import (
        DEFAULT_SEEDS_BY_CATEGORY as ORCH_DEFAULTS,
    )
    assert DEFAULT_SEEDS_BY_CATEGORY == ORCH_DEFAULTS


# ---------------------------------------------------------------------------
# Help / usage smoke
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# A4: resume-after-restart from the CLI
# ---------------------------------------------------------------------------


def test_continuous_resume_picks_up_existing_run_dir(
    env_with_target: dict[str, str], tmp_path: Path
) -> None:
    """Phase 1: run the daemon to write artifacts to disk.
    Phase 2: invoke main() AGAIN with the same --run-id; the second call
    must NOT overwrite — it must resume and add more artifacts.
    """
    run_id = "resume-test-001"
    # Phase 1 — initial run
    with _patch_agents():
        code1 = main([
            "--continuous", "--run-id", run_id,
            "--max-iterations", "2", "--halt-on-empty-categories",
        ])
    assert code1 == 0
    run_dir = tmp_path / "results" / run_id
    attacks_before = sorted((run_dir / "attacks").glob("*.json"))
    assert len(attacks_before) == 2

    # Phase 2 — resume with the same run-id
    with _patch_agents():
        code2 = main([
            "--continuous", "--run-id", run_id,
            "--max-iterations", "1", "--halt-on-empty-categories",
        ])
    assert code2 == 0
    attacks_after = sorted((run_dir / "attacks").glob("*.json"))
    # Three total attacks across the two sessions
    assert len(attacks_after) == 3
    # The third attack must have sequence 3 in its filename
    assert attacks_after[-1].stem.endswith("_003")


def test_continuous_resume_preserves_cost_ledger(
    env_with_target: dict[str, str], tmp_path: Path
) -> None:
    """The cost ledger must be reloaded on resume, not zeroed."""
    run_id = "resume-test-002"
    with _patch_agents():
        main([
            "--continuous", "--run-id", run_id,
            "--max-iterations", "2", "--halt-on-empty-categories",
        ])

    # Read the ledger from disk between sessions
    from clinical_redteam.cost_ledger import CostLedger
    run_dir = tmp_path / "results" / run_id
    ledger_phase1 = CostLedger.load(run_dir=run_dir)
    cost_after_phase1 = ledger_phase1.total_usd
    assert cost_after_phase1 > 0

    with _patch_agents():
        main([
            "--continuous", "--run-id", run_id,
            "--max-iterations", "1", "--halt-on-empty-categories",
        ])

    ledger_phase2 = CostLedger.load(run_dir=run_dir)
    # Cost from phase 2 ADDS to phase 1's cost — not replaces.
    assert ledger_phase2.total_usd > cost_after_phase1


def test_resume_rejects_target_url_mismatch(
    env_with_target: dict[str, str], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """Audit MEDIUM-2: a resumed run against a different target than the
    one stored in its manifest must error out cleanly, not silently corrupt
    the regression-replay model with mixed-target artifacts.
    """
    run_id = "resume-mismatch-001"
    # Phase 1: create the run with the original target
    with _patch_agents():
        main([
            "--continuous", "--run-id", run_id,
            "--max-iterations", "1", "--halt-on-empty-categories",
        ])

    # Phase 2: try to resume with a DIFFERENT target URL
    monkeypatch.setenv("RED_TEAM_TARGET_URL", "http://different-host:8000")
    with _patch_agents():
        code = main([
            "--continuous", "--run-id", run_id,
            "--max-iterations", "1", "--halt-on-empty-categories",
        ])
    assert code == 2
    err = capsys.readouterr().err
    assert "Resuming across targets is not allowed" in err


def test_resume_max_budget_override_warns(
    env_with_target: dict[str, str], tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Audit MEDIUM-2 (cost cap): on resume, the on-disk ledger cap wins.
    If --max-budget on resume differs from the persisted cap, the user must
    get a WARN that their flag was ignored.
    """
    run_id = "resume-budget-001"
    with _patch_agents():
        # Phase 1 sets cap to 5.0 (the env_with_target fixture's default)
        main([
            "--continuous", "--run-id", run_id, "--max-budget", "5.00",
            "--max-iterations", "1", "--halt-on-empty-categories",
        ])

    with _patch_agents():
        # Phase 2 attempts to raise the cap to 10.0 — should be ignored + warned
        main([
            "--continuous", "--run-id", run_id, "--max-budget", "10.00",
            "--max-iterations", "1", "--halt-on-empty-categories",
        ])
    err = capsys.readouterr().err
    assert "ignored on resume" in err


def test_resume_missing_cost_ledger_errors_cleanly(
    env_with_target: dict[str, str], tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Audit MEDIUM-3: if cost-ledger.json is missing on resume, surface a
    clean error instead of a Python traceback at exit code 1.
    """
    run_id = "resume-corrupt-001"
    with _patch_agents():
        main([
            "--continuous", "--run-id", run_id,
            "--max-iterations", "1", "--halt-on-empty-categories",
        ])

    # Delete the ledger to simulate operator removal / corruption
    run_dir = tmp_path / "results" / run_id
    (run_dir / "cost-ledger.json").unlink()

    with _patch_agents():
        code = main([
            "--continuous", "--run-id", run_id,
            "--max-iterations", "1", "--halt-on-empty-categories",
        ])
    assert code == 2
    err = capsys.readouterr().err
    assert "cannot resume" in err


# ---------------------------------------------------------------------------
# A7: CLI polish
# ---------------------------------------------------------------------------


def test_version_flag_prints_and_exits_zero(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A7: --version is the standard ops-debug introspection. Exits 0
    without touching env / daemon / .env."""
    from clinical_redteam import __version__
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert "clinical-redteam" in out
    assert __version__ in out


def test_list_categories_prints_inventory_and_exits_zero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """A7: --list-categories prints which seeds are on disk per category.
    Useful for CI / 'did Bram's seeds land yet' smoke.

    Explicitly unsets RED_TEAM_TARGET_URL + patches load_dotenv to prove
    the introspection path requires NEITHER a configured target NOR a
    .env file — runs on a freshly-installed machine.
    """
    monkeypatch.setenv("EVALS_DIR", str(REPO_EVALS))
    monkeypatch.delenv("RED_TEAM_TARGET_URL", raising=False)
    monkeypatch.setattr("clinical_redteam.run.load_dotenv", lambda: None)
    code = main(["--list-categories"])
    assert code == 0
    out = capsys.readouterr().out
    # Repo's evals/seed/sensitive_information_disclosure/ has c7-paraphrased-leakage
    assert "sensitive_information_disclosure" in out
    assert "c7-paraphrased-leakage" in out
    # The other categories may or may not have seeds yet (Bram's track).
    # Confirm the lines appear regardless.
    assert "prompt_injection" in out
    assert "unbounded_consumption" in out


def test_continuous_rejects_non_default_max_attacks(
    env_with_target: dict[str, str], capsys: pytest.CaptureFixture[str],
) -> None:
    """A7: --max-attacks is single-shot only. A non-default value in
    continuous mode is operator confusion (they probably meant
    --max-iterations); reject with exit 2 and a guiding error message."""
    code = main([
        "--continuous", "--max-attacks", "5",
        "--halt-on-empty-categories",
    ])
    assert code == 2
    err = capsys.readouterr().err
    assert "single-shot only" in err
    assert "--max-iterations" in err


def test_continuous_default_max_attacks_does_not_trip_rejection(
    env_with_target: dict[str, str],
) -> None:
    """The default --max-attacks=1 must NOT be rejected in continuous mode
    (otherwise every continuous invocation would fail). Verifies the
    rejection rule only fires for non-default values."""
    with _patch_agents():
        code = main([
            "--continuous", "--max-iterations", "1",
            "--halt-on-empty-categories",
        ])
    assert code == 0  # clean halt by max-iterations


def test_help_does_not_crash(capsys: pytest.CaptureFixture[str]) -> None:
    parser = _build_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["--help"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr().out
    assert "--continuous" in captured
    assert "--max-budget" in captured
    assert "--halt-on-empty-categories" in captured
