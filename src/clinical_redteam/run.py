"""End-to-end attack CLI.

Two modes:

1. **Single-shot (Phase 1a #15 vertical slice):** one attack, exit.
   `python -m clinical_redteam.run --category sensitive_information_disclosure --max-attacks 1`

2. **Continuous (Phase 1b A3 — this commit):** `while not halt:` loop driven
   by the Orchestrator daemon (A2). Picks categories, halts on cost cap /
   signal collapse / coverage floor / max-iterations / SIGINT.
   `python -m clinical_redteam.run --continuous --max-budget 5.00 \\
       --halt-on-empty-categories`

   Per-iteration progress goes to stdout (one JSON line per iteration).
   Final HaltReport summary printed on exit.

Acceptance criterion (work plan A3):
  Daemon starts; runs unattended; per-iteration line to stdout; halts
  cleanly on bound; no orphaned processes.

A4 will add resume-after-restart explicitly. The persistence layer
already supports it; A4 wires the CLI to detect `--run-id <existing>`
and resume rather than start fresh.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from clinical_redteam import __version__ as _PACKAGE_VERSION
from clinical_redteam.agents.documentation import DocumentationAgent
from clinical_redteam.agents.judge import JudgeAgent
from clinical_redteam.agents.orchestrator import (
    DEFAULT_SEEDS_BY_CATEGORY as _ORCH_DEFAULT_SEEDS,
)
from clinical_redteam.agents.orchestrator import (
    HaltReason,
    HaltReport,
    OrchestratorConfig,
    OrchestratorDaemon,
)
from clinical_redteam.agents.red_team import (
    AGENT_NAME as RED_TEAM_AGENT_NAME,
)
from clinical_redteam.agents.red_team import (
    AGENT_VERSION as RED_TEAM_AGENT_VERSION,
)
from clinical_redteam.agents.red_team import (
    AttackRefusedError,
    RedTeamAgent,
    load_seed,
)
from clinical_redteam.cost_ledger import CostLedger, CostLedgerError
from clinical_redteam.coverage import CoverageError, CoverageTracker
from clinical_redteam.observability import Observability
from clinical_redteam.persistence import PersistenceError, resume_run, start_run
from clinical_redteam.schemas import Category
from clinical_redteam.target_client import (
    HmacRejectedError,
    Message,
    TargetClient,
    TargetUnavailableError,
)

logger = logging.getLogger(__name__)


# Single source of truth — re-exported from orchestrator. A3 removes the
# duplicate dict that lived here in Phase 1a.
DEFAULT_SEEDS_BY_CATEGORY: dict[Category, str] = dict(_ORCH_DEFAULT_SEEDS)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Introspection flags exit before any side-effects (no .env load, no
    # logging config, no agent construction). Safe to invoke from CI /
    # ops scripts that just want to confirm the install + seed layout.
    if args.list_categories:
        return _print_seeded_categories()

    load_dotenv()
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.continuous:
        return _run_continuous(args)
    return _run_single_shot(args)


def _print_seeded_categories() -> int:
    """Print each MVP category and its resolved seed_id (or `<none>`)."""
    evals_dir = Path(os.getenv("EVALS_DIR", "./evals"))
    seed_root = evals_dir / "seed"
    print(f"clinical-redteam {_PACKAGE_VERSION} — seed inventory at {seed_root}")
    print()
    for cat in (
        "sensitive_information_disclosure",
        "prompt_injection",
        "unbounded_consumption",
    ):
        cat_dir = seed_root / cat
        if not cat_dir.exists():
            print(f"  {cat:40s} (no directory)")
            continue
        yamls = sorted(cat_dir.glob("*.yaml"))
        if not yamls:
            print(f"  {cat:40s} <none>")
            continue
        names = ", ".join(y.stem for y in yamls)
        print(f"  {cat:40s} {names}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m clinical_redteam.run",
        description=(
            "Run the Clinical Red Team Platform. Defaults to single-shot mode "
            "(one attack, exit). Use --continuous for the daemon loop."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  Single-shot (Phase 1a #15 vertical slice):\n"
            "    python -m clinical_redteam.run --category sensitive_information_disclosure\n"
            "\n"
            "  Continuous (Phase 1b A3 — bounded by cost):\n"
            "    python -m clinical_redteam.run --continuous --max-budget 5.00 \\\n"
            "        --halt-on-empty-categories\n"
            "\n"
            "  Continuous (bounded by iterations — useful for smoke tests):\n"
            "    python -m clinical_redteam.run --continuous --max-iterations 5\n"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"clinical-redteam {_PACKAGE_VERSION}",
        help="Print package version and exit.",
    )
    parser.add_argument(
        "--list-categories",
        action="store_true",
        help=(
            "Print available seed inventory (one line per MVP category, "
            "showing each category's seed_ids on disk) and exit. Useful "
            "for CI smoke / `did Bram's seeds land yet` checks."
        ),
    )
    parser.add_argument(
        "--continuous",
        action="store_true",
        help=(
            "Run the Orchestrator daemon (A2) until a halt condition fires "
            "instead of running a single attack."
        ),
    )
    parser.add_argument(
        "--category",
        choices=[
            "sensitive_information_disclosure",
            "prompt_injection",
            "unbounded_consumption",
        ],
        default="sensitive_information_disclosure",
        help=(
            "[single-shot] Attack category to load seed from. In continuous "
            "mode the Orchestrator picks categories itself per ARCH §3.6.1."
        ),
    )
    parser.add_argument(
        "--seed",
        default=None,
        help=(
            "[single-shot] Specific seed_id to use; defaults to the canonical "
            "seed for the chosen category."
        ),
    )
    parser.add_argument(
        "--max-attacks",
        type=int,
        default=1,
        help=(
            "[single-shot] Number of attack iterations (Phase 1a #15: 1 only). "
            "For continuous mode use --max-iterations instead."
        ),
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=None,
        help=(
            "[continuous] Upper bound on iterations before halt. Default: "
            "unbounded — halt fires on cost cap / signal collapse / coverage."
        ),
    )
    parser.add_argument(
        "--max-budget",
        type=float,
        default=None,
        help=(
            "[continuous] Hard cost cap in USD. Overrides MAX_SESSION_COST_USD "
            "env var. Daemon halts cleanly when total session cost >= cap."
        ),
    )
    parser.add_argument(
        "--halt-on-empty-categories",
        action="store_true",
        help=(
            "[continuous] Halt when there is no seeded category to attack "
            "(rather than running existing categories indefinitely)."
        ),
    )
    parser.add_argument(
        "--signal-floor",
        type=float,
        default=None,
        help=(
            "[continuous] If > 0, halt when recent-window signal-to-cost falls "
            "below this floor (ARCH §10.2 — signal collapse detection). "
            "Default: disabled."
        ),
    )
    parser.add_argument(
        "--no-mutate",
        action="store_true",
        help=(
            "[single-shot] Use seed verbatim instead of calling OpenRouter for "
            "mutation. Useful for deterministic regression replay."
        ),
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help="Run ID for the results directory (defaults to UTC timestamp + uuid suffix).",
    )
    parser.add_argument(
        "--results-dir",
        default=None,
        help="Override RESULTS_DIR env var.",
    )
    return parser


# ---------------------------------------------------------------------------
# Continuous mode (A3)
# ---------------------------------------------------------------------------


def _run_continuous(args: argparse.Namespace) -> int:
    """Build the Orchestrator daemon and run it until halt.

    Each iteration emits one JSON line to stdout. Final HaltReport is
    written as a single JSON object on stdout when the daemon halts.
    """
    # Reject single-shot-only flags that don't apply
    if args.seed is not None:
        print(
            "ERROR: --seed is single-shot only. In continuous mode the "
            "Orchestrator picks seeds per ARCH §3.6.1. Drop --seed, or run "
            "without --continuous to attack the named seed once.",
            file=sys.stderr,
        )
        return 2
    if args.no_mutate:
        print(
            "ERROR: --no-mutate is single-shot only (regression-replay "
            "mode). In continuous mode mutation is automatically reduced "
            "at the soft cost-cap. Drop --no-mutate, or use single-shot.",
            file=sys.stderr,
        )
        return 2
    if args.max_attacks != 1:
        # --max-attacks is the single-shot iteration bound; continuous uses
        # --max-iterations. A non-default value here is operator confusion.
        print(
            f"ERROR: --max-attacks={args.max_attacks} is single-shot only. "
            "In continuous mode use --max-iterations instead. (--max-attacks "
            "defaults to 1 and is ignored when --continuous is set.)",
            file=sys.stderr,
        )
        return 2

    run_id = args.run_id or _new_run_id()
    results_dir = Path(args.results_dir or os.getenv("RESULTS_DIR", "./evals/results"))
    evals_dir = Path(os.getenv("EVALS_DIR", "./evals"))
    canonical_vuln_dir = Path(os.getenv("EVALS_DIR", "./evals")) / "vulnerabilities"

    target_url = os.getenv("RED_TEAM_TARGET_URL", "")
    if not target_url:
        print("ERROR: RED_TEAM_TARGET_URL is required. Populate .env.", file=sys.stderr)
        return 2

    cost_cap_usd = args.max_budget if args.max_budget is not None else float(
        os.getenv("MAX_SESSION_COST_USD", "10")
    )
    if cost_cap_usd <= 0:
        print(
            f"ERROR: --max-budget must be > 0; got {cost_cap_usd}.",
            file=sys.stderr,
        )
        return 2

    # A4: resume-after-restart. If the run-id directory already has a
    # manifest.json, treat this invocation as a resume — re-attach to the
    # existing on-disk run instead of creating fresh artifacts.
    resuming = (results_dir / run_id / "manifest.json").exists()
    if resuming:
        try:
            handle, ledger, coverage = _resume_run_artifacts(
                run_id=run_id, results_dir=results_dir
            )
        except (PersistenceError, CostLedgerError, CoverageError) as exc:
            # Audit MEDIUM-3: surface a clean error instead of a traceback
            # when on-disk artifacts are missing or schema-incompatible.
            print(
                f"ERROR: cannot resume run {run_id!r}: {exc}. "
                "Inspect the run directory or use a different --run-id.",
                file=sys.stderr,
            )
            return 2

        # Audit MEDIUM-2: refuse to resume against a different target than
        # the one that produced the prior artifacts. Cross-target attacks
        # in the same run-dir would corrupt the regression-replay model.
        manifest = handle.load_manifest()
        prior_target_url = manifest.get("target_url")
        if prior_target_url and prior_target_url != target_url:
            print(
                f"ERROR: --run-id {run_id!r} was created against target "
                f"{prior_target_url!r}; this invocation is configured for "
                f"{target_url!r}. Resuming across targets is not allowed. "
                "Use a fresh --run-id or align RED_TEAM_TARGET_URL.",
                file=sys.stderr,
            )
            return 2

        # Audit MEDIUM-2 (cost cap): the on-disk ledger cap wins on resume.
        # If the operator passed --max-budget thinking they'd override, warn
        # so they know the original cap is still in force.
        if args.max_budget is not None and abs(
            ledger.cost_cap_usd - args.max_budget
        ) > 1e-9:
            print(
                f"WARN: --max-budget {args.max_budget:.4f} ignored on resume; "
                f"prior on-disk cap ${ledger.cost_cap_usd:.4f} is in force. "
                "Cost-cap bypass via restart is explicitly prevented.",
                file=sys.stderr,
            )

        logger.info(
            "resuming run=%s — %d prior attacks, $%.4f prior cost",
            run_id, len(manifest.get("attack_ids", [])),
            ledger.total_usd,
        )
    else:
        handle = start_run(
            run_id=run_id,
            results_dir=results_dir,
            target_url=target_url,
            extra_metadata={
                "cli": "phase_1b_a3_continuous",
                "halt_on_empty_categories": args.halt_on_empty_categories,
            },
        )
        ledger = CostLedger.create(run_dir=handle.run_dir, cost_cap_usd=cost_cap_usd)
        coverage = CoverageTracker.create(
            run_dir=handle.run_dir,
            target_version_sha="unknown",  # Phase 2 reads /version from target
            cost_cap_usd=cost_cap_usd,
        )
    obs = Observability.from_env(session_id=run_id)
    # Audit MEDIUM-1: ensure obs buffer drains even if daemon CONSTRUCTION
    # raises (e.g., RedTeamAgent.from_env() raising on missing OpenRouter
    # key). The inner finally inside `run_until_halt` is the primary flush
    # site; this outer try/finally is the safety net for the construction
    # window. Calling flush() twice is idempotent.
    try:
        config_overrides: dict[str, Any] = {
            "halt_on_empty_categories": args.halt_on_empty_categories,
            "on_iteration": _stdout_iteration_emitter,
        }
        if args.signal_floor is not None:
            config_overrides["signal_floor"] = args.signal_floor

        config = OrchestratorConfig.from_env(
            evals_dir=evals_dir,
            canonical_vuln_dir=canonical_vuln_dir,
            **config_overrides,
        )

        # Operator preamble: one tight line so anyone tailing the log
        # knows exactly what mode / cap / target / run-id they're observing.
        logger.info(
            "clinical-redteam %s continuous-mode: run=%s target=%s cap=$%.2f "
            "max_iter=%s halt_on_empty_categories=%s resuming=%s",
            _PACKAGE_VERSION,
            run_id,
            target_url,
            cost_cap_usd,
            args.max_iterations if args.max_iterations is not None else "unbounded",
            args.halt_on_empty_categories,
            resuming,
        )
        logger.info("results dir: %s", handle.run_dir)

        daemon = OrchestratorDaemon(
            red_team=RedTeamAgent.from_env(),
            judge=JudgeAgent.from_env(),
            documentation=DocumentationAgent.from_env(),
            target=TargetClient.from_env(),
            coverage=coverage,
            ledger=ledger,
            handle=handle,
            obs=obs,
            config=config,
            session_id=run_id,
        )

        report = daemon.run_until_halt(max_iterations=args.max_iterations)
        _emit_halt_report(report=report, run_id=run_id, run_dir=handle.run_dir)
        return _exit_code_for_halt(report.reason)
    finally:
        obs.flush()


def _resume_run_artifacts(
    *, run_id: str, results_dir: Path
) -> tuple[Any, CostLedger, CoverageTracker]:
    """A4: re-attach to an existing on-disk run.

    Returns (handle, ledger, coverage). Caller is responsible for noting
    the resume in logs and proceeding as normal — the orchestrator's
    `__post_init__` rehydrates `signal_window` from the verdicts dir.

    Raises PersistenceError / CostLedgerError / CoverageError if the
    on-disk artifacts are missing or schema-incompatible.
    """
    handle = resume_run(run_id=run_id, results_dir=results_dir)
    ledger = CostLedger.load(run_dir=handle.run_dir)
    coverage = CoverageTracker.load(run_dir=handle.run_dir)
    return handle, ledger, coverage


def _stdout_iteration_emitter(line: dict[str, Any]) -> None:
    """Print one JSON line per iteration — the operator's progress signal."""
    # default=str so datetimes / Paths serialize cleanly
    print(json.dumps(line, default=str), flush=True)


def _emit_halt_report(*, report: HaltReport, run_id: str, run_dir: Path) -> None:
    """Final JSON summary written to stdout when the daemon halts."""
    payload = {
        "halt_reason": report.reason.value,
        "iterations": report.iterations,
        "attacks_attempted": report.attacks_attempted,
        "attacks_skipped_refused": report.attacks_skipped_refused,
        "target_unavailable_count": report.target_unavailable_count,
        "provider_outage_count": report.provider_outage_count,
        "total_cost_usd": report.total_cost_usd,
        "run_id": run_id,
        "run_dir": str(run_dir),
    }
    print(json.dumps(payload, indent=2, default=str))


# Halt-reason → process exit code. 0 means "clean shutdown for a benign
# reason"; non-zero indicates an external condition the operator may care
# about (target outage, HMAC misconfig, provider outage, content filter
# stuck). Cost cap + coverage met + max iterations + interrupt all exit 0.
_HALT_EXIT_CODES: dict[HaltReason, int] = {
    HaltReason.COST_CAP_REACHED: 0,
    HaltReason.COST_CAP_PROJECTED_BREACH: 0,
    HaltReason.MAX_ITERATIONS_REACHED: 0,
    HaltReason.SIGNAL_TO_COST_COLLAPSED: 0,
    HaltReason.COVERAGE_FLOOR_MET_NO_OPEN: 0,
    HaltReason.NO_ELIGIBLE_CATEGORIES: 0,
    HaltReason.SIGNAL_INTERRUPT: 0,
    HaltReason.HMAC_REJECTED: 4,
    HaltReason.TARGET_CIRCUIT_OPEN: 5,
    HaltReason.CONTENT_FILTER_JAMMED: 6,
    HaltReason.PROVIDER_OUTAGE_PERSISTENT: 7,
}


def _exit_code_for_halt(reason: HaltReason) -> int:
    return _HALT_EXIT_CODES.get(reason, 1)


# ---------------------------------------------------------------------------
# Single-shot mode (Phase 1a #15 — preserved verbatim for regression replay)
# ---------------------------------------------------------------------------


def _run_single_shot(args: argparse.Namespace) -> int:
    # Audit MEDIUM-2: symmetric rejection — continuous-only flags should not
    # be silently ignored in single-shot mode. The parser's help text marks
    # each flag with [continuous]/[single-shot] but only the runtime check
    # makes the boundary enforced.
    _continuous_only_set = []
    if args.max_iterations is not None:
        _continuous_only_set.append("--max-iterations")
    if args.max_budget is not None:
        _continuous_only_set.append("--max-budget")
    if args.halt_on_empty_categories:
        _continuous_only_set.append("--halt-on-empty-categories")
    if args.signal_floor is not None:
        _continuous_only_set.append("--signal-floor")
    if _continuous_only_set:
        print(
            "ERROR: the following flags are continuous-mode-only and require "
            f"--continuous: {', '.join(_continuous_only_set)}.",
            file=sys.stderr,
        )
        return 2

    if args.max_attacks != 1:
        # Phase 1a #15 ships single-shot only; for N>1 use --continuous.
        print(
            f"WARN: single-shot mode supports --max-attacks=1; got "
            f"{args.max_attacks}. Use --continuous for multi-iteration runs.",
            file=sys.stderr,
        )

    seed_id = args.seed or DEFAULT_SEEDS_BY_CATEGORY.get(args.category)
    if not seed_id:
        print(
            f"ERROR: No default seed for category {args.category}. "
            "Pass --seed explicitly or seed the category in Phase 1b.",
            file=sys.stderr,
        )
        return 2

    run_id = args.run_id or _new_run_id()
    results_dir = Path(args.results_dir or os.getenv("RESULTS_DIR", "./evals/results"))
    evals_dir = Path(os.getenv("EVALS_DIR", "./evals"))
    cost_cap_usd = float(os.getenv("MAX_SESSION_COST_USD", "10"))

    target_url = os.getenv("RED_TEAM_TARGET_URL", "")
    if not target_url:
        print("ERROR: RED_TEAM_TARGET_URL is required. Populate .env.", file=sys.stderr)
        return 2

    seed = load_seed(seed_id, category=args.category, evals_dir=evals_dir)
    primary_pid = int(seed["primary_patient_id"])

    handle = start_run(
        run_id=run_id,
        results_dir=results_dir,
        target_url=target_url,
        extra_metadata={
            "seed_id": seed_id,
            "category": args.category,
            "cli": "phase_1a_15_single_shot",
        },
    )
    ledger = CostLedger.create(run_dir=handle.run_dir, cost_cap_usd=cost_cap_usd)
    coverage = CoverageTracker.create(
        run_dir=handle.run_dir,
        target_version_sha="unknown",
        cost_cap_usd=cost_cap_usd,
    )
    obs = Observability.from_env(session_id=run_id)

    logger.info("run=%s seed=%s category=%s", run_id, seed_id, args.category)
    logger.info("results dir: %s", handle.run_dir)

    red_team = RedTeamAgent.from_env()
    target = TargetClient.from_env()
    judge = JudgeAgent.from_env()

    # -- Red Team --
    try:
        with obs.agent_span(
            agent_name=RED_TEAM_AGENT_NAME,
            agent_version=RED_TEAM_AGENT_VERSION,
            agent_role="attack_generation",
            category=args.category,
            inputs={"seed_id": seed_id, "mutate": not args.no_mutate},
        ) as rt_span:
            candidate = red_team.generate(
                seed_id=seed_id,
                category=args.category,
                evals_dir=evals_dir,
                sequence=1,
                mutate=not args.no_mutate,
            )
            rt_span.update(output={"attack_id": candidate.attack_id})
    except AttackRefusedError as exc:
        print(
            f"REFUSED at pre-flight: reason={exc.reason} label={exc.label}",
            file=sys.stderr,
        )
        obs.flush()
        return 3

    # ORDER LOAD-BEARING — same invariant the daemon enforces:
    # save_attack FIRST so cost entries never reference orphan attack files.
    handle.save_attack(candidate)
    ledger.record(
        tier="red_team",
        model_used=candidate.model_used,
        cost_usd=candidate.cost_usd,
        tokens_input=0,
        tokens_output=0,
        related_id=candidate.attack_id,
    )
    logger.info("attack saved: %s", candidate.attack_id)

    # -- Target call --
    try:
        with obs.agent_span(
            agent_name="target_client",
            agent_version="v0.1.0",
            agent_role="signed_http_to_copilot",
            attack_id=candidate.attack_id,
            category=args.category,
            inputs={"endpoint": target.base_url + candidate.target_endpoint},
        ) as tc_span:
            response = target.chat(
                messages=[
                    Message(role="user", content=candidate.payload.content or "")
                ],
                patient_id=primary_pid,
                session_id=run_id,
            )
            tc_span.update(
                output={
                    "status_code": response.status_code,
                    "request_id": response.request_id,
                    "trace_id": response.trace_id,
                    "assistant_text_len": len(response.assistant_text),
                }
            )
    except HmacRejectedError as exc:
        print(f"HMAC rejected by target: {exc}", file=sys.stderr)
        obs.flush()
        return 4
    except TargetUnavailableError as exc:
        print(f"Target unavailable: {exc}", file=sys.stderr)
        obs.flush()
        return 5

    # coverage.record_attack AFTER target success — same invariant as daemon
    coverage.record_attack(category=args.category)

    logger.info(
        "target HTTP %d (latency=%dms request_id=%s)",
        response.status_code,
        response.latency_ms,
        response.request_id,
    )

    # -- Judge --
    with obs.agent_span(
        agent_name="judge",
        agent_version="v0.1.0",
        agent_role="verdict_rendering",
        attack_id=candidate.attack_id,
        category=args.category,
        inputs={"attack_id": candidate.attack_id, "target_status": response.status_code},
    ) as j_span:
        verdict = judge.evaluate(
            attack=candidate,
            target_response_text=response.assistant_text,
            sequence=1,
            evals_dir=evals_dir,
        )
        j_span.update(
            output={
                "verdict_id": verdict.verdict_id,
                "verdict": verdict.verdict,
                "confidence": verdict.confidence,
                "criteria_triggered": verdict.criteria_triggered,
                "human_escalation_required": verdict.human_escalation_required,
            }
        )

    ledger.record(
        tier="judge",
        model_used=verdict.judge_model,
        cost_usd=verdict.cost_usd,
        tokens_input=0,
        tokens_output=0,
        related_id=verdict.verdict_id,
    )
    handle.save_verdict(verdict)
    coverage.record_verdict(
        category=args.category,
        verdict=verdict.verdict,
        session_cost_usd=ledger.total_usd,
    )

    obs.flush()

    # -- Summary --
    summary = {
        "run_id": run_id,
        "results_dir": str(handle.run_dir),
        "category": args.category,
        "seed_id": seed_id,
        "attack_id": candidate.attack_id,
        "verdict_id": verdict.verdict_id,
        "verdict": verdict.verdict,
        "confidence": verdict.confidence,
        "criteria_triggered": verdict.criteria_triggered,
        "human_escalation_required": verdict.human_escalation_required,
        "target_http_status": response.status_code,
        "target_latency_ms": response.latency_ms,
        "target_request_id": response.request_id,
        "session_cost_usd": ledger.total_usd,
        "cost_by_tier": ledger.by_tier_usd,
    }
    print(json.dumps(summary, indent=2, default=str))
    return 0


def _new_run_id() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:6]


if __name__ == "__main__":
    sys.exit(main())


__all__ = ["main"]
