"""End-to-end attack CLI — the Phase 1a vertical slice.

   Red Team seed/mutation → live target call → Judge verdict → persisted
   regression artifacts → cost ledger updated → coverage state updated

Single-shot mode (this commit, Phase 1a #15): one attack, exit.
Continuous mode (Phase 1b A2/A3): the `while not halt:` loop that calls
this same vertical slice in iteration. Aria owns the continuous-mode CLI
extension.

Acceptance criterion (work plan):
  `python -m clinical_redteam.run --category sensitive_information_disclosure
   --max-attacks 1` runs end-to-end against the LIVE target; produces
   `evals/results/<run-id>/` with attack + verdict + cost line.

The verdict can be PASS / FAIL / PARTIAL / UNCERTAIN. What matters for
the Phase 1a gate is that the FLOW works — the C-7 rediscovery may or
may not fire on the first attempt; mutation pressure across the
continuous-mode loop (Phase 1b) is where signal accumulates.
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

from dotenv import load_dotenv

from clinical_redteam.agents.judge import JudgeAgent
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
from clinical_redteam.cost_ledger import CostLedger
from clinical_redteam.coverage import CoverageTracker
from clinical_redteam.observability import Observability
from clinical_redteam.persistence import start_run
from clinical_redteam.schemas import Category
from clinical_redteam.target_client import (
    HmacRejectedError,
    Message,
    TargetClient,
    TargetUnavailableError,
)

logger = logging.getLogger(__name__)

DEFAULT_SEEDS_BY_CATEGORY: dict[Category, str] = {
    "sensitive_information_disclosure": "c7-paraphrased-leakage",
    # Phase 1b Bram adds: "prompt_injection": ..., "unbounded_consumption": ...
}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m clinical_redteam.run",
        description="Single-shot end-to-end attack (Phase 1a #15 vertical slice).",
    )
    parser.add_argument(
        "--category",
        choices=[
            "sensitive_information_disclosure",
            "prompt_injection",
            "unbounded_consumption",
        ],
        default="sensitive_information_disclosure",
        help="Attack category to load seed from (default: SID — the C-7 reproducer)",
    )
    parser.add_argument(
        "--seed",
        default=None,
        help=(
            "Specific seed_id to use; defaults to the canonical seed for the "
            "category (SID → c7-paraphrased-leakage)"
        ),
    )
    parser.add_argument(
        "--max-attacks",
        type=int,
        default=1,
        help="Number of attack iterations (Phase 1a #15 supports 1; Phase 1b A3 extends)",
    )
    parser.add_argument(
        "--no-mutate",
        action="store_true",
        help="Use seed verbatim instead of calling OpenRouter for mutation (fixture mode)",
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help="Run ID for the results directory (defaults to UTC timestamp + uuid suffix)",
    )
    parser.add_argument(
        "--results-dir",
        default=None,
        help="Override RESULTS_DIR env var",
    )
    args = parser.parse_args(argv)

    load_dotenv()
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.max_attacks != 1:
        # Phase 1a #15 ships single-shot only; continuous mode (Phase 1b A2/A3)
        # extends this loop with halt conditions per ARCH §10.2.
        print(
            f"WARN: Phase 1a #15 supports --max-attacks=1; got {args.max_attacks}. "
            "Continuous mode lands in Phase 1b A2/A3.",
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
        target_version_sha="unknown",  # Phase 1b reads /version from target
        cost_cap_usd=cost_cap_usd,
    )
    obs = Observability.from_env(session_id=run_id)

    logger.info("run=%s seed=%s category=%s", run_id, seed_id, args.category)
    logger.info("results dir: %s", handle.run_dir)

    red_team = RedTeamAgent.from_env()
    target = TargetClient.from_env()
    judge = JudgeAgent.from_env()

    coverage.record_attack(category=args.category)

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

    ledger.record(
        tier="red_team",
        model_used=candidate.model_used,
        cost_usd=candidate.cost_usd,
        tokens_input=0,  # exposed in Phase 1b once Red Team plumbs usage through
        tokens_output=0,
        related_id=candidate.attack_id,
    )
    handle.save_attack(candidate)
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
