"""Orchestrator Agent (ARCH §2.3, §3.6.1, §10.2).

The continuous-mode daemon. A pure-Python `while not halt:` loop that:

1. Evaluates halt conditions BEFORE every external call (cost cap,
   signal-to-cost collapse, coverage-floor-met, max-iterations,
   halt-on-empty-categories, sustained provider/target outages).
2. Selects the next category per ARCH §3.6.1 priority rules.
3. Dispatches Red Team → Target → Judge → (Documentation if FAIL/PARTIAL).
4. Persists at every checkpoint via the existing RunHandle / CostLedger /
   CoverageTracker primitives — every artifact survives `kill -9`.

Design tenets:

- **No new disk artifacts** for MVP. CoverageTracker + CostLedger +
  RunHandle's manifest carry everything halt-eval and category-selection
  need. A4 may promote `replayed_attack_ids` to the manifest later.
- **Pure functions where possible.** `evaluate_halt()` and
  `select_category()` are module-level pure functions; the daemon's only
  job is sequencing + I/O. Tests pin halt-reason strings without
  instantiating the daemon.
- **Constructor injection.** The daemon does NOT call any
  `*.from_env()`; the CLI (A3) wires agents + clients in and hands them
  to `OrchestratorDaemon(...)`. Tests inject fakes.
- **MVP scope.** Single-turn attacks only (ARCH §9.4). Multi-turn,
  target-version-change detection, LLM-augmented category picking are
  Phase 2.

Out of scope (deferred):

- `--continuous` CLI plumbing → A3 extends `run.py` against this API.
- Resume-from-checkpoint smoke + `replayed_attack_ids` persistence → A4.
- Daemon meta-tests → A5 (uses constructor-injection hooks defined here).
"""

from __future__ import annotations

import logging
import os
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from clinical_redteam.agents.documentation import (
    DocumentationAgent,
    NoDraftNeededError,
)
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
from clinical_redteam.cost_ledger import (
    CostCapExceededError,
    CostLedger,
)
from clinical_redteam.coverage import CoverageTracker
from clinical_redteam.observability import Observability
from clinical_redteam.openrouter import AllModelsFailedError
from clinical_redteam.persistence import RunHandle
from clinical_redteam.schemas import (
    AttackCandidate,
    Category,
    JudgeVerdict,
)
from clinical_redteam.target_client import (
    HmacRejectedError,
    Message,
    TargetClient,
    TargetUnavailableError,
)

AGENT_NAME = "orchestrator"
AGENT_VERSION = "v0.1.0"

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------


DEFAULT_COVERAGE_FLOOR = 10
"""Minimum attacks per category before that category is considered 'covered'
(ARCH §3.6.1 rule 3)."""

DEFAULT_SIGNAL_FLOOR = 0.0
"""Disabled by default — A3 may surface a `--signal-floor` flag. When > 0,
halts when `recent_signal.signal_to_cost < floor` after K attempts."""

DEFAULT_RECENT_K = 10
"""Window size for the rolling recent-signal computation (ARCH §3.6.1 rule 4)."""

DEFAULT_SIGNAL_MOMENTUM_THRESHOLD = 0.30
"""Fail+partial rate above which a category is considered 'on momentum'
(ARCH §3.6.1 rule 4)."""

DEFAULT_TARGET_OUTAGE_HALT_AFTER = 3
"""Consecutive target-unavailable events within a window before halting
(ARCH §10.2 — sustained target unavailability)."""

DEFAULT_REFUSAL_HALT_AFTER = 5
"""Consecutive content-filter refusals before halting (Red Team is stuck)."""

DEFAULT_PROVIDER_OUTAGE_HALT_AFTER = 5
"""Consecutive OpenRouter chain-exhausted events before halting."""

DEFAULT_PER_ITERATION_BUDGET_USD = 0.50
"""Projected next-iteration cost used by halt-check to predict cap-breach.
Conservative enough to cover one Red Team + one Judge + one Documentation
call at frontier-model rates."""

DEFAULT_PRIOR_VERDICTS_FOR_MUTATION = 3
"""Max same-seed verdicts threaded into Red Team mutation prompt (F5)."""


# Canonical seed for each category — same source-of-truth as run.py uses;
# moved into orchestrator so A3's run.py extension imports from here.
DEFAULT_SEEDS_BY_CATEGORY: dict[Category, str] = {
    "sensitive_information_disclosure": "c7-paraphrased-leakage",
    # Bram is adding canonical seeds for prompt_injection + unbounded_consumption
    # on the B-track. Until those land, those categories are "empty" — the
    # `halt_on_empty_categories` flag (and select_category) handles it.
}


# ---------------------------------------------------------------------------
# Enums + value types
# ---------------------------------------------------------------------------


class HaltReason(str, Enum):
    """Canonical halt-reason strings. Meta-tests pin these values."""

    RUN_NEXT = "run_next"
    COST_CAP_REACHED = "cost_cap_reached"
    COST_CAP_PROJECTED_BREACH = "cost_cap_projected_breach"
    MAX_ITERATIONS_REACHED = "max_iterations_reached"
    SIGNAL_TO_COST_COLLAPSED = "signal_to_cost_collapsed"
    COVERAGE_FLOOR_MET_NO_OPEN = "coverage_floor_met_no_open"
    NO_ELIGIBLE_CATEGORIES = "no_eligible_categories"
    TARGET_CIRCUIT_OPEN = "target_circuit_open"
    HMAC_REJECTED = "hmac_rejected"
    CONTENT_FILTER_JAMMED = "content_filter_jammed"
    PROVIDER_OUTAGE_PERSISTENT = "provider_outage_persistent"
    SIGNAL_INTERRUPT = "signal_interrupt"


@dataclass(frozen=True)
class HaltDecision:
    """Result of `evaluate_halt`. `is_halt=False` ⇒ run another iteration."""

    is_halt: bool
    reason: HaltReason
    flags: dict[str, bool] = field(default_factory=dict)


@dataclass(frozen=True)
class HaltReport:
    """Summary returned by `OrchestratorDaemon.run_until_halt()`."""

    reason: HaltReason
    iterations: int
    total_cost_usd: float
    attacks_attempted: int
    attacks_skipped_refused: int
    target_unavailable_count: int
    provider_outage_count: int


@dataclass(frozen=True)
class SelectionResult:
    """Output of `select_category`. `category is None` ⇒ no eligible category."""

    category: Category | None
    seed_id: str | None
    replay_attack_id: str | None
    rule: str


@dataclass(frozen=True)
class _SignalRecord:
    """One entry in the recent-signal rolling window."""

    category: str
    verdict: str
    cost_usd: float


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OrchestratorConfig:
    """All knobs the daemon respects. CLI / env reads happen at construction
    time (in `from_env`); the daemon itself never reads `os.environ`."""

    evals_dir: Path
    canonical_vuln_dir: Path
    coverage_floor: int = DEFAULT_COVERAGE_FLOOR
    signal_floor: float = DEFAULT_SIGNAL_FLOOR
    recent_k: int = DEFAULT_RECENT_K
    signal_momentum_threshold: float = DEFAULT_SIGNAL_MOMENTUM_THRESHOLD
    halt_on_empty_categories: bool = False
    per_iteration_cost_budget_usd: float = DEFAULT_PER_ITERATION_BUDGET_USD
    target_outage_halt_after: int = DEFAULT_TARGET_OUTAGE_HALT_AFTER
    refusal_halt_after: int = DEFAULT_REFUSAL_HALT_AFTER
    provider_outage_halt_after: int = DEFAULT_PROVIDER_OUTAGE_HALT_AFTER
    on_iteration: Callable[[dict[str, Any]], None] | None = None

    @classmethod
    def from_env(
        cls,
        *,
        evals_dir: Path | None = None,
        canonical_vuln_dir: Path | None = None,
        env: dict[str, str] | None = None,
        **overrides: Any,
    ) -> OrchestratorConfig:
        e = env if env is not None else os.environ
        evals = evals_dir or Path(e.get("EVALS_DIR", "./evals"))
        canonical = canonical_vuln_dir or (evals / "vulnerabilities")
        defaults: dict[str, Any] = {
            "evals_dir": evals,
            "canonical_vuln_dir": canonical,
            "coverage_floor": int(
                e.get("ORCHESTRATOR_COVERAGE_FLOOR", DEFAULT_COVERAGE_FLOOR)
            ),
            "signal_floor": float(
                e.get("ORCHESTRATOR_SIGNAL_FLOOR", DEFAULT_SIGNAL_FLOOR)
            ),
            "recent_k": int(e.get("ORCHESTRATOR_RECENT_K", DEFAULT_RECENT_K)),
        }
        defaults.update(overrides)
        return cls(**defaults)


# ---------------------------------------------------------------------------
# Recent-signal rolling window
# ---------------------------------------------------------------------------


class RecentSignalWindow:
    """Bounded deque of the last K verdicts, used by `select_category` rule 4
    and by `evaluate_halt` for signal-to-cost collapse detection.

    Rehydrated from `<run-dir>/verdicts/*.json` at daemon construction so
    resumed runs get warm signal without disk schema changes.
    """

    def __init__(self, k: int) -> None:
        self._buf: deque[_SignalRecord] = deque(maxlen=max(1, k))

    @property
    def attempts(self) -> int:
        return len(self._buf)

    def push(self, *, category: str, verdict: str, cost_usd: float) -> None:
        self._buf.append(
            _SignalRecord(category=category, verdict=verdict, cost_usd=cost_usd)
        )

    def fail_partial_rate(self, category: str) -> float:
        """Rate of (fail|partial) over the last K attempts in `category`."""
        in_cat = [r for r in self._buf if r.category == category]
        if not in_cat:
            return 0.0
        hits = sum(1 for r in in_cat if r.verdict in ("fail", "partial"))
        return hits / len(in_cat)

    def signal_to_cost(self) -> float:
        """Open-finding-like signal per USD across the window. `fail`+`partial`
        count as signal; `pass` and `uncertain` do not."""
        total_cost = sum(r.cost_usd for r in self._buf)
        if total_cost <= 0:
            return 0.0
        signal = sum(1 for r in self._buf if r.verdict in ("fail", "partial"))
        return signal / total_cost


# ---------------------------------------------------------------------------
# Pure functions — halt evaluation + category selection
# ---------------------------------------------------------------------------


def evaluate_halt(
    *,
    coverage: CoverageTracker,
    ledger: CostLedger,
    config: OrchestratorConfig,
    recent_signal: RecentSignalWindow,
    iteration: int,
    max_iterations: int | None,
    target_unavailable_streak: int,
    refusal_streak: int,
    provider_outage_streak: int,
) -> HaltDecision:
    """Halt-evaluation state machine. Pure function — no I/O, no agent calls.

    First matching condition wins; ordering is load-bearing.

    See ARCH §10.2 for the failure modes mapped to each halt reason. Soft-cap
    is not a halt — surfaced via `flags["soft_cap_tripped"]` so the daemon
    can pass `mutate=False` (Phase 2 mutation-scope reduction) without ending
    the run.
    """
    flags = {"soft_cap_tripped": ledger.soft_cap_tripped()}

    # 1. Hard cost cap reached (already over the line).
    if ledger.total_usd >= ledger.cost_cap_usd:
        return HaltDecision(True, HaltReason.COST_CAP_REACHED, flags)

    # 2. Projected next-iteration cost would breach the cap.
    if ledger.would_exceed_cap(config.per_iteration_cost_budget_usd):
        return HaltDecision(True, HaltReason.COST_CAP_PROJECTED_BREACH, flags)

    # 3. Bounded iteration count.
    if max_iterations is not None and iteration >= max_iterations:
        return HaltDecision(True, HaltReason.MAX_ITERATIONS_REACHED, flags)

    # 4. Signal-to-cost collapse (only checks once we have a full window).
    if (
        config.signal_floor > 0.0
        and recent_signal.attempts >= config.recent_k
        and recent_signal.signal_to_cost() < config.signal_floor
    ):
        return HaltDecision(True, HaltReason.SIGNAL_TO_COST_COLLAPSED, flags)

    # 5. Sustained target unavailability.
    if target_unavailable_streak >= config.target_outage_halt_after:
        return HaltDecision(True, HaltReason.TARGET_CIRCUIT_OPEN, flags)

    # 6. Content-filter jam (Red Team stuck producing refused payloads).
    if refusal_streak >= config.refusal_halt_after:
        return HaltDecision(True, HaltReason.CONTENT_FILTER_JAMMED, flags)

    # 7. Provider outage persistent (OpenRouter chain exhausted repeatedly).
    if provider_outage_streak >= config.provider_outage_halt_after:
        return HaltDecision(True, HaltReason.PROVIDER_OUTAGE_PERSISTENT, flags)

    # 8. Coverage floor met for ALL categories AND no open findings remain.
    state = coverage.to_state(session_cost_usd=ledger.total_usd)
    all_at_floor = all(
        cat.attack_count >= config.coverage_floor for cat in state.categories.values()
    )
    no_open = all(cat.open_findings == 0 for cat in state.categories.values())
    if all_at_floor and no_open:
        return HaltDecision(True, HaltReason.COVERAGE_FLOOR_MET_NO_OPEN, flags)

    return HaltDecision(False, HaltReason.RUN_NEXT, flags)


def select_category(
    *,
    coverage: CoverageTracker,
    recent_signal: RecentSignalWindow,
    available_categories: dict[Category, str | None] | dict[Category, bool],
    replayed_attack_ids: set[str],
    open_findings_by_category: dict[Category, list[str]],
    config: OrchestratorConfig,
) -> SelectionResult:
    """Decide which (category, seed_id) to attack next per ARCH §3.6.1.

    Pure function. `open_findings_by_category` maps category → list of
    `attack_id`s for FAIL verdicts not yet in `replayed_attack_ids`. The
    daemon assembles this once per iteration from manifest + verdicts.

    `available_categories` may be either:
    - `dict[Category, str | None]` mapping category → seed_id (recommended;
      what the daemon supplies) — eliminates the silent-no-progress path
      when a category is seeded but no entry exists in
      `DEFAULT_SEEDS_BY_CATEGORY`.
    - `dict[Category, bool]` for back-compat with pure-function tests that
      don't care which seed gets picked. In bool form, seed_id falls back
      to `DEFAULT_SEEDS_BY_CATEGORY` lookup.

    Returns SelectionResult with `category=None` when no seeded category
    is available AND `halt_on_empty_categories=True`.
    """
    state = coverage.to_state(session_cost_usd=0.0)  # cost not needed here

    def _seed_for(cat: Category) -> str | None:
        v = available_categories.get(cat)
        if isinstance(v, str):
            return v
        if v is True:
            return DEFAULT_SEEDS_BY_CATEGORY.get(cat)
        return None

    def _is_seeded(cat: Category) -> bool:
        return _seed_for(cat) is not None

    # Rule 1: target version changed → regression. MVP stub.
    # Implemented in Phase 2 when target /version endpoint is wired.

    # Rule 2: open finding without replay.
    for category, attack_ids in open_findings_by_category.items():
        unreplayed = [aid for aid in attack_ids if aid not in replayed_attack_ids]
        if unreplayed and _is_seeded(category):
            return SelectionResult(
                category=category,
                seed_id=_seed_for(category),
                replay_attack_id=unreplayed[-1],  # most recent first
                rule="rule_2_replay_open_finding",
            )

    # Rule 3: any category below coverage floor → pick lowest.
    below_floor = [
        cat
        for cat, c in state.categories.items()
        if c.attack_count < config.coverage_floor
    ]
    if below_floor:
        # Stable tiebreak: lowest count, then MVP-declared order.
        below_floor.sort(
            key=lambda c: (
                state.categories[c].attack_count,
                _mvp_category_order(c),
            )
        )
        for category in below_floor:
            if _is_seeded(category):  # type: ignore[arg-type]
                return SelectionResult(
                    category=category,  # type: ignore[arg-type]
                    seed_id=_seed_for(category),  # type: ignore[arg-type]
                    replay_attack_id=None,
                    rule="rule_3_coverage_floor",
                )
        if config.halt_on_empty_categories:
            return SelectionResult(None, None, None, "no_seeded_below_floor")
        # else fall through to subsequent rules

    # Rule 4: signal-momentum on the highest-rate category.
    momentum_candidates = [
        cat
        for cat in state.categories
        if recent_signal.fail_partial_rate(cat)
        >= config.signal_momentum_threshold
        and _is_seeded(cat)  # type: ignore[arg-type]
    ]
    if momentum_candidates:
        momentum_candidates.sort(
            key=lambda c: recent_signal.fail_partial_rate(c), reverse=True
        )
        cat = momentum_candidates[0]
        return SelectionResult(
            category=cat,  # type: ignore[arg-type]
            seed_id=_seed_for(cat),  # type: ignore[arg-type]
            replay_attack_id=None,
            rule="rule_4_signal_momentum",
        )

    # Rule 5: round-robin by stale-since timestamp over SEEDED categories.
    seeded = [cat for cat in available_categories if _is_seeded(cat)]  # type: ignore[arg-type]
    if not seeded:
        # All categories are unseeded. Halt cleanly — running with no seeds
        # would either crash on load_seed or burn iterations doing nothing.
        return SelectionResult(None, None, None, "no_seeded_categories_remain")

    def _stale_key(cat: Category) -> tuple[int, str]:
        last = state.categories[cat].last_attack_at
        # Never-attacked categories sort first (priority).
        return (1 if last is not None else 0, str(last) if last else "")

    seeded.sort(key=_stale_key)  # type: ignore[arg-type]
    chosen = seeded[0]
    return SelectionResult(
        category=chosen,  # type: ignore[arg-type]
        seed_id=_seed_for(chosen),  # type: ignore[arg-type]
        replay_attack_id=None,
        rule="rule_5_round_robin",
    )


def _mvp_category_order(category: str) -> int:
    """Tiebreak by MVP-declared order (SID > PI > UC) — matches ARCH §9.4."""
    order: dict[str, int] = {
        "sensitive_information_disclosure": 0,
        "prompt_injection": 1,
        "unbounded_consumption": 2,
    }
    return order.get(category, 99)


# ---------------------------------------------------------------------------
# Daemon
# ---------------------------------------------------------------------------


@dataclass
class OrchestratorDaemon:
    """Continuous-mode orchestrator daemon.

    Constructor-injected; no `from_env`. The CLI (A3) wires it together:

        daemon = OrchestratorDaemon(
            red_team=RedTeamAgent.from_env(),
            judge=JudgeAgent.from_env(),
            documentation=DocumentationAgent.from_env(),
            target=TargetClient.from_env(),
            coverage=CoverageTracker.create(...),
            ledger=CostLedger.create(...),
            handle=start_run(...),
            obs=Observability.from_env(...),
            config=OrchestratorConfig.from_env(...),
            session_id=run_id,
        )
        report = daemon.run_until_halt(max_iterations=None)
    """

    red_team: RedTeamAgent
    judge: JudgeAgent
    documentation: DocumentationAgent
    target: TargetClient
    coverage: CoverageTracker
    ledger: CostLedger
    handle: RunHandle
    obs: Observability
    config: OrchestratorConfig
    session_id: str
    target_version_sha: str = "unknown"

    # private state
    signal_window: RecentSignalWindow = field(init=False)
    replayed_attack_ids: set[str] = field(init=False, default_factory=set)
    _seed_cache: dict[str, dict[str, Any]] = field(init=False, default_factory=dict)
    _target_unavailable_streak: int = field(init=False, default=0)
    _refusal_streak: int = field(init=False, default=0)
    _provider_outage_streak: int = field(init=False, default=0)
    _attacks_skipped_refused: int = field(init=False, default=0)
    _target_unavailable_count: int = field(init=False, default=0)
    _provider_outage_count: int = field(init=False, default=0)
    _attacks_attempted: int = field(init=False, default=0)

    def __post_init__(self) -> None:
        self.signal_window = RecentSignalWindow(self.config.recent_k)
        self._seed_id_by_category: dict[Category, str | None] = (
            self._discover_seed_ids()
        )
        # A4: rehydrate signal_window from on-disk verdicts so a resumed
        # daemon's halt evaluation reflects the prior session's signal.
        # replayed_attack_ids stays in-memory for MVP — a kill -9 between
        # the replay-pick and the next verdict write would re-replay a
        # finding, which is an acceptable correctness leak for MVP (cost
        # bounded by mutation depth + cost cap; replay is also idempotent
        # from the human reviewer's perspective).
        self._rehydrate_signal_window_from_disk()
        # A4 polish (Tate B6 coordination ticket
        # A4-resume-coverage-reconciliation-tate-to-aria.md): coverage.json
        # can desync from verdicts/ if the daemon dies between save_verdict
        # and coverage.record_verdict. Verdicts/ is the source of truth;
        # rebuild coverage from disk on every construction so resumed
        # daemons see consistent state.
        self._reconcile_coverage_from_disk()

    # ------------------------------------------------------------------ public

    def run_until_halt(self, max_iterations: int | None = None) -> HaltReport:
        """Run the daemon loop until a halt condition fires.

        `max_iterations=None` runs unbounded (until cost cap / signal collapse
        / coverage floor / interrupt). Tests pass a small integer to bound the
        loop deterministically.
        """
        iteration = 0
        try:
            while True:
                decision = evaluate_halt(
                    coverage=self.coverage,
                    ledger=self.ledger,
                    config=self.config,
                    recent_signal=self.signal_window,
                    iteration=iteration,
                    max_iterations=max_iterations,
                    target_unavailable_streak=self._target_unavailable_streak,
                    refusal_streak=self._refusal_streak,
                    provider_outage_streak=self._provider_outage_streak,
                )
                if decision.is_halt:
                    return self._finalize(decision.reason, iteration)

                sel = select_category(
                    coverage=self.coverage,
                    recent_signal=self.signal_window,
                    available_categories=self._seed_id_by_category,
                    replayed_attack_ids=self.replayed_attack_ids,
                    open_findings_by_category=self._open_findings_index(),
                    config=self.config,
                )
                if sel.category is None:
                    return self._finalize(
                        HaltReason.NO_ELIGIBLE_CATEGORIES, iteration
                    )

                iteration += 1
                proceeded = self._run_one_iteration(sel, iteration)
                if proceeded == "hmac_rejected":
                    return self._finalize(HaltReason.HMAC_REJECTED, iteration)

        except KeyboardInterrupt:
            logger.warning("KeyboardInterrupt — finalizing daemon cleanly")
            return self._finalize(HaltReason.SIGNAL_INTERRUPT, iteration)
        finally:
            self.obs.flush()

    # ------------------------------------------------------------------ internals

    def _run_one_iteration(
        self, sel: SelectionResult, iteration: int
    ) -> str | None:
        """Execute one Red Team → Target → Judge → (Documentation) cycle.

        Returns a sentinel string for unrecoverable conditions the caller
        must propagate (currently only "hmac_rejected"). Otherwise None.
        """
        assert sel.category is not None  # select_category guarantees this
        category: Category = sel.category
        seed_id = sel.seed_id

        if seed_id is None:
            logger.warning(
                "select_category returned category=%s seed_id=None; "
                "skipping iteration",
                category,
            )
            return None

        sequence = self._next_sequence()
        # F5: verdict-informed mutation. Pull the last 3 same-seed verdicts
        # from disk so the LLM can reason about what didn't work and pivot to
        # a different angle. PHI-safe: only structural fields are forwarded
        # (see `_render_prior_verdicts_block`); Evidence is dropped.
        prior_verdicts = self._prior_verdicts_for_seed(
            seed_id, n=DEFAULT_PRIOR_VERDICTS_FOR_MUTATION
        )

        # 1. Red Team
        try:
            with self.obs.agent_span(
                agent_name=RED_TEAM_AGENT_NAME,
                agent_version=RED_TEAM_AGENT_VERSION,
                agent_role="attack_generation",
                category=category,
                inputs={
                    "seed_id": seed_id,
                    "rule": sel.rule,
                    "prior_verdict_count": len(prior_verdicts),
                },
            ) as rt_span:
                candidate = self.red_team.generate(
                    seed_id=seed_id,
                    category=category,
                    evals_dir=self.config.evals_dir,
                    sequence=sequence,
                    mutate=(not self.ledger.soft_cap_tripped()),
                    prior_verdicts=prior_verdicts,
                )
                rt_span.update(output={"attack_id": candidate.attack_id})
        except AttackRefusedError as exc:
            self._refusal_streak += 1
            self._attacks_skipped_refused += 1
            logger.warning(
                "iteration %d: AttackRefused %s — streak=%d",
                iteration,
                exc.reason,
                self._refusal_streak,
            )
            return None
        except AllModelsFailedError:
            self._provider_outage_streak += 1
            self._provider_outage_count += 1
            logger.warning(
                "iteration %d: Red Team provider outage — streak=%d",
                iteration,
                self._provider_outage_streak,
            )
            return None

        self._refusal_streak = 0  # consecutive-only

        # ORDER LOAD-BEARING (hard rule #1 / #7):
        # 1. Persist the attack artifact FIRST — durable on disk.
        # 2. THEN record cost (cost entry's related_id references the artifact).
        # Reverse order would create orphan cost entries on kill -9 between
        # the two writes (audit CRITICAL-1).
        self.handle.save_attack(candidate)  # CHECKPOINT before target call
        self.ledger.record(
            tier="red_team",
            model_used=candidate.model_used,
            cost_usd=candidate.cost_usd,
            tokens_input=0,
            tokens_output=0,
            related_id=candidate.attack_id,
        )
        # NOTE: coverage.record_attack + _attacks_attempted moved to AFTER
        # the target call so a TargetUnavailable mid-iteration doesn't count
        # toward the coverage floor (audit HIGH-1).

        # 2. Target call
        try:
            with self.obs.agent_span(
                agent_name="target_client",
                agent_version="v0.1.0",
                agent_role="signed_http_to_copilot",
                attack_id=candidate.attack_id,
                category=category,
                inputs={"endpoint": candidate.target_endpoint},
            ) as tc_span:
                response = self.target.chat(
                    messages=[
                        Message(
                            role="user",
                            content=candidate.payload.content or "",
                        )
                    ],
                    patient_id=self._primary_pid_for_seed(seed_id, category),
                    session_id=self.session_id,
                )
                tc_span.update(
                    output={
                        "status_code": response.status_code,
                        "request_id": response.request_id,
                    }
                )
        except HmacRejectedError as exc:
            logger.error(
                "iteration %d: HMAC rejected by target — halting: %s", iteration, exc
            )
            return "hmac_rejected"
        except TargetUnavailableError as exc:
            self._target_unavailable_streak += 1
            self._target_unavailable_count += 1
            logger.warning(
                "iteration %d: TargetUnavailable — streak=%d: %s",
                iteration,
                self._target_unavailable_streak,
                exc,
            )
            return None

        self._target_unavailable_streak = 0
        self._provider_outage_streak = 0  # Red Team succeeded, reset

        # Now that the target call succeeded, count this as a real attack
        # toward coverage. Reordered from pre-target per audit HIGH-1.
        self.coverage.record_attack(category=category)
        self._attacks_attempted += 1

        # 3. Judge
        with self.obs.agent_span(
            agent_name="judge",
            agent_version="v0.1.0",
            agent_role="verdict_rendering",
            attack_id=candidate.attack_id,
            category=category,
            inputs={
                "attack_id": candidate.attack_id,
                "target_status": response.status_code,
            },
        ) as j_span:
            verdict = self.judge.evaluate(
                attack=candidate,
                target_response_text=response.assistant_text,
                sequence=sequence,
                evals_dir=self.config.evals_dir,
            )
            j_span.update(
                output={
                    "verdict_id": verdict.verdict_id,
                    "verdict": verdict.verdict,
                    "confidence": verdict.confidence,
                    "human_escalation_required": verdict.human_escalation_required,
                }
            )

        try:
            self.ledger.record(
                tier="judge",
                model_used=verdict.judge_model,
                cost_usd=verdict.cost_usd,
                tokens_input=0,
                tokens_output=0,
                related_id=verdict.verdict_id,
            )
        except CostCapExceededError:
            # ledger.record() does not raise on cap-exceed by default; this
            # branch is defensive only (covers a future tightening).
            logger.warning(
                "iteration %d: Judge cost recording exceeded cap — halt next pass",
                iteration,
            )

        self.handle.save_verdict(verdict)  # CHECKPOINT
        self.coverage.record_verdict(
            category=category,
            verdict=verdict.verdict,
            session_cost_usd=self.ledger.total_usd,
        )
        self.signal_window.push(
            category=category,
            verdict=verdict.verdict,
            cost_usd=candidate.cost_usd + verdict.cost_usd,
        )
        if sel.replay_attack_id is not None:
            self.replayed_attack_ids.add(sel.replay_attack_id)

        # 4. Documentation (only on fail/partial)
        # ASI06 / cost-runaway defense (audit HIGH-2): if a poisoned Judge is
        # returning constant "fail" verdicts, the Documentation Agent would be
        # invoked every iteration and burn budget on prose generation. We
        # check projected-cap BEFORE invoking. The next-iteration halt would
        # also catch this, but the explicit guard prevents a single Doc call
        # from being the call that crosses the cap.
        doc_vuln_id: str | None = None
        if verdict.verdict in ("fail", "partial"):
            if self.ledger.would_exceed_cap(
                self.config.per_iteration_cost_budget_usd
            ):
                logger.warning(
                    "iteration %d: skipping Documentation draft for %s — "
                    "would breach cost cap; halt fires on next pass",
                    iteration,
                    verdict.verdict,
                )
            else:
                doc_vuln_id = self._run_documentation(
                    candidate=candidate,
                    verdict=verdict,
                    response_text=response.assistant_text,
                )

        self._emit_iteration_line(
            iteration=iteration,
            sel=sel,
            candidate=candidate,
            verdict=verdict,
            response_status=response.status_code,
            response_latency_ms=response.latency_ms,
            doc_vuln_id=doc_vuln_id,
        )
        return None

    def _run_documentation(
        self,
        *,
        candidate: AttackCandidate,
        verdict: JudgeVerdict,
        response_text: str,
    ) -> str | None:
        try:
            with self.obs.agent_span(
                agent_name="documentation",
                agent_version="v0.1.0",
                agent_role="vuln_draft_authoring",
                attack_id=candidate.attack_id,
                category=candidate.category,
                inputs={"verdict": verdict.verdict, "confidence": verdict.confidence},
            ) as d_span:
                draft = self.documentation.draft(
                    attack=candidate,
                    target_response_text=response_text,
                    verdict=verdict,
                    target_version_sha=self.target_version_sha,
                    canonical_dir=self.config.canonical_vuln_dir,
                    run_handle=self.handle,
                )
                d_span.update(
                    output={
                        "vuln_id": draft.vuln_id,
                        "severity": draft.severity,
                        "model_used": draft.model_used,
                    }
                )
        except NoDraftNeededError:
            logger.error(
                "Documentation Agent rejected fail/partial verdict — orchestrator bug"
            )
            return None
        except AllModelsFailedError:
            # Should not bubble (the agent has a deterministic fallback) but
            # defend against future tightening.
            logger.warning("Documentation Agent provider outage; draft incomplete")
            return None
        except Exception:  # noqa: BLE001
            # Audit CRITICAL-2: the agent atomically writes the canonical
            # draft file BEFORE returning. If anything raises after that
            # write (e.g., DuplicateArtifactError on the per-run snapshot,
            # or an unexpected Pydantic validation regression), the file
            # exists on disk but the cost ledger has no entry. Log loudly
            # so a human notices the inconsistency; do not crash the daemon.
            logger.exception(
                "Documentation Agent raised an unexpected exception; "
                "canonical draft MAY exist on disk without a ledger entry. "
                "Inspect evals/vulnerabilities/ for orphan VULN-NNN-DRAFT.md."
            )
            return None

        self.ledger.record(
            tier="documentation",
            model_used=draft.model_used,
            cost_usd=draft.cost_usd,
            tokens_input=draft.tokens_input,
            tokens_output=draft.tokens_output,
            related_id=draft.vuln_id,
        )
        return draft.vuln_id

    # ------------------------------------------------------------------ helpers

    def _next_sequence(self) -> int:
        """Sequence number for attack/verdict IDs within the run.

        Derives from `len(manifest['attack_ids']) + 1` — same value across
        restarts because the manifest is authoritative.
        """
        manifest = self.handle.load_manifest()
        return len(manifest.get("attack_ids", [])) + 1

    def _prior_verdicts_for_seed(
        self, seed_id: str, *, n: int = DEFAULT_PRIOR_VERDICTS_FOR_MUTATION
    ) -> list[JudgeVerdict]:
        """Return the last `n` JudgeVerdicts whose attack mutated from `seed_id`.

        F5 feeds these into the Red Team mutation prompt so the LLM can pivot
        to a different angle. Sort key: lexical verdict_id (mirrors
        zero-padded sequence number), oldest → newest. Returns the trailing
        window so the most recent attempt is last.

        Cost is O(verdicts_on_disk). Run-dirs typically hold ≤30 verdicts at
        MVP coverage floors; rescanning per iteration is cheap. If this ever
        becomes hot, cache by seed_id and invalidate on save_verdict.

        Errors in loading any single verdict/attack are tolerated — partial
        history is acceptable; a missing attack file is logged at WARNING.
        """
        verdicts_dir = self.handle.verdicts_dir
        if not verdicts_dir.exists():
            return []
        matched: list[JudgeVerdict] = []
        for path in sorted(verdicts_dir.glob("*.json")):
            try:
                verdict = self.handle.load_verdict(path.stem)
            except Exception:  # noqa: BLE001 — tolerate .tmp residue races
                continue
            try:
                attack = self.handle.load_attack(verdict.attack_id)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "prior-verdicts lookup: verdict %s references missing "
                    "attack %s (%s) — entry skipped",
                    verdict.verdict_id, verdict.attack_id, exc,
                )
                continue
            if attack.mutation_parent != seed_id:
                continue
            matched.append(verdict)
        return matched[-n:] if n > 0 else matched

    def _open_findings_index(self) -> dict[Category, list[str]]:
        """Map each category → list of FAIL attack_ids not yet replayed.

        Reads from disk-persisted verdicts so the index survives restart
        (A4 leverages this). MVP keeps it simple: load all verdicts, filter
        by verdict=fail, group by attack's category.
        """
        result: dict[Category, list[str]] = {}
        verdicts_dir = self.handle.verdicts_dir
        if not verdicts_dir.exists():
            return result
        for verdict_path in sorted(verdicts_dir.glob("*.json")):
            try:
                verdict = self.handle.load_verdict(verdict_path.stem)
            except Exception:  # noqa: BLE001 — tolerate transient read races
                continue
            if verdict.verdict != "fail":
                continue
            try:
                attack = self.handle.load_attack(verdict.attack_id)
            except Exception:  # noqa: BLE001
                continue
            result.setdefault(attack.category, []).append(verdict.attack_id)
        return result

    def _primary_pid_for_seed(self, seed_id: str, category: Category) -> int:
        """Resolve the seed's `primary_patient_id` (sentinel 999100+).

        Cached so a multi-iteration run doesn't re-read the YAML each loop.
        """
        cache_key = f"{category}/{seed_id}"
        cached = self._seed_cache.get(cache_key)
        if cached is None:
            cached = load_seed(
                seed_id, category=category, evals_dir=self.config.evals_dir
            )
            self._seed_cache[cache_key] = cached
        return int(cached["primary_patient_id"])

    def _reconcile_coverage_from_disk(self) -> None:
        """Verify (and rebuild if needed) coverage state from on-disk verdicts.

        Failure mode this defends against (Tate B6 coordination):
        - daemon dies between `save_verdict` and `coverage.record_verdict`
        - verdict file is on disk but coverage.json's per-category counters
          are stale
        - on resume, `select_category` over-attacks the under-counted category
        - `coverage_floor_met` halt fires later than it should

        Strategy: count verdict files per category by joining each verdict
        to its attack JSON. If the sum differs from coverage's reported
        attack_count for any category, replay the missing entries via
        `record_attack` + `record_verdict`. NEVER decrement — if coverage
        claims MORE attacks than verdicts/ contains, leave it alone (likely
        an attack file landed but the run never reached verdict write; the
        operator can manually clear coverage if needed).
        """
        verdicts_dir = self.handle.verdicts_dir
        if not verdicts_dir.exists():
            return

        # Build the disk-derived view: per-category list of (verdict, attack)
        disk_view: dict[str, list[tuple[Any, Any]]] = {}
        for path in sorted(verdicts_dir.glob("*.json")):
            try:
                verdict = self.handle.load_verdict(path.stem)
            except Exception:  # noqa: BLE001 — tolerate transient .tmp residue
                continue
            try:
                attack = self.handle.load_attack(verdict.attack_id)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "coverage reconciliation: verdict %s references missing "
                    "or unreadable attack %s (%s) — skipped",
                    verdict.verdict_id, verdict.attack_id, exc,
                )
                continue
            disk_view.setdefault(attack.category, []).append((verdict, attack))

        # Compare with current coverage and replay any missing entries.
        # `coverage.attack_count` is the load-bearing counter; if disk has
        # more than coverage, we have a desync gap to close.
        state = self.coverage.to_state(session_cost_usd=0.0)
        for category, entries in disk_view.items():
            # Audit R1: guard against unknown categories from disk (e.g.,
            # a verdict file with a typo or a removed-from-MVP category
            # name). Without this guard, a single bad verdict could make
            # the entire run-dir permanently unresumable.
            if category not in state.categories:
                logger.warning(
                    "coverage reconciliation: %d verdict(s) reference "
                    "unknown category %r — skipped (likely typo, "
                    "MVP-category mismatch, or fixture corruption)",
                    len(entries), category,
                )
                continue
            disk_count = len(entries)
            coverage_count = state.categories[category].attack_count
            if disk_count <= coverage_count:
                continue  # already counted, or coverage is ahead (leave alone)
            gap = disk_count - coverage_count
            logger.warning(
                "coverage reconciliation: category %s has %d verdicts on "
                "disk but coverage shows %d attacks — replaying %d entries",
                category, disk_count, coverage_count, gap,
            )
            # Replay the LAST `gap` entries — they're the most recent and
            # therefore the most likely to be the missing tail.
            for verdict, attack in entries[-gap:]:
                self.coverage.record_attack(category=category)
                self.coverage.record_verdict(
                    category=category,
                    verdict=verdict.verdict,
                    session_cost_usd=self.ledger.total_usd,
                )

    def _rehydrate_signal_window_from_disk(self) -> None:
        """Populate the rolling signal window from the run-dir's persisted
        verdicts so a resumed daemon's halt evaluation matches the pre-kill
        state. Reads the LAST K verdicts (by lexical sort order on filename,
        which mirrors the sequence number embedded in verdict IDs).

        Costs are bounded by `config.recent_k` (default 10). Error handling
        is intentionally two-level (audit HIGH):

        - **Verdict parse failures** are silently skipped — `.tmp` residue
          on non-POSIX filesystems where `os.replace` isn't strictly atomic
          is plausibly transient and shouldn't pollute warning logs.
        - **Attack load failures for a successfully-parsed verdict** are
          STRUCTURAL inconsistency (the verdict references an attack_id
          whose file is missing). Emitted as a WARNING so operators see
          it — silently dropping these would under-populate the window
          and could suppress a `signal_to_cost_collapsed` halt.
        """
        verdicts_dir = self.handle.verdicts_dir
        if not verdicts_dir.exists():
            return
        verdict_paths = sorted(verdicts_dir.glob("*.json"))
        if not verdict_paths:
            return
        for path in verdict_paths[-self.config.recent_k :]:
            try:
                verdict = self.handle.load_verdict(path.stem)
            except Exception:  # noqa: BLE001 — tolerate transient verdict-file races
                continue
            try:
                attack = self.handle.load_attack(verdict.attack_id)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "signal_window rehydration: verdict %s references missing "
                    "or unreadable attack %s (%s) — entry dropped; "
                    "signal_to_cost may be under-counted on this resume",
                    verdict.verdict_id,
                    verdict.attack_id,
                    exc,
                )
                continue
            self.signal_window.push(
                category=attack.category,
                verdict=verdict.verdict,
                cost_usd=attack.cost_usd + verdict.cost_usd,
            )

    def _discover_seed_ids(self) -> dict[Category, str | None]:
        """Map each MVP category → seed_id (first yaml file's stem) OR None.

        Prefers `DEFAULT_SEEDS_BY_CATEGORY` when its named seed exists on
        disk (so SID → c7-paraphrased-leakage as expected); falls back to
        the first yaml file alphabetically when the default isn't present
        or isn't defined. Returning None for a category means there is no
        usable seed yet — `select_category` will skip it.

        Resolved ONCE at construction; not re-read mid-run. A daemon
        restart picks up freshly-added Bram seeds.
        """
        result: dict[Category, str | None] = {}
        seed_root = self.config.evals_dir / "seed"
        for cat in (
            "sensitive_information_disclosure",
            "prompt_injection",
            "unbounded_consumption",
        ):
            cat_dir = seed_root / cat
            if not cat_dir.exists():
                result[cat] = None  # type: ignore[index]
                continue
            default_id = DEFAULT_SEEDS_BY_CATEGORY.get(cat)  # type: ignore[arg-type]
            if default_id is not None and (cat_dir / f"{default_id}.yaml").exists():
                result[cat] = default_id  # type: ignore[index]
                continue
            yamls = sorted(cat_dir.glob("*.yaml"))
            result[cat] = yamls[0].stem if yamls else None  # type: ignore[index]
        return result

    def _emit_iteration_line(
        self,
        *,
        iteration: int,
        sel: SelectionResult,
        candidate: AttackCandidate,
        verdict: JudgeVerdict,
        response_status: int,
        response_latency_ms: int,
        doc_vuln_id: str | None,
    ) -> None:
        """Per-iteration callback. A3 wires the stdout formatter here."""
        line = {
            "iteration": iteration,
            "rule": sel.rule,
            "category": candidate.category,
            "attack_id": candidate.attack_id,
            "verdict_id": verdict.verdict_id,
            "verdict": verdict.verdict,
            "confidence": verdict.confidence,
            "human_escalation_required": verdict.human_escalation_required,
            "target_status": response_status,
            "target_latency_ms": response_latency_ms,
            "session_cost_usd": self.ledger.total_usd,
            "vuln_id": doc_vuln_id,
        }
        if self.config.on_iteration is not None:
            self.config.on_iteration(line)
        else:
            logger.info("iteration %d: %s", iteration, line)

    def _finalize(self, reason: HaltReason, iteration: int) -> HaltReport:
        report = HaltReport(
            reason=reason,
            iterations=iteration,
            total_cost_usd=self.ledger.total_usd,
            attacks_attempted=self._attacks_attempted,
            attacks_skipped_refused=self._attacks_skipped_refused,
            target_unavailable_count=self._target_unavailable_count,
            provider_outage_count=self._provider_outage_count,
        )
        logger.info("daemon halted: %s", report)
        return report


__all__ = [
    "AGENT_NAME",
    "AGENT_VERSION",
    "DEFAULT_COVERAGE_FLOOR",
    "DEFAULT_PRIOR_VERDICTS_FOR_MUTATION",
    "DEFAULT_RECENT_K",
    "DEFAULT_SEEDS_BY_CATEGORY",
    "DEFAULT_SIGNAL_FLOOR",
    "DEFAULT_SIGNAL_MOMENTUM_THRESHOLD",
    "HaltDecision",
    "HaltReason",
    "HaltReport",
    "OrchestratorConfig",
    "OrchestratorDaemon",
    "RecentSignalWindow",
    "SelectionResult",
    "evaluate_halt",
    "select_category",
]
