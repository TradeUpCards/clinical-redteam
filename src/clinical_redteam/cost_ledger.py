"""Per-run cost ledger (ARCH §8.1).

Tracks accumulated cost across every LLM call (Red Team, Judge,
Documentation) and every target API call (charged at $0 by the target but
recorded for latency/throughput reasoning). The Orchestrator reads this
to decide when to halt:

- Hard cap (MAX_SESSION_COST_USD) → immediate halt
- Soft cap (50% of hard cap) → reduce Red Team scope (single-turn only,
  fewer mutations) — enforced by Orchestrator at its read site
- Signal-to-cost ratio collapse → halt (computed against coverage.py)

Storage: <run-dir>/cost-ledger.json. Atomic-written via persistence.py's
primitive after every `record()` so the ledger survives crashes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from clinical_redteam.persistence import atomic_write_json

LEDGER_FILENAME = "cost-ledger.json"
LEDGER_SCHEMA_VERSION = 1

CostTier = Literal["red_team", "judge", "documentation", "orchestrator"]
"""Routing tier from openrouter.py + an additional 'orchestrator' bucket
for LLM-augmented orchestration calls (empty bucket for MVP — Orchestrator
is pure rules per ARCH §8.2.4)."""


class CostLedgerError(Exception):
    """Base class for cost ledger errors."""


class CostCapExceededError(CostLedgerError):
    """Recorded cost would push total over the configured cap."""

    def __init__(self, total: float, cap: float) -> None:
        self.total = total
        self.cap = cap
        super().__init__(
            f"Session cost {total:.4f} USD would exceed cap {cap:.4f} USD."
        )


@dataclass
class CostEntry:
    """One recorded LLM call."""

    timestamp: str
    tier: CostTier
    model_used: str
    cost_usd: float
    tokens_input: int
    tokens_output: int
    related_id: str | None  # attack_id / verdict_id / vuln_id when known


@dataclass
class CostLedger:
    """Run-scoped accumulator. One instance per run; serialized to disk
    on every record() call."""

    run_dir: Path
    cost_cap_usd: float
    schema_version: int = LEDGER_SCHEMA_VERSION
    total_usd: float = 0.0
    by_tier_usd: dict[str, float] = field(
        default_factory=lambda: {
            "red_team": 0.0,
            "judge": 0.0,
            "documentation": 0.0,
            "orchestrator": 0.0,
        }
    )
    by_tier_calls: dict[str, int] = field(
        default_factory=lambda: {
            "red_team": 0,
            "judge": 0,
            "documentation": 0,
            "orchestrator": 0,
        }
    )
    entries: list[CostEntry] = field(default_factory=list)

    @property
    def ledger_path(self) -> Path:
        return self.run_dir / LEDGER_FILENAME

    # ---------------------------------------------------------------- create

    @classmethod
    def create(cls, *, run_dir: Path, cost_cap_usd: float) -> CostLedger:
        """Initialize and persist an empty ledger for a new run."""
        ledger = cls(run_dir=run_dir, cost_cap_usd=cost_cap_usd)
        ledger._flush()
        return ledger

    @classmethod
    def load(cls, *, run_dir: Path) -> CostLedger:
        """Reload an existing ledger from disk for resume-after-restart."""
        path = run_dir / LEDGER_FILENAME
        if not path.exists():
            raise CostLedgerError(
                f"No cost ledger at {path}. Call CostLedger.create() first."
            )
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        schema_version = data.get("schema_version")
        if schema_version != LEDGER_SCHEMA_VERSION:
            raise CostLedgerError(
                f"Ledger schema_version {schema_version!r} != expected "
                f"{LEDGER_SCHEMA_VERSION}."
            )
        ledger = cls(
            run_dir=run_dir,
            cost_cap_usd=data["cost_cap_usd"],
            total_usd=data["total_usd"],
            by_tier_usd=data["by_tier_usd"],
            by_tier_calls=data["by_tier_calls"],
            entries=[
                CostEntry(**e) if isinstance(e, dict) else e for e in data["entries"]
            ],
        )
        return ledger

    # ---------------------------------------------------------------- record

    def record(
        self,
        *,
        tier: CostTier,
        model_used: str,
        cost_usd: float,
        tokens_input: int,
        tokens_output: int,
        related_id: str | None = None,
    ) -> None:
        """Record a single LLM call's cost + tokens, persist, return.

        Does NOT raise on cap-exceed by default — the Orchestrator decides
        what to do (halt vs. scope-reduce); call `would_exceed_cap()` or
        `assert_within_cap()` first if you want to gate.
        """
        if cost_usd < 0:
            raise CostLedgerError(f"cost_usd must be non-negative, got {cost_usd!r}")
        if tier not in self.by_tier_usd:
            raise CostLedgerError(
                f"Unknown tier {tier!r}; allowed: {sorted(self.by_tier_usd)}"
            )
        entry = CostEntry(
            timestamp=datetime.now(UTC).isoformat(),
            tier=tier,
            model_used=model_used,
            cost_usd=cost_usd,
            tokens_input=tokens_input,
            tokens_output=tokens_output,
            related_id=related_id,
        )
        self.entries.append(entry)
        self.total_usd += cost_usd
        self.by_tier_usd[tier] += cost_usd
        self.by_tier_calls[tier] += 1
        self._flush()

    # ---------------------------------------------------------------- query

    def would_exceed_cap(self, additional_cost_usd: float) -> bool:
        return (self.total_usd + additional_cost_usd) > self.cost_cap_usd

    def assert_within_cap(self, additional_cost_usd: float = 0.0) -> None:
        """Raise CostCapExceededError if the budget is or would be exceeded."""
        projected = self.total_usd + additional_cost_usd
        if projected > self.cost_cap_usd:
            raise CostCapExceededError(total=projected, cap=self.cost_cap_usd)

    def soft_cap_tripped(self) -> bool:
        """True at 50% of hard cap (ARCH §8.1 — Red Team scope reduction)."""
        return self.total_usd >= (self.cost_cap_usd * 0.5)

    # ---------------------------------------------------------------- persist

    def _flush(self) -> None:
        payload = {
            "schema_version": self.schema_version,
            "cost_cap_usd": self.cost_cap_usd,
            "total_usd": self.total_usd,
            "by_tier_usd": self.by_tier_usd,
            "by_tier_calls": self.by_tier_calls,
            "entries": [
                {
                    "timestamp": e.timestamp,
                    "tier": e.tier,
                    "model_used": e.model_used,
                    "cost_usd": e.cost_usd,
                    "tokens_input": e.tokens_input,
                    "tokens_output": e.tokens_output,
                    "related_id": e.related_id,
                }
                for e in self.entries
            ],
        }
        atomic_write_json(self.ledger_path, payload)


__all__ = [
    "LEDGER_FILENAME",
    "LEDGER_SCHEMA_VERSION",
    "CostCapExceededError",
    "CostEntry",
    "CostLedger",
    "CostLedgerError",
    "CostTier",
]
