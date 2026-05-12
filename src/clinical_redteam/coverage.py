"""Per-category coverage tracker (ARCH §3.6.1 + §12.3).

Maintains the CoverageState the Orchestrator reads at every iteration to
decide which category to attack next. Coverage state is the substrate for
the platform's halt conditions:

- attacks_count_at_floor    → all categories have reached a minimum attempt
                              count; Orchestrator can halt if no new signal
- per-category verdict mix  → drives mutation depth + scope decisions
- open_findings             → FAIL verdicts not yet resolved (drive Documentation
                              Agent backlog awareness, ARCH §10.2)

Storage: <run-dir>/coverage.json. Atomic-written via persistence.py.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from clinical_redteam.persistence import atomic_write_json
from clinical_redteam.schemas import (
    CategoryCoverage,
    CoverageState,
    Verdict,
    VerdictCounts,
)

COVERAGE_FILENAME = "coverage.json"
COVERAGE_SCHEMA_VERSION = 1

# MVP categories (ARCH §9.4). New categories require schema-version bump.
_MVP_CATEGORIES: tuple[str, ...] = (
    "sensitive_information_disclosure",
    "prompt_injection",
    "unbounded_consumption",
)


class CoverageError(Exception):
    """Base class for coverage tracker errors."""


@dataclass
class CoverageTracker:
    """Run-scoped coverage accumulator. Mirrors CoverageState schema but
    persists between iterations and exposes mutation helpers."""

    run_dir: Path
    target_version_sha: str
    cost_cap_usd: float
    schema_version: int = COVERAGE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not hasattr(self, "_categories"):
            self._categories: dict[str, dict[str, int | str | None]] = {
                cat: {
                    "attack_count": 0,
                    "pass": 0,
                    "fail": 0,
                    "partial": 0,
                    "uncertain": 0,
                    "last_attack_at": None,
                    "open_findings": 0,
                }
                for cat in _MVP_CATEGORIES
            }

    @property
    def coverage_path(self) -> Path:
        return self.run_dir / COVERAGE_FILENAME

    # ---------------------------------------------------------------- create

    @classmethod
    def create(
        cls, *, run_dir: Path, target_version_sha: str, cost_cap_usd: float
    ) -> CoverageTracker:
        tracker = cls(
            run_dir=run_dir,
            target_version_sha=target_version_sha,
            cost_cap_usd=cost_cap_usd,
        )
        tracker._flush(session_cost_usd=0.0)
        return tracker

    @classmethod
    def load(cls, *, run_dir: Path) -> CoverageTracker:
        path = run_dir / COVERAGE_FILENAME
        if not path.exists():
            raise CoverageError(
                f"No coverage state at {path}. Call CoverageTracker.create() first."
            )
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if data.get("schema_version") != COVERAGE_SCHEMA_VERSION:
            raise CoverageError(
                f"Coverage schema_version {data.get('schema_version')!r} != "
                f"{COVERAGE_SCHEMA_VERSION}"
            )
        tracker = cls(
            run_dir=run_dir,
            target_version_sha=data["target_version_sha"],
            cost_cap_usd=data["cost_cap_usd"],
        )
        tracker._categories = data["_categories"]
        return tracker

    # ---------------------------------------------------------------- mutate

    def record_attack(self, *, category: str, attacked_at: str | None = None) -> None:
        """Bump the attack count for a category and stamp last_attack_at."""
        self._require_known_category(category)
        cat = self._categories[category]
        cat["attack_count"] = int(cat["attack_count"]) + 1  # type: ignore[arg-type]
        cat["last_attack_at"] = attacked_at or datetime.now(UTC).isoformat()
        self._persist_only(session_cost_usd=None)

    def record_verdict(
        self,
        *,
        category: str,
        verdict: Verdict,
        session_cost_usd: float,
    ) -> None:
        """Record a Judge verdict against a category.

        FAIL verdicts increment `open_findings` — decrement comes from
        Documentation Agent when the report is filed + remediated. For
        MVP, open_findings == fail_count; the gap appears in Phase 2 once
        fix-validation flows close findings.
        """
        self._require_known_category(category)
        cat = self._categories[category]
        cat[verdict] = int(cat[verdict]) + 1  # type: ignore[arg-type]
        if verdict == "fail":
            cat["open_findings"] = int(cat["open_findings"]) + 1  # type: ignore[arg-type]
        self._persist_only(session_cost_usd=session_cost_usd)

    # ---------------------------------------------------------------- query

    def to_state(self, *, session_cost_usd: float) -> CoverageState:
        """Materialize the current coverage as a validated CoverageState
        Pydantic model (ARCH §12.3)."""
        return CoverageState(
            as_of=datetime.now(UTC),
            target_version_sha=self.target_version_sha,
            categories={
                cat: CategoryCoverage(
                    attack_count=int(data["attack_count"]),  # type: ignore[arg-type]
                    verdicts=VerdictCounts.model_validate(
                        {
                            "pass": data["pass"],
                            "fail": data["fail"],
                            "partial": data["partial"],
                            "uncertain": data["uncertain"],
                        }
                    ),
                    last_attack_at=data["last_attack_at"],  # type: ignore[arg-type]
                    open_findings=int(data["open_findings"]),  # type: ignore[arg-type]
                )
                for cat, data in self._categories.items()
            },
            session_cost_usd=session_cost_usd,
            cost_cap_usd=self.cost_cap_usd,
            signal_to_cost_ratio=self.signal_to_cost_ratio(session_cost_usd),
        )

    def signal_to_cost_ratio(self, session_cost_usd: float) -> float:
        """open_findings / session_cost_usd, clamped at 0 when cost is zero."""
        if session_cost_usd <= 0:
            return 0.0
        total_open = sum(
            int(c["open_findings"]) for c in self._categories.values()  # type: ignore[arg-type]
        )
        return total_open / session_cost_usd

    def least_covered_category(self) -> str:
        """Return the category with the lowest attack_count.

        Ties broken by MVP-declared order (deterministic). The Orchestrator
        uses this for default routing when no other priority signal applies.
        """
        return min(
            _MVP_CATEGORIES,
            key=lambda cat: int(self._categories[cat]["attack_count"]),  # type: ignore[arg-type]
        )

    # ---------------------------------------------------------------- persist

    def _persist_only(self, *, session_cost_usd: float | None) -> None:
        """Internal: flush without changing session_cost (used by record_attack
        before a verdict + cost are known)."""
        self._flush(session_cost_usd=session_cost_usd or 0.0)

    def _flush(self, *, session_cost_usd: float) -> None:
        payload = {
            "schema_version": self.schema_version,
            "target_version_sha": self.target_version_sha,
            "cost_cap_usd": self.cost_cap_usd,
            "last_session_cost_usd": session_cost_usd,
            "_categories": self._categories,
        }
        atomic_write_json(self.coverage_path, payload)

    def _require_known_category(self, category: str) -> None:
        if category not in self._categories:
            raise CoverageError(
                f"Unknown category {category!r}. MVP categories: "
                f"{sorted(self._categories)}. Adding a new category requires "
                "schema-version bump in coverage.py + ARCH §9.4 update."
            )


__all__ = [
    "COVERAGE_FILENAME",
    "COVERAGE_SCHEMA_VERSION",
    "CoverageError",
    "CoverageTracker",
]
