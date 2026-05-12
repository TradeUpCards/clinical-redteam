"""Tests for the status app + trend dashboard (Cleo P5 stretch).

Pins:
- _aggregate_trends shape over an empty results dir
- _aggregate_trends shape over a multi-run results dir, including
  chronological ordering by manifest.started_at
- _sum_verdict_counts reads from coverage-state.json's `_categories`
  key (NOT the manifest's never-written `verdict_counts`)
- _run_summary reads total_cost_usd from cost-ledger's `total_usd` key
- SVG helpers escape user-controlled text into title attributes
- The index route returns 200 with all four chart sections when run
  dirs are present, and degrades cleanly to a single empty-state
  message when no runs exist
- /api/runs reflects the corrected field shapes (so external machine
  readers see populated counts + cost rather than perpetual nulls)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from clinical_redteam.web import status_app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _write_run(
    results_dir: Path,
    *,
    run_id: str,
    started_at: str,
    categories: dict[str, dict[str, Any]],
    total_usd: float,
) -> Path:
    """Materialize a fake run dir matching the on-disk shape the daemon writes."""
    d = results_dir / run_id
    (d / "attacks").mkdir(parents=True)
    (d / "verdicts").mkdir()
    (d / "vulnerabilities").mkdir()
    (d / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "run_id": run_id,
                "started_at": started_at,
                "last_updated_at": started_at,
                "target_url": "https://target.example",
                "target_version_sha": None,
                "attack_ids": [],
                "verdict_ids": [],
                "vuln_ids": [],
                "metadata": {},
            }
        )
    )
    (d / "coverage.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target_version_sha": None,
                "cost_cap_usd": 10.0,
                "last_session_cost_usd": total_usd,
                "_categories": categories,
            }
        )
    )
    (d / "cost-ledger.json").write_text(
        json.dumps({"schema_version": 1, "total_usd": total_usd, "calls": []})
    )
    return d


@pytest.fixture
def populated_results(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Three chronological runs with growing coverage + cost."""
    results = tmp_path / "results"
    results.mkdir()
    _write_run(
        results,
        run_id="run-001",
        started_at="2026-05-12T10:00:00+00:00",
        categories={
            "sensitive_information_disclosure": {
                "attack_count": 2,
                "pass": 1,
                "fail": 0,
                "partial": 0,
                "uncertain": 1,
                "last_attack_at": "2026-05-12T10:05:00+00:00",
                "open_findings": 0,
            },
            "prompt_injection": {
                "attack_count": 1,
                "pass": 0,
                "fail": 1,
                "partial": 0,
                "uncertain": 0,
                "last_attack_at": "2026-05-12T10:10:00+00:00",
                "open_findings": 1,
            },
        },
        total_usd=0.05,
    )
    _write_run(
        results,
        run_id="run-002",
        started_at="2026-05-12T11:00:00+00:00",
        categories={
            "sensitive_information_disclosure": {
                "attack_count": 4,
                "pass": 2,
                "fail": 1,
                "partial": 1,
                "uncertain": 0,
                "last_attack_at": "2026-05-12T11:05:00+00:00",
                "open_findings": 1,
            },
            "prompt_injection": {
                "attack_count": 2,
                "pass": 1,
                "fail": 1,
                "partial": 0,
                "uncertain": 0,
                "last_attack_at": "2026-05-12T11:10:00+00:00",
                "open_findings": 1,
            },
        },
        total_usd=0.10,
    )
    _write_run(
        results,
        run_id="run-003",
        started_at="2026-05-12T12:00:00+00:00",
        categories={
            "sensitive_information_disclosure": {
                "attack_count": 6,
                "pass": 4,
                "fail": 1,
                "partial": 1,
                "uncertain": 0,
                "last_attack_at": "2026-05-12T12:05:00+00:00",
                "open_findings": 1,
            },
            "prompt_injection": {
                "attack_count": 3,
                "pass": 2,
                "fail": 1,
                "partial": 0,
                "uncertain": 0,
                "last_attack_at": "2026-05-12T12:10:00+00:00",
                "open_findings": 1,
            },
        },
        total_usd=0.15,
    )
    monkeypatch.setenv("EVALS_DIR", str(tmp_path))
    monkeypatch.setenv("RESULTS_DIR", str(results))
    return results


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def test_aggregate_trends_empty(tmp_path: Path) -> None:
    out = status_app._aggregate_trends([])
    assert out["run_count"] == 0
    assert out["verdict_series"] == []
    assert out["category_series"] == []
    assert out["categories"] == []
    assert out["cost_series"] == []
    assert out["verdict_shift"] is None


def test_aggregate_trends_sorts_chronologically(
    populated_results: Path,
) -> None:
    # Reverse-iterate to make sure aggregation, not file system order,
    # is what produces the chronological series.
    dirs = sorted((populated_results.iterdir()), key=lambda p: p.name, reverse=True)
    trends = status_app._aggregate_trends(dirs)
    assert [r["run_id"] for r in trends["verdict_series"]] == [
        "run-001",
        "run-002",
        "run-003",
    ]
    # Verdict counts pulled from coverage-state._categories — not manifest.
    assert trends["verdict_series"][0]["pass"] == 1
    assert trends["verdict_series"][0]["fail"] == 1
    assert trends["verdict_series"][-1]["pass"] == 6
    assert trends["verdict_series"][-1]["fail"] == 2


def test_aggregate_trends_cumulative_coverage_grows(
    populated_results: Path,
) -> None:
    trends = status_app._aggregate_trends(list(populated_results.iterdir()))
    cum = trends["category_series"]
    # Run 1: 2 SID + 1 PI. Run 2: cumulative 2+4=6 SID, 1+2=3 PI. Run 3: 6+6=12, 3+3=6.
    assert cum[0]["by_cat"]["sensitive_information_disclosure"] == 2
    assert cum[1]["by_cat"]["sensitive_information_disclosure"] == 6
    assert cum[2]["by_cat"]["sensitive_information_disclosure"] == 12
    assert cum[0]["by_cat"]["prompt_injection"] == 1
    assert cum[2]["by_cat"]["prompt_injection"] == 6
    assert "prompt_injection" in trends["categories"]
    assert "sensitive_information_disclosure" in trends["categories"]


def test_aggregate_trends_cost_per_attack(populated_results: Path) -> None:
    trends = status_app._aggregate_trends(list(populated_results.iterdir()))
    cost = trends["cost_series"]
    # run-001: 3 attacks, $0.05 → 0.05/3
    assert cost[0]["total_cost_usd"] == pytest.approx(0.05)
    assert cost[0]["cost_per_attack"] == pytest.approx(0.05 / 3)
    # run-003: 9 attacks, $0.15 → 0.15/9
    assert cost[-1]["cost_per_attack"] == pytest.approx(0.15 / 9)


def test_verdict_shift_falls_back_for_small_n(populated_results: Path) -> None:
    # 3 runs → window 1-vs-rest, not 3-vs-3.
    trends = status_app._aggregate_trends(list(populated_results.iterdir()))
    vs = trends["verdict_shift"]
    assert vs is not None
    assert vs["recent_runs"] == 1
    assert vs["prior_runs"] == 2


def test_verdict_shift_returns_none_for_single_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    results = tmp_path / "results"
    results.mkdir()
    _write_run(
        results,
        run_id="solo",
        started_at="2026-05-12T10:00:00+00:00",
        categories={
            "sensitive_information_disclosure": {
                "attack_count": 1,
                "pass": 1,
                "fail": 0,
                "partial": 0,
                "uncertain": 0,
                "last_attack_at": "2026-05-12T10:05:00+00:00",
                "open_findings": 0,
            },
        },
        total_usd=0.01,
    )
    trends = status_app._aggregate_trends(list(results.iterdir()))
    assert trends["verdict_shift"] is None


# ---------------------------------------------------------------------------
# Field-shape regression — these are the bugs we caught on tate-attacker-deploy
# ---------------------------------------------------------------------------


def test_run_summary_reads_cost_from_total_usd(
    populated_results: Path,
) -> None:
    summary = status_app._run_summary(populated_results / "run-002")
    # cost-ledger.json's actual key is `total_usd`, NOT `total_cost_usd`.
    assert summary["total_cost_usd"] == pytest.approx(0.10)


def test_run_summary_derives_verdict_counts_from_coverage(
    populated_results: Path,
) -> None:
    summary = status_app._run_summary(populated_results / "run-003")
    # Manifest does not carry verdict_counts; coverage-state._categories does.
    assert summary["verdict_counts"] == {
        "pass": 6,
        "fail": 2,
        "partial": 1,
        "uncertain": 0,
    }


def test_sum_verdict_counts_reads_flat_keys() -> None:
    """Production shape: pass/fail/partial/uncertain are siblings of
    attack_count inside each `_categories[cat]` dict (see
    CoverageTracker.__post_init__ + _flush in coverage.py)."""
    coverage = {
        "_categories": {
            "sid": {
                "attack_count": 5,
                "pass": 3,
                "fail": 1,
                "partial": 1,
                "uncertain": 0,
                "last_attack_at": "2026-05-12T10:00:00+00:00",
                "open_findings": 1,
            },
            "pi": {
                "attack_count": 2,
                "pass": 0,
                "fail": 2,
                "partial": 0,
                "uncertain": 0,
                "last_attack_at": "2026-05-12T10:30:00+00:00",
                "open_findings": 2,
            },
        }
    }
    assert status_app._sum_verdict_counts(coverage) == {
        "pass": 3,
        "fail": 3,
        "partial": 1,
        "uncertain": 0,
    }


def test_sum_verdict_counts_falls_back_to_nested_verdicts_subdict() -> None:
    """Forward-compat shape: a future writer could normalize to the
    Pydantic CategoryCoverage shape where verdicts live in a sub-dict."""
    coverage = {
        "_categories": {
            "sid": {
                "attack_count": 5,
                "verdicts": {"pass": 3, "fail": 1, "partial": 1, "uncertain": 0},
            },
        }
    }
    assert status_app._sum_verdict_counts(coverage) == {
        "pass": 3,
        "fail": 1,
        "partial": 1,
        "uncertain": 0,
    }


def test_sum_verdict_counts_robust_to_missing_and_malformed() -> None:
    assert status_app._sum_verdict_counts({}) == {
        "pass": 0,
        "fail": 0,
        "partial": 0,
        "uncertain": 0,
    }
    assert status_app._sum_verdict_counts({"_categories": {"x": None}}) == {
        "pass": 0,
        "fail": 0,
        "partial": 0,
        "uncertain": 0,
    }
    bad = {"_categories": {"x": {"pass": "not-a-number", "fail": None}}}
    out = status_app._sum_verdict_counts(bad)
    assert out["pass"] == 0
    assert out["fail"] == 0


def test_coverage_categories_handles_legacy_by_category_key() -> None:
    # If a future writer ever uses by_category instead of _categories
    # (or vice versa), the dashboard should keep working.
    legacy = {"by_category": {"x": {"attack_count": 7, "verdicts": {}}}}
    assert status_app._coverage_categories(legacy) == {
        "x": {"attack_count": 7, "verdicts": {}}
    }
    current = {"_categories": {"y": {"attack_count": 3, "verdicts": {}}}}
    assert status_app._coverage_categories(current) == {
        "y": {"attack_count": 3, "verdicts": {}}
    }
    # _categories wins when both are present.
    both = {
        "_categories": {"a": {"attack_count": 1, "verdicts": {}}},
        "by_category": {"b": {"attack_count": 9, "verdicts": {}}},
    }
    assert "a" in status_app._coverage_categories(both)
    assert "b" not in status_app._coverage_categories(both)


# ---------------------------------------------------------------------------
# SVG helpers
# ---------------------------------------------------------------------------


def test_svg_helpers_return_empty_on_empty_series() -> None:
    assert status_app._svg_verdict_stacked_bars([]) == ""
    assert (
        status_app._svg_multiline([], categories=[], value_key="by_cat", title_text="x")
        == ""
    )
    assert status_app._svg_cost_lines([]) == ""


def test_svg_verdict_bars_includes_legend_and_run_titles() -> None:
    series = [
        {
            "run_id": "run-A",
            "started_at": "2026-05-12T10:00:00+00:00",
            "pass": 3,
            "fail": 1,
            "partial": 0,
            "uncertain": 2,
        }
    ]
    svg = status_app._svg_verdict_stacked_bars(series)
    assert svg.startswith("<svg")
    assert svg.endswith("</svg>")
    assert "run-A" in svg
    assert "pass 3" in svg
    assert "fail 1" in svg
    # Legend entries
    for label in ("pass", "partial", "uncertain", "fail"):
        assert f">{label}<" in svg


def test_svg_escapes_html_in_run_id() -> None:
    # A malicious run dir name shouldn't be able to inject markup.
    series = [
        {
            "run_id": "<script>alert(1)</script>",
            "started_at": "",
            "pass": 1,
            "fail": 0,
            "partial": 0,
            "uncertain": 0,
        }
    ]
    svg = status_app._svg_verdict_stacked_bars(series)
    assert "<script>" not in svg
    assert "&lt;script&gt;" in svg


# ---------------------------------------------------------------------------
# End-to-end index route
# ---------------------------------------------------------------------------


def test_index_renders_all_chart_sections(populated_results: Path) -> None:
    app = status_app.create_app()
    body = app.test_client().get("/").get_data(as_text=True)
    for needle in (
        "Resilience shift",
        "Verdict counts per run",
        "Cumulative attack coverage",
        "Cost trend",
        "<svg",
    ):
        assert needle in body, f"missing section: {needle}"


def test_index_corrected_verdict_cell_populated(populated_results: Path) -> None:
    """Regression: the existing table used to always show — for verdicts
    + cost because _run_summary was reading from never-written keys."""
    body = (
        status_app.create_app()
        .test_client()
        .get("/")
        .get_data(as_text=True)
    )
    # run-001 verdict total: pass=1, partial=0, uncertain=1, fail=1 → row visible
    assert "verdict-cell" in body
    # Cost cells should now show $-prefixed numbers for at least one row.
    assert body.count("$0.05") >= 1


def test_index_empty_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    results = tmp_path / "results"
    results.mkdir()
    monkeypatch.setenv("EVALS_DIR", str(tmp_path))
    monkeypatch.setenv("RESULTS_DIR", str(results))
    body = (
        status_app.create_app()
        .test_client()
        .get("/")
        .get_data(as_text=True)
    )
    # No SVG when there's no data, but the page still renders.
    assert "<svg" not in body
    assert "No runs yet" in body


def test_api_runs_carries_corrected_fields(populated_results: Path) -> None:
    body = status_app.create_app().test_client().get("/api/runs").get_json()
    assert len(body) == 3
    for entry in body:
        # Counts populated (sum of pass/fail/partial/uncertain > 0).
        v = entry["verdict_counts"]
        assert v is not None
        assert sum(v.values()) > 0
        assert entry["total_cost_usd"] is not None
