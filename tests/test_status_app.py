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


# ---------------------------------------------------------------------------
# Vuln-header parser (YAML frontmatter + legacy markdown fallback)
# ---------------------------------------------------------------------------


def _write_vuln(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


def test_parse_vuln_header_yaml_frontmatter(tmp_path: Path) -> None:
    """ARCH §12.4 canonical: YAML frontmatter between --- markers."""
    p = _write_vuln(
        tmp_path / "VULN-002-DRAFT.md",
        """---
vuln_id: VULN-002
title: Prompt Injection via indirect via extraction field poisoning
severity: high
status: draft-pending-review
discovered_at: 2026-05-14T03:21:00+00:00
discovered_by_attack_id: atk_2026-05-14_001
target_version_sha: abc123
---

# Body — Description, Reproduction, etc.

Some content here.
""",
    )
    meta = status_app._parse_vuln_header(p)
    assert meta["vuln_id"] == "VULN-002"
    assert meta["severity"] == "high"
    assert meta["status"] == "draft-pending-review"
    assert "Prompt Injection" in meta["title"]
    assert meta["discovered_at"].startswith("2026-05-14")


def test_parse_vuln_header_legacy_markdown_fallback(tmp_path: Path) -> None:
    """Older hand-written reports use **Severity:** / **Status:** lines."""
    p = _write_vuln(
        tmp_path / "VULN-LEGACY-001.md",
        """# Legacy Vulnerability Title

**Severity:** HIGH
**Status:** filed

Body content.
""",
    )
    meta = status_app._parse_vuln_header(p)
    assert meta["title"] == "Legacy Vulnerability Title"
    assert meta["severity"] == "HIGH"
    assert meta["status"] == "filed"
    # No frontmatter → no vuln_id from header (filename fallback in caller).
    assert meta["vuln_id"] is None


def test_parse_vuln_header_malformed_yaml_does_not_raise(tmp_path: Path) -> None:
    """A bad YAML block must not blow up the request — caller wants
    best-effort fields."""
    p = _write_vuln(
        tmp_path / "VULN-003-DRAFT.md",
        """---
this: is: not: valid yaml because too many colons
   - and a broken list
---

# Fallback body title

**Severity:** medium
""",
    )
    meta = status_app._parse_vuln_header(p)
    # Frontmatter ignored, but fallback grabs the body H1 + Severity.
    assert meta["title"] == "Fallback body title"
    assert meta["severity"] == "medium"


def test_vuln_id_from_filename_handles_withdrawn() -> None:
    assert (
        status_app._vuln_id_from_filename("VULN-002-DRAFT")
        == "VULN-002"
    )
    assert (
        status_app._vuln_id_from_filename(
            "VULN-WITHDRAWN-001-pre-F25-judge-confabulation"
        )
        == "VULN-WITHDRAWN-001"
    )
    assert (
        status_app._vuln_id_from_filename(
            "VULN-001-c7-cross-patient-paraphrased-leakage"
        )
        == "VULN-001"
    )
    assert status_app._vuln_id_from_filename("garbage") is None


def test_list_vulnerabilities_surfaces_vuln_id_and_withdrawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Three drafts with identical titles still distinguish via vuln_id;
    WITHDRAWN entries surface a `withdrawn=True` flag."""
    vulns_dir = tmp_path / "vulnerabilities"
    vulns_dir.mkdir()
    same_title_yaml = (
        "---\n"
        "vuln_id: {vid}\n"
        "title: Prompt Injection via indirect via extraction (high)\n"
        "severity: high\n"
        "status: draft-pending-review\n"
        "discovered_at: 2026-05-14T03:21:00+00:00\n"
        "discovered_by_attack_id: atk_2026-05-14_001\n"
        "target_version_sha: abc123\n"
        "---\n\n# Body\n"
    )
    _write_vuln(vulns_dir / "VULN-002-DRAFT.md", same_title_yaml.format(vid="VULN-002"))
    _write_vuln(vulns_dir / "VULN-003-DRAFT.md", same_title_yaml.format(vid="VULN-003"))
    _write_vuln(
        vulns_dir / "VULN-WITHDRAWN-001-bad-judge.md",
        same_title_yaml.format(vid="VULN-WITHDRAWN-001"),
    )
    monkeypatch.setenv("EVALS_DIR", str(tmp_path))
    vulns = status_app._list_vulnerabilities()
    assert len(vulns) == 3
    by_vid = {v["vuln_id"]: v for v in vulns}
    assert set(by_vid) == {"VULN-002", "VULN-003", "VULN-WITHDRAWN-001"}
    assert by_vid["VULN-WITHDRAWN-001"]["withdrawn"] is True
    assert by_vid["VULN-002"]["withdrawn"] is False
    for v in vulns:
        assert v["severity"] == "high"
        assert v["status"] == "draft-pending-review"
        assert v["last_replay"] is None  # no replay_index passed


# ---------------------------------------------------------------------------
# Regression-replay aggregation
# ---------------------------------------------------------------------------


def _write_replay_artifacts(
    run_dir: Path,
    *,
    attack_id: str,
    verdict_id: str,
    category: str,
    case_id: str,
    verdict: str,
) -> None:
    """Materialize a regression_replay/{attacks,verdicts}/ pair."""
    attacks = run_dir / "regression_replay" / "attacks"
    verdicts = run_dir / "regression_replay" / "verdicts"
    attacks.mkdir(parents=True)
    verdicts.mkdir(parents=True)
    (attacks / f"{attack_id}.json").write_text(
        json.dumps(
            {
                "attack_id": attack_id,
                "category": category,
                "subcategory": "regression_replay",
                "generated_by": f"regression_replay::{case_id}",
                "payload": {"type": "single_turn", "content": "x"},
                "target_endpoint": "/chat",
            }
        )
    )
    (verdicts / f"{verdict_id}.json").write_text(
        json.dumps(
            {
                "verdict_id": verdict_id,
                "attack_id": attack_id,
                "verdict": verdict,
                "confidence": 0.9,
                "evidence": [],
            }
        )
    )


def test_aggregate_regression_replays_empty(tmp_path: Path) -> None:
    """No regression_replay/ dirs → empty snapshot, no errors."""
    snapshot = status_app._aggregate_regression_replays([tmp_path])
    assert snapshot == {}


def test_aggregate_regression_replays_joins_via_case_yaml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Hand-authored regression YAML: parent_vuln_id resolved + replay surfaced."""
    # Set up regression case YAML with parent_vuln_id.
    reg_dir = tmp_path / "regression" / "sensitive_information_disclosure"
    reg_dir.mkdir(parents=True)
    (reg_dir / "REGR-001.yaml").write_text(
        "case_id: REGR-001\n"
        "parent_vuln_id: VULN-001\n"
        "category: sensitive_information_disclosure\n"
    )
    # Set up a run dir with a passing replay verdict.
    run = tmp_path / "results" / "run-A"
    run.mkdir(parents=True)
    (run / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "run_id": "run-A",
                "started_at": "2026-05-14T10:00:00+00:00",
                "last_updated_at": "2026-05-14T10:30:00+00:00",
                "target_url": "https://target.example",
                "target_version_sha": "abc123def456",
                "target_fingerprint": "fp_xyz_789012345678",
                "metadata": {},
            }
        )
    )
    _write_replay_artifacts(
        run,
        attack_id="atk_2026-05-14_900",
        verdict_id="ver_2026-05-14_900",
        category="sensitive_information_disclosure",
        case_id="REGR-001",
        verdict="pass",
    )
    monkeypatch.setenv("EVALS_DIR", str(tmp_path))
    snapshot = status_app._aggregate_regression_replays([run])
    assert "VULN-001" in snapshot
    entry = snapshot["VULN-001"]
    assert entry["last_verdict"] == "pass"
    assert entry["case_id"] == "REGR-001"
    assert entry["target_version_sha"] == "abc123def456"
    assert entry["target_fingerprint"] == "fp_xyz_789012345678"
    assert entry["replay_count"] == 1
    assert entry["run_id"] == "run-A"


def test_aggregate_regression_replays_joins_via_f17_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F17 auto-promoted JSON: `promoted_from_vuln_id` field resolved."""
    reg_dir = tmp_path / "regression" / "prompt_injection"
    reg_dir.mkdir(parents=True)
    (reg_dir / "atk_2026-05-14_001.json").write_text(
        json.dumps(
            {
                "regression_entry_version": "1",
                "promoted_from_vuln_id": "VULN-002",
                "source_attack_id": "atk_2026-05-14_001",
                "category": "prompt_injection",
            }
        )
    )
    run = tmp_path / "results" / "run-B"
    run.mkdir(parents=True)
    (run / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "run_id": "run-B",
                "last_updated_at": "2026-05-14T11:00:00+00:00",
                "target_url": "https://t.example",
                "target_version_sha": "deadbeef",
                "metadata": {},
            }
        )
    )
    _write_replay_artifacts(
        run,
        attack_id="atk_2026-05-14_950",
        verdict_id="ver_2026-05-14_950",
        category="prompt_injection",
        case_id="atk_2026-05-14_001",  # the case_id is the source attack_id
        verdict="fail",
    )
    monkeypatch.setenv("EVALS_DIR", str(tmp_path))
    snapshot = status_app._aggregate_regression_replays([run])
    assert snapshot["VULN-002"]["last_verdict"] == "fail"
    assert snapshot["VULN-002"]["case_id"] == "atk_2026-05-14_001"


def test_aggregate_regression_replays_picks_newest_across_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Multiple replays of the same VULN → latest verdict wins, count totals."""
    reg_dir = tmp_path / "regression" / "sensitive_information_disclosure"
    reg_dir.mkdir(parents=True)
    (reg_dir / "REGR-001.yaml").write_text(
        "parent_vuln_id: VULN-001\ncategory: sensitive_information_disclosure\n"
    )
    runs = []
    for run_id, ts, verdict in [
        ("run-old", "2026-05-12T10:00:00+00:00", "fail"),
        ("run-mid", "2026-05-13T10:00:00+00:00", "partial"),
        ("run-new", "2026-05-14T10:00:00+00:00", "pass"),
    ]:
        run = tmp_path / "results" / run_id
        run.mkdir(parents=True)
        (run / "manifest.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "run_id": run_id,
                    "last_updated_at": ts,
                    "target_url": "https://t",
                    "target_version_sha": f"sha-{run_id}",
                    "metadata": {},
                }
            )
        )
        _write_replay_artifacts(
            run,
            attack_id=f"atk_{run_id}_001",
            verdict_id=f"ver_{run_id}_001",
            category="sensitive_information_disclosure",
            case_id="REGR-001",
            verdict=verdict,
        )
        runs.append(run)
    monkeypatch.setenv("EVALS_DIR", str(tmp_path))
    # Iterate newest-first (the production call order):
    snapshot = status_app._aggregate_regression_replays(list(reversed(runs)))
    entry = snapshot["VULN-001"]
    assert entry["last_verdict"] == "pass"
    assert entry["run_id"] == "run-new"
    assert entry["target_version_sha"] == "sha-run-new"
    assert entry["replay_count"] == 3


def test_aggregate_regression_replays_orphan_verdict_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A replay verdict whose case_id has no matching regression entry
    (e.g., case file deleted, case file in a deprecated category) is
    skipped — not surfaced under a phantom vuln_id."""
    run = tmp_path / "results" / "run-orphan"
    run.mkdir(parents=True)
    (run / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "run_id": "run-orphan",
                "last_updated_at": "2026-05-14T12:00:00+00:00",
                "target_url": "https://t",
                "metadata": {},
            }
        )
    )
    _write_replay_artifacts(
        run,
        attack_id="atk_orphan_001",
        verdict_id="ver_orphan_001",
        category="sensitive_information_disclosure",
        case_id="REGR-DOES-NOT-EXIST",
        verdict="pass",
    )
    monkeypatch.setenv("EVALS_DIR", str(tmp_path))
    # No regression dir at all → orphan with no parent_vuln_id → skipped.
    snapshot = status_app._aggregate_regression_replays([run])
    assert snapshot == {}


def test_list_vulnerabilities_withdrawn_does_not_collide_with_active(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When a WITHDRAWN file preserves its original frontmatter
    `vuln_id: VULN-001` as historical record AND a fresh active
    VULN-001 exists, the dashboard must not surface two entries
    claiming the same vuln_id. Withdrawn entries should report the
    filename-derived `VULN-WITHDRAWN-NNN` so machine readers can
    differentiate.

    Reproduces the observed live-deploy collision: VULN-WITHDRAWN-001-pre-F25-...
    carries `vuln_id: VULN-001` in its frontmatter (since it IS the
    original-but-reclassified VULN-001), colliding with the fresh
    C-7 VULN-001 in `/api/vulnerabilities` output.
    """
    vulns_dir = tmp_path / "vulnerabilities"
    vulns_dir.mkdir()
    # Fresh active VULN-001 (post-withdrawal re-allocation).
    _write_vuln(
        vulns_dir / "VULN-001-c7-cross-patient.md",
        "---\n"
        "vuln_id: VULN-001\n"
        "title: C-7 Cross-Patient PHI Leakage\n"
        "severity: high\n"
        "status: filed\n"
        "discovered_at: 2026-05-12T00:00:00+00:00\n"
        "discovered_by_attack_id: atk_2026-05-12_001\n"
        "target_version_sha: x\n---\n# Body\n",
    )
    # Withdrawn file whose frontmatter still says VULN-001 (historical).
    _write_vuln(
        vulns_dir / "VULN-WITHDRAWN-001-pre-F25-judge-confabulation.md",
        "---\n"
        "vuln_id: VULN-001\n"  # original id preserved as historical record
        "title: Pre-F25 judge confabulation (withdrawn)\n"
        "severity: high\n"
        "status: draft-pending-review\n"
        "discovered_at: 2026-05-14T05:50:00+00:00\n"
        "discovered_by_attack_id: atk_2026-05-14_001\n"
        "target_version_sha: x\n---\n# Body\n",
    )
    monkeypatch.setenv("EVALS_DIR", str(tmp_path))
    vulns = status_app._list_vulnerabilities()
    by_id = {v["vuln_id"]: v for v in vulns}
    # No collision — two distinct vuln_ids surface.
    assert set(by_id) == {"VULN-001", "VULN-WITHDRAWN-001"}
    assert by_id["VULN-001"]["withdrawn"] is False
    assert by_id["VULN-WITHDRAWN-001"]["withdrawn"] is True
    # Active entry kept its frontmatter title; withdrawn kept its own
    # frontmatter title (just gets a different vuln_id surfaced).
    assert "C-7" in by_id["VULN-001"]["title"]
    assert "Pre-F25" in by_id["VULN-WITHDRAWN-001"]["title"]


def test_lookup_parent_vuln_id_rejects_path_traversal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Defense-in-depth: a case_id with `..` segments must not escape
    the regression dir, even if a planted file outside would resolve."""
    # Plant a file outside `evals/regression/` that would be a "valid"
    # vuln record if the lookup followed the traversal.
    outside = tmp_path / "outside_secret.yaml"
    outside.write_text("parent_vuln_id: VULN-666\n")
    # Also plant a real entry so we can confirm the sanitizer doesn't
    # break normal lookups.
    reg_dir = tmp_path / "regression" / "prompt_injection"
    reg_dir.mkdir(parents=True)
    (reg_dir / "REGR-OK.yaml").write_text(
        "parent_vuln_id: VULN-007\ncategory: prompt_injection\n"
    )
    monkeypatch.setenv("EVALS_DIR", str(tmp_path))
    # Traversal attempt: must not resolve to outside_secret.yaml.
    assert status_app._lookup_parent_vuln_id("../../outside_secret", None) is None
    assert (
        status_app._lookup_parent_vuln_id("../../outside_secret", "prompt_injection")
        is None
    )
    # Slash injection blocked.
    assert status_app._lookup_parent_vuln_id("foo/bar", None) is None
    # Hostile category blocked too (sanitizer falls back to None-category
    # globbing the safe case_id only).
    assert (
        status_app._lookup_parent_vuln_id("REGR-OK", "../../etc")
        == "VULN-007"
    )
    # Real lookup still works.
    assert (
        status_app._lookup_parent_vuln_id("REGR-OK", "prompt_injection")
        == "VULN-007"
    )


def test_aggregate_regression_replays_malformed_files_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bad JSON in attack/verdict files → skip the entry, don't crash."""
    run = tmp_path / "results" / "run-bad"
    run.mkdir(parents=True)
    (run / "manifest.json").write_text(
        json.dumps({"schema_version": 1, "metadata": {}})
    )
    attacks = run / "regression_replay" / "attacks"
    verdicts = run / "regression_replay" / "verdicts"
    attacks.mkdir(parents=True)
    verdicts.mkdir(parents=True)
    (attacks / "broken.json").write_text("{not valid json")
    (verdicts / "broken.json").write_text("also not valid")
    monkeypatch.setenv("EVALS_DIR", str(tmp_path))
    snapshot = status_app._aggregate_regression_replays([run])
    assert snapshot == {}


# ---------------------------------------------------------------------------
# End-to-end: dashboard renders vuln list with replay tie-back
# ---------------------------------------------------------------------------


def test_index_surfaces_vuln_id_and_replay_tieback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Full path: write a VULN draft + a regression case + a replay verdict;
    the HTML index renders the vuln id, severity badge, and the
    'Last regression replay' cell with the verdict + target fingerprint."""
    # Vuln draft.
    vulns_dir = tmp_path / "vulnerabilities"
    vulns_dir.mkdir()
    (vulns_dir / "VULN-001-c7.md").write_text(
        "---\n"
        "vuln_id: VULN-001\n"
        "title: C-7 paraphrased leakage (high)\n"
        "severity: high\n"
        "status: draft-pending-review\n"
        "discovered_at: 2026-05-12T03:21:00+00:00\n"
        "discovered_by_attack_id: atk_2026-05-12_001\n"
        "target_version_sha: original\n"
        "---\n\n# Body\n"
    )
    # Regression case YAML.
    reg_dir = tmp_path / "regression" / "sensitive_information_disclosure"
    reg_dir.mkdir(parents=True)
    (reg_dir / "REGR-001.yaml").write_text(
        "case_id: REGR-001\n"
        "parent_vuln_id: VULN-001\n"
        "category: sensitive_information_disclosure\n"
    )
    # Run dir with passing replay verdict.
    results = tmp_path / "results"
    results.mkdir()
    _write_run(
        results,
        run_id="run-after-fix",
        started_at="2026-05-14T10:00:00+00:00",
        categories={},
        total_usd=0.10,
    )
    run = results / "run-after-fix"
    # Overwrite manifest to add fingerprint.
    (run / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "run_id": "run-after-fix",
                "started_at": "2026-05-14T10:00:00+00:00",
                "last_updated_at": "2026-05-14T10:30:00+00:00",
                "target_url": "https://target.example",
                "target_version_sha": "fixed1234abcd",
                "target_fingerprint": "fp_after_fix_xyzwabcd",
                "metadata": {},
            }
        )
    )
    _write_replay_artifacts(
        run,
        attack_id="atk_2026-05-14_900",
        verdict_id="ver_2026-05-14_900",
        category="sensitive_information_disclosure",
        case_id="REGR-001",
        verdict="pass",
    )
    monkeypatch.setenv("EVALS_DIR", str(tmp_path))
    monkeypatch.setenv("RESULTS_DIR", str(results))
    body = status_app.create_app().test_client().get("/").get_data(as_text=True)
    # vuln_id rendered prominently in the table.
    assert "VULN-001" in body
    # severity badge present (not "—").
    assert "badge-high" in body
    # last_replay column has the PASS verdict text.
    assert "verdict-pass" in body
    # target fingerprint cell visible (truncated to first 12 chars).
    assert "fp_after_fix" in body or "fixed1234abc" in body


def test_api_vulnerabilities_includes_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """JSON endpoint exposes the enriched per-vuln structure including
    last_replay for machine readers."""
    vulns_dir = tmp_path / "vulnerabilities"
    vulns_dir.mkdir()
    (vulns_dir / "VULN-001.md").write_text(
        "---\nvuln_id: VULN-001\ntitle: t\nseverity: high\nstatus: filed\n"
        "discovered_at: 2026-05-12T00:00:00+00:00\n"
        "discovered_by_attack_id: atk_2026-05-12_001\ntarget_version_sha: x\n---\n# B\n"
    )
    reg_dir = tmp_path / "regression" / "sensitive_information_disclosure"
    reg_dir.mkdir(parents=True)
    (reg_dir / "REGR-001.yaml").write_text(
        "parent_vuln_id: VULN-001\ncategory: sensitive_information_disclosure\n"
    )
    results = tmp_path / "results"
    results.mkdir()
    run = results / "run-1"
    run.mkdir()
    (run / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "run_id": "run-1",
                "last_updated_at": "2026-05-14T10:00:00+00:00",
                "target_url": "https://t",
                "target_version_sha": "sha-1",
                "metadata": {},
            }
        )
    )
    _write_replay_artifacts(
        run,
        attack_id="atk_x_1",
        verdict_id="ver_x_1",
        category="sensitive_information_disclosure",
        case_id="REGR-001",
        verdict="pass",
    )
    monkeypatch.setenv("EVALS_DIR", str(tmp_path))
    monkeypatch.setenv("RESULTS_DIR", str(results))
    body = (
        status_app.create_app()
        .test_client()
        .get("/api/vulnerabilities")
        .get_json()
    )
    assert len(body) == 1
    entry = body[0]
    assert entry["vuln_id"] == "VULN-001"
    assert entry["severity"] == "high"
    assert entry["status"] == "filed"
    assert entry["last_replay"]["last_verdict"] == "pass"
    assert entry["last_replay"]["target_version_sha"] == "sha-1"


def test_api_regression_replays_standalone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The /api/regression-replays endpoint returns the per-vuln snapshot
    keyed by vuln_id, independent of the vuln report listing."""
    reg_dir = tmp_path / "regression" / "sensitive_information_disclosure"
    reg_dir.mkdir(parents=True)
    (reg_dir / "REGR-001.yaml").write_text(
        "parent_vuln_id: VULN-001\ncategory: sensitive_information_disclosure\n"
    )
    results = tmp_path / "results"
    results.mkdir()
    run = results / "run-only"
    run.mkdir()
    (run / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "run_id": "run-only",
                "last_updated_at": "2026-05-14T10:00:00+00:00",
                "target_url": "https://t",
                "metadata": {},
            }
        )
    )
    _write_replay_artifacts(
        run,
        attack_id="atk_solo_1",
        verdict_id="ver_solo_1",
        category="sensitive_information_disclosure",
        case_id="REGR-001",
        verdict="partial",
    )
    monkeypatch.setenv("EVALS_DIR", str(tmp_path))
    monkeypatch.setenv("RESULTS_DIR", str(results))
    body = (
        status_app.create_app()
        .test_client()
        .get("/api/regression-replays")
        .get_json()
    )
    assert "VULN-001" in body
    assert body["VULN-001"]["last_verdict"] == "partial"
