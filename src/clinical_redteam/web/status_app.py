"""Status app for the deployed attacker platform.

Exposes a read-only HTTP surface that lets a grader (or operator) verify
the platform is running, see recent runs, and read vulnerability reports.

Endpoints:
  GET  /                      HTML index — last 10 runs + vuln-report links
  GET  /health                {"status":"ok"} — Caddy upstream + monitoring
  GET  /api/status            Latest run's manifest summary
  GET  /api/runs              List of recent run-ids with summary
  GET  /api/runs/<run_id>     That run's manifest + cost ledger + coverage
  GET  /api/vulnerabilities   List of VULN-NNN files with severity + status

All endpoints read from disk under `EVALS_DIR` (default `./evals`). No
mutation. No auth — only already-published artifacts surface here.

The companion `redteam-daemon` container produces the artifacts this
service reads (sibling Docker compose service; both bind-mount the same
evals/ volume).
"""

from __future__ import annotations

import json
import logging
import os
from html import escape
from pathlib import Path
from typing import Any

from flask import Flask, abort, jsonify, render_template_string

logger = logging.getLogger(__name__)

_RECENT_RUNS_LIMIT = 25
"""Cap on /api/runs and the HTML index. Keep the response small even
when the artifact tree grows over a long unattended run."""


def _evals_dir() -> Path:
    """Resolve the eval-suite directory at request time.

    Read from `EVALS_DIR` each call rather than at import time so tests
    can monkey-patch the env. Default mirrors `run.py`'s default of
    `./evals` for parity with the CLI's resolution.
    """
    return Path(os.getenv("EVALS_DIR", "./evals")).resolve()


def _results_dir() -> Path:
    """Where per-run artifacts live. Falls back to `<evals>/results/`."""
    explicit = os.getenv("RESULTS_DIR")
    if explicit:
        return Path(explicit).resolve()
    return _evals_dir() / "results"


def _vulnerabilities_dir() -> Path:
    return _evals_dir() / "vulnerabilities"


def _read_json_safe(p: Path) -> dict[str, Any] | None:
    """Read a JSON file; return None on missing-or-malformed.

    Used for run artifacts that may be mid-write (the daemon uses atomic
    tempfile-rename in persistence.py, so this is belt-and-suspenders).
    """
    try:
        with p.open(encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def _list_run_dirs(limit: int = _RECENT_RUNS_LIMIT) -> list[Path]:
    """Run dirs sorted newest-first by mtime, capped at `limit`.

    Sort by mtime rather than the directory name's embedded timestamp so
    that a partial / in-progress run shows up at the top of the list
    even if its name's timestamp is slightly older than a completed
    sibling's.
    """
    root = _results_dir()
    if not root.exists():
        return []
    dirs = [p for p in root.iterdir() if p.is_dir()]
    dirs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return dirs[:limit]


def _coverage_categories(coverage: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return the per-category map from a coverage-state payload.

    CoverageTracker._flush writes the map under `_categories`. Older /
    alternative writers may use `by_category`. Read both so the dashboard
    keeps working if the persistence key is ever renamed.
    """
    cats = coverage.get("_categories")
    if isinstance(cats, dict):
        return cats
    legacy = coverage.get("by_category")
    return legacy if isinstance(legacy, dict) else {}


def _sum_verdict_counts(coverage: dict[str, Any]) -> dict[str, int]:
    """Sum per-category verdict tallies. Keyed pass/fail/partial/uncertain.

    Reads the FLAT verdict keys CoverageTracker._flush writes — each
    `_categories[cat]` carries `pass`/`fail`/`partial`/`uncertain`
    sibling keys to `attack_count`, not a nested `verdicts` sub-dict.
    A `verdicts` sub-dict (the Pydantic CategoryCoverage shape) is also
    tolerated for forward-compat if a future writer normalizes to that
    form.

    Counts are derived from coverage rather than the manifest because
    the manifest (today) does not carry an aggregate tally.
    """
    totals = {"pass": 0, "fail": 0, "partial": 0, "uncertain": 0}
    for cat_data in _coverage_categories(coverage).values():
        if not isinstance(cat_data, dict):
            continue
        nested = cat_data.get("verdicts") if isinstance(cat_data.get("verdicts"), dict) else None
        for key in totals:
            raw = nested.get(key) if nested is not None else cat_data.get(key, 0)
            try:
                totals[key] += int(raw or 0)
            except (TypeError, ValueError):
                continue
    return totals


def _attack_counts_by_category(coverage: dict[str, Any]) -> dict[str, int]:
    """Per-category attack_count, defaulting missing entries to 0."""
    out: dict[str, int] = {}
    for cat, cat_data in _coverage_categories(coverage).items():
        try:
            out[cat] = int((cat_data or {}).get("attack_count", 0) or 0)
        except (TypeError, ValueError):
            out[cat] = 0
    return out


def _run_summary(run_dir: Path) -> dict[str, Any]:
    """Compact per-run summary suitable for index listings.

    Pulls just the fields a grader / operator needs to see at a glance:
    when, what halted it, how many verdicts of each shape, what it cost.
    Avoids returning the full per-attack JSON tree to keep responses
    small.

    Note on field provenance: `verdict_counts` and `total_cost_usd` are
    derived from coverage.json and cost-ledger.json's actual on-disk
    keys (`_categories`, `total_usd`) rather than from manifest keys that
    are not populated by the current persistence layer. See
    `_coverage_categories` for the legacy-key fallback.
    """
    manifest = _read_json_safe(run_dir / "manifest.json") or {}
    cost = _read_json_safe(run_dir / "cost-ledger.json") or {}
    coverage = _read_json_safe(run_dir / "coverage.json") or {}
    return {
        "run_id": run_dir.name,
        "started_at": manifest.get("started_at"),
        "ended_at": manifest.get("ended_at"),
        "halt_reason": manifest.get("halt_reason"),
        "iteration_count": manifest.get("iteration_count"),
        "verdict_counts": _sum_verdict_counts(coverage),
        "total_cost_usd": cost.get("total_usd"),
        "category_coverage": _coverage_categories(coverage),
    }


def _list_vulnerabilities() -> list[dict[str, Any]]:
    """Surface vuln-report files with parsed front-matter metadata.

    The Documentation Agent writes VULN-NNN files following ARCH §12.4.
    For the index we extract just severity + status + first-line title
    so a grader can scan the list. Full markdown lands at /api/runs/<id>
    if they want the whole report.
    """
    root = _vulnerabilities_dir()
    if not root.exists():
        return []
    out: list[dict[str, Any]] = []
    for p in sorted(root.glob("VULN-*.md")):
        title, severity, status = _parse_vuln_header(p)
        out.append(
            {
                "id": p.stem,
                "path": str(p.relative_to(_evals_dir())),
                "title": title,
                "severity": severity,
                "status": status,
            }
        )
    return out


def _parse_vuln_header(p: Path) -> tuple[str | None, str | None, str | None]:
    """Pull title + severity + status from the first ~30 lines.

    The Documentation Agent's ARCH §12.4 template is markdown with
    `**Severity:** HIGH` / `**Status:** filed` style key-value lines
    early in the file. Cheap regex-free scan; bounded read keeps a
    malicious-or-malformed file from stalling the request.
    """
    title = severity = status = None
    try:
        with p.open(encoding="utf-8") as f:
            for i, raw in enumerate(f):
                if i > 30:
                    break
                line = raw.strip()
                if title is None and line.startswith("# "):
                    title = line[2:].strip()
                low = line.lower()
                if "**severity:**" in low:
                    severity = line.split(":", 1)[1].strip().strip("*").strip()
                elif "**status:**" in low:
                    status = line.split(":", 1)[1].strip().strip("*").strip()
    except OSError:
        pass
    return title, severity, status


# ---------------------------------------------------------------------------
# Trend aggregation — answers PRD p.10 Observability Layer questions 1/2/3/5
# (which categories, pass/fail rate, resilience over time, cost trend).
# Aggregation lives server-side so the JSON API and HTML dashboard share
# one data model (and tests can pin shape via the function, not the page).
# ---------------------------------------------------------------------------


_TREND_RUNS_LIMIT = 50
"""Cap on the trend aggregation window. Bigger than the index table's
limit so the dashboard has more historical points to chart, but still
bounded — a long unattended run with hundreds of results dirs should
not blow up the dashboard response."""


def _aggregate_trends(run_dirs: list[Path]) -> dict[str, Any]:
    """Walk run dirs chronologically and build per-chart series.

    Sort order: by manifest `started_at` (ISO-8601, lexicographic order
    matches chronological for zero-padded timestamps), falling back to
    the run dir name when started_at is missing. A run with no manifest
    contributes zero-valued data — it appears on the timeline rather
    than disappearing, so partial / mid-write runs still show up.

    Cumulative-by-category: each run's `attack_count` represents that
    run's coverage tracker total at flush time. Across runs, the
    coverage tracker resets per run (CoverageTracker is per-RunHandle),
    so we sum per-run attack_counts to produce a cross-run cumulative.

    Verdict shift (last-N vs prior-N): defaults to 3-vs-3 when ≥ 6
    runs are available; falls back to 1-vs-rest when 2 ≤ runs < 6;
    None otherwise.
    """
    runs_chrono: list[dict[str, Any]] = []
    for d in run_dirs:
        manifest = _read_json_safe(d / "manifest.json") or {}
        coverage = _read_json_safe(d / "coverage.json") or {}
        cost = _read_json_safe(d / "cost-ledger.json") or {}
        by_cat = _attack_counts_by_category(coverage)
        try:
            total_cost_usd = float(cost.get("total_usd") or 0.0)
        except (TypeError, ValueError):
            total_cost_usd = 0.0
        runs_chrono.append(
            {
                "run_id": d.name,
                "started_at": manifest.get("started_at") or "",
                "verdicts": _sum_verdict_counts(coverage),
                "by_category": by_cat,
                "total_attacks": sum(by_cat.values()),
                "total_cost_usd": total_cost_usd,
            }
        )
    runs_chrono.sort(key=lambda r: (r["started_at"] or "", r["run_id"]))

    categories = sorted({c for r in runs_chrono for c in r["by_category"]})

    cumulative_series: list[dict[str, Any]] = []
    running = dict.fromkeys(categories, 0)
    for r in runs_chrono:
        for c in categories:
            running[c] += r["by_category"].get(c, 0)
        cumulative_series.append(
            {
                "run_id": r["run_id"],
                "started_at": r["started_at"],
                "by_cat": dict(running),
            }
        )

    verdict_series = [
        {
            "run_id": r["run_id"],
            "started_at": r["started_at"],
            **r["verdicts"],
        }
        for r in runs_chrono
    ]

    cost_series: list[dict[str, Any]] = []
    for r in runs_chrono:
        attacks = r["total_attacks"]
        cpa = (r["total_cost_usd"] / attacks) if attacks > 0 else 0.0
        cost_series.append(
            {
                "run_id": r["run_id"],
                "started_at": r["started_at"],
                "total_cost_usd": r["total_cost_usd"],
                "cost_per_attack": cpa,
            }
        )

    verdict_shift = _compute_verdict_shift(runs_chrono)

    return {
        "verdict_series": verdict_series,
        "category_series": cumulative_series,
        "categories": categories,
        "cost_series": cost_series,
        "verdict_shift": verdict_shift,
        "run_count": len(runs_chrono),
    }


def _compute_verdict_shift(
    runs_chrono: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Last-N vs prior-N fail-rate comparison. Window size adapts to N.

    Fail rate = fail / (pass + fail + partial + uncertain) per group,
    summed across runs in that group. Returns None when fewer than 2
    runs are available — a single run has no "trend" to compute.
    """
    n = len(runs_chrono)
    if n < 2:
        return None
    if n >= 6:
        recent = runs_chrono[-3:]
        prior = runs_chrono[-6:-3]
    else:
        recent = runs_chrono[-1:]
        prior = runs_chrono[:-1]
    if not prior:
        return None

    def fail_rate(group: list[dict[str, Any]]) -> tuple[float, int]:
        total = 0
        fails = 0
        for r in group:
            v = r["verdicts"]
            total += v["pass"] + v["fail"] + v["partial"] + v["uncertain"]
            fails += v["fail"]
        return ((fails / total) if total else 0.0), total

    recent_rate, recent_total = fail_rate(recent)
    prior_rate, prior_total = fail_rate(prior)
    return {
        "recent_runs": len(recent),
        "prior_runs": len(prior),
        "recent_judged": recent_total,
        "prior_judged": prior_total,
        "recent_fail_rate_pct": round(recent_rate * 100, 1),
        "prior_fail_rate_pct": round(prior_rate * 100, 1),
        "delta_pp": round((recent_rate - prior_rate) * 100, 1),
    }


# ---------------------------------------------------------------------------
# Inline SVG chart helpers — no CDN, no JS, no external font loads.
#
# Hand-rolled SVG over Chart.js because (a) the deployed URL is read by
# the grader without trusting external resource loads and (b) we have
# < 50 data points so a stacked-bar / multi-line in raw SVG is < 200 LOC
# and easier to audit than embedding a minified bundle. All caller-
# supplied strings flow through `escape()` before reaching SVG attribute
# or text content.
# ---------------------------------------------------------------------------


_CHART_WIDTH = 720
_CHART_HEIGHT = 220
_CHART_MARGIN = {"top": 12, "right": 12, "bottom": 36, "left": 44}

_VERDICT_COLORS = {
    "pass": "#15803d",
    "partial": "#b45309",
    "uncertain": "#1d4ed8",
    "fail": "#b91c1c",
}
"""Stack order is dictated by render order below: pass first (bottom),
then partial, then uncertain, then fail (top). Colors mirror the badge
palette in `_INDEX_TEMPLATE` so the chart legend reads visually."""

_CATEGORY_COLORS = [
    "#1d4ed8",  # blue
    "#15803d",  # green
    "#b45309",  # amber
    "#7c3aed",  # purple
    "#0e7490",  # teal
    "#b91c1c",  # red — last; we don't expect > 6 categories at MVP
]


def _plot_area() -> tuple[int, int, int, int]:
    """Inner-plot (x0, y0, x1, y1) inside the chart margins."""
    x0 = _CHART_MARGIN["left"]
    y0 = _CHART_MARGIN["top"]
    x1 = _CHART_WIDTH - _CHART_MARGIN["right"]
    y1 = _CHART_HEIGHT - _CHART_MARGIN["bottom"]
    return x0, y0, x1, y1


def _y_ticks(max_value: float, *, n: int = 4) -> list[float]:
    """Evenly spaced y-tick values from 0 to a rounded max."""
    if max_value <= 0:
        return [0.0]
    step = max_value / n
    return [round(step * i, 4) for i in range(n + 1)]


def _format_y_label(value: float) -> str:
    """Compact y-axis label: integer for whole numbers, else 2 decimals."""
    if abs(value - round(value)) < 1e-9:
        return str(int(round(value)))
    return f"{value:.2f}"


def _format_cost_label(value: float) -> str:
    if value >= 1.0:
        return f"${value:.2f}"
    return f"${value:.4f}".rstrip("0").rstrip(".") or "$0"


def _svg_open(title: str) -> str:
    safe_title = escape(title)
    return (
        f'<svg role="img" aria-label="{safe_title}" '
        f'viewBox="0 0 {_CHART_WIDTH} {_CHART_HEIGHT}" '
        f'preserveAspectRatio="xMidYMid meet" '
        f'xmlns="http://www.w3.org/2000/svg" '
        f'style="width:100%;height:auto;font-family:inherit;font-size:11px;">'
        f"<title>{safe_title}</title>"
    )


def _svg_axes(*, y_max: float, x_label_left: str, x_label_right: str) -> str:
    """Frame + y-axis ticks/labels + x-axis endpoint labels."""
    x0, y0, x1, y1 = _plot_area()
    parts = [
        f'<rect x="{x0}" y="{y0}" width="{x1 - x0}" height="{y1 - y0}" '
        f'fill="white" stroke="#e5e5e0" stroke-width="1"/>'
    ]
    for tick in _y_ticks(y_max):
        ty = y1 - (y1 - y0) * (tick / y_max if y_max > 0 else 0)
        parts.append(
            f'<line x1="{x0}" x2="{x1}" y1="{ty:.2f}" y2="{ty:.2f}" '
            f'stroke="#f3f3ef" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{x0 - 6}" y="{ty:.2f}" fill="#6b6b6b" '
            f'text-anchor="end" dominant-baseline="middle">'
            f"{escape(_format_y_label(tick))}</text>"
        )
    parts.append(
        f'<text x="{x0}" y="{y1 + 16}" fill="#6b6b6b" text-anchor="start">'
        f"{escape(x_label_left)}</text>"
    )
    parts.append(
        f'<text x="{x1}" y="{y1 + 16}" fill="#6b6b6b" text-anchor="end">'
        f"{escape(x_label_right)}</text>"
    )
    return "".join(parts)


def _svg_legend(items: list[tuple[str, str]]) -> str:
    """Inline-flow legend rendered as SVG <g>. items: [(label, color), ...]."""
    x0, _, x1, _ = _plot_area()
    parts = []
    cursor = x0
    y = _CHART_HEIGHT - 6
    for label, color in items:
        parts.append(
            f'<rect x="{cursor}" y="{y - 9}" width="10" height="10" '
            f'fill="{color}" stroke="none"/>'
        )
        parts.append(
            f'<text x="{cursor + 14}" y="{y}" fill="#1a1a1a">{escape(label)}</text>'
        )
        cursor += 14 + 7 * (len(label) + 2)
        if cursor > x1 - 60:
            break
    return "".join(parts)


def _svg_verdict_stacked_bars(series: list[dict[str, Any]]) -> str:
    """Stacked bars per run, chronological. PRD p.10 Q2 + Q3.

    Empty series → empty string (caller's template guards on truthiness).
    Bars stack pass (bottom) → partial → uncertain → fail (top).
    A run with zero totals still renders as a baseline tick so the
    timeline doesn't gap visually.
    """
    if not series:
        return ""
    x0, y0, x1, y1 = _plot_area()
    plot_w = x1 - x0
    plot_h = y1 - y0
    max_total = max(
        (s["pass"] + s["fail"] + s["partial"] + s["uncertain"]) for s in series
    )
    max_total = max(max_total, 1)
    n = len(series)
    bar_w = max(2.0, min(28.0, plot_w / max(n, 1) - 4))
    step = plot_w / n if n else plot_w

    parts: list[str] = [
        _svg_open(f"Verdict counts per run ({n} runs)"),
        _svg_axes(
            y_max=max_total,
            x_label_left=series[0].get("started_at", "") or series[0]["run_id"],
            x_label_right=series[-1].get("started_at", "") or series[-1]["run_id"],
        ),
    ]
    for idx, s in enumerate(series):
        cx = x0 + step * (idx + 0.5)
        bx = cx - bar_w / 2
        cursor_top = float(y1)
        run_title = (
            f"{s['run_id']} · started {s.get('started_at') or '—'} · "
            f"pass {s['pass']} / partial {s['partial']} / "
            f"uncertain {s['uncertain']} / fail {s['fail']}"
        )
        parts.append(f"<g><title>{escape(run_title)}</title>")
        for key in ("pass", "partial", "uncertain", "fail"):
            v = s.get(key, 0) or 0
            if v <= 0:
                continue
            seg_h = plot_h * (v / max_total)
            cursor_top -= seg_h
            parts.append(
                f'<rect x="{bx:.2f}" y="{cursor_top:.2f}" '
                f'width="{bar_w:.2f}" height="{seg_h:.2f}" '
                f'fill="{_VERDICT_COLORS[key]}" stroke="none"/>'
            )
        parts.append("</g>")
    parts.append(
        _svg_legend(
            [
                ("pass", _VERDICT_COLORS["pass"]),
                ("partial", _VERDICT_COLORS["partial"]),
                ("uncertain", _VERDICT_COLORS["uncertain"]),
                ("fail", _VERDICT_COLORS["fail"]),
            ]
        )
    )
    parts.append("</svg>")
    return "".join(parts)


def _svg_multiline(
    series: list[dict[str, Any]],
    *,
    categories: list[str],
    value_key: str = "by_cat",
    title_text: str,
) -> str:
    """Multi-line chart over chronological points.

    Each entry in `series` has a `value_key` dict mapping category →
    numeric value. Y axis scales to the max across all (entry, category)
    pairs. Polylines are one per category, colored from
    `_CATEGORY_COLORS` in stable category-sort order.
    """
    if not series or not categories:
        return ""
    x0, y0, x1, y1 = _plot_area()
    plot_w = x1 - x0
    plot_h = y1 - y0
    max_value = max(
        (entry[value_key].get(c, 0) or 0) for entry in series for c in categories
    )
    max_value = max(max_value, 1)
    n = len(series)
    step = plot_w / max(n - 1, 1) if n > 1 else 0

    parts: list[str] = [
        _svg_open(title_text),
        _svg_axes(
            y_max=max_value,
            x_label_left=series[0].get("started_at", "") or series[0]["run_id"],
            x_label_right=series[-1].get("started_at", "") or series[-1]["run_id"],
        ),
    ]
    color_for = {
        cat: _CATEGORY_COLORS[i % len(_CATEGORY_COLORS)]
        for i, cat in enumerate(categories)
    }
    for cat in categories:
        coords: list[str] = []
        for idx, entry in enumerate(series):
            v = entry[value_key].get(cat, 0) or 0
            x = (x0 + step * idx) if n > 1 else (x0 + plot_w / 2)
            y = y1 - plot_h * (v / max_value)
            coords.append(f"{x:.2f},{y:.2f}")
        polyline_pts = " ".join(coords)
        parts.append(
            f'<polyline points="{polyline_pts}" fill="none" '
            f'stroke="{color_for[cat]}" stroke-width="1.8" '
            f'stroke-linejoin="round" stroke-linecap="round"/>'
        )
        if n == 1:
            x_only, y_only = coords[0].split(",")
            parts.append(
                f'<circle cx="{x_only}" cy="{y_only}" r="2.5" '
                f'fill="{color_for[cat]}"/>'
            )
    parts.append(_svg_legend([(c, color_for[c]) for c in categories]))
    parts.append("</svg>")
    return "".join(parts)


def _svg_cost_lines(series: list[dict[str, Any]]) -> str:
    """Two lines on a shared timeline: total cost (USD) and cost per attack.

    Each series has its own normalized y-scale to keep both visible when
    the magnitudes differ. Y-axis label shows the total-cost scale; the
    cost-per-attack line is drawn lighter and labeled in the legend.
    """
    if not series:
        return ""
    x0, y0, x1, y1 = _plot_area()
    plot_w = x1 - x0
    plot_h = y1 - y0
    max_total = max((s["total_cost_usd"] or 0.0) for s in series)
    max_cpa = max((s["cost_per_attack"] or 0.0) for s in series)
    max_total = max(max_total, 1e-6)
    max_cpa = max(max_cpa, 1e-6)
    n = len(series)
    step = plot_w / max(n - 1, 1) if n > 1 else 0

    parts: list[str] = [
        _svg_open(f"Cost trend ({n} runs)"),
        # Custom axes — y-ticks use cost-format labels.
        f'<rect x="{x0}" y="{y0}" width="{plot_w}" height="{plot_h}" '
        f'fill="white" stroke="#e5e5e0" stroke-width="1"/>',
    ]
    for tick in _y_ticks(max_total):
        ty = y1 - plot_h * (tick / max_total if max_total > 0 else 0)
        parts.append(
            f'<line x1="{x0}" x2="{x1}" y1="{ty:.2f}" y2="{ty:.2f}" '
            f'stroke="#f3f3ef" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{x0 - 6}" y="{ty:.2f}" fill="#6b6b6b" '
            f'text-anchor="end" dominant-baseline="middle">'
            f"{escape(_format_cost_label(tick))}</text>"
        )
    parts.append(
        f'<text x="{x0}" y="{y1 + 16}" fill="#6b6b6b" text-anchor="start">'
        f"{escape(series[0].get('started_at', '') or series[0]['run_id'])}</text>"
    )
    parts.append(
        f'<text x="{x1}" y="{y1 + 16}" fill="#6b6b6b" text-anchor="end">'
        f"{escape(series[-1].get('started_at', '') or series[-1]['run_id'])}</text>"
    )

    def line(key: str, color: str, scale_max: float, width: float) -> str:
        coords: list[str] = []
        for idx, s in enumerate(series):
            v = s.get(key, 0.0) or 0.0
            x = (x0 + step * idx) if n > 1 else (x0 + plot_w / 2)
            y = y1 - plot_h * (v / scale_max if scale_max > 0 else 0)
            coords.append(f"{x:.2f},{y:.2f}")
        pts = " ".join(coords)
        circle_marker = ""
        if n == 1:
            cx, cy = coords[0].split(",")
            circle_marker = (
                f'<circle cx="{cx}" cy="{cy}" r="2.5" fill="{color}"/>'
            )
        return (
            f'<polyline points="{pts}" fill="none" stroke="{color}" '
            f'stroke-width="{width}" stroke-linejoin="round" '
            f'stroke-linecap="round"/>{circle_marker}'
        )

    parts.append(line("total_cost_usd", "#1d4ed8", max_total, 1.8))
    parts.append(line("cost_per_attack", "#b45309", max_cpa, 1.4))
    parts.append(
        _svg_legend(
            [
                (f"total cost (max {_format_cost_label(max_total)})", "#1d4ed8"),
                (f"cost per attack (max {_format_cost_label(max_cpa)})", "#b45309"),
            ]
        )
    )
    parts.append("</svg>")
    return "".join(parts)


# ---------------------------------------------------------------------------
# HTML index — minimal Jinja-rendered single page
# ---------------------------------------------------------------------------

_INDEX_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Clinical Red Team Platform — Status</title>
<style>
  :root {
    --bg: #fafaf8; --ink: #1a1a1a; --muted: #6b6b6b;
    --line: #e5e5e0; --good: #15803d; --warn: #b45309;
    --bad: #b91c1c; --info: #1d4ed8;
  }
  body { margin: 0; background: var(--bg); color: var(--ink);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-size: 14px; line-height: 1.5; }
  .page { max-width: 1080px; margin: 0 auto; padding: 24px 22px 80px; }
  h1 { font-size: 22px; margin: 0 0 6px; }
  .sub { color: var(--muted); margin-bottom: 26px; font-size: 13px; }
  h2 { font-size: 16px; margin: 30px 0 12px;
    padding-bottom: 6px; border-bottom: 1px solid var(--line); }
  table { width: 100%; border-collapse: collapse;
    background: white; border: 1px solid var(--line); border-radius: 5px;
    overflow: hidden; }
  th, td { padding: 10px 12px; text-align: left;
    border-bottom: 1px solid var(--line); font-size: 13px;
    vertical-align: top; }
  th { background: #f3f3ef; font-size: 11px; color: var(--muted);
    text-transform: uppercase; letter-spacing: 0.04em; font-weight: 600; }
  tr:last-child td { border-bottom: none; }
  code { font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 12px;
    background: #f3f3ef; padding: 1px 5px; border-radius: 3px; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 10px;
    font-size: 11px; font-weight: 600; letter-spacing: 0.02em; text-transform: uppercase; }
  .badge-high { background: #fef2f2; color: var(--bad); }
  .badge-medium { background: #fffbeb; color: var(--warn); }
  .badge-low { background: #eff6ff; color: var(--info); }
  .badge-info { background: #f3f3ef; color: var(--muted); }
  .empty { color: var(--muted); padding: 14px; text-align: center; font-style: italic; }
  .api-list code { display: block; margin: 4px 0; }
  .chart-card { background: white; border: 1px solid var(--line); border-radius: 5px;
    padding: 14px 18px 8px; margin-bottom: 16px; }
  .chart-card h3 { margin: 0 0 4px; font-size: 13px; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); }
  .chart-card .chart-note { color: var(--muted); font-size: 12px; margin: 0 0 10px; }
  .stat-grid { display: grid; grid-template-columns: repeat(3, 1fr);
    gap: 12px; margin: 0; }
  .stat-grid .stat { background: #f7f7f3; border: 1px solid var(--line);
    border-radius: 5px; padding: 10px 12px; }
  .stat-grid .stat .label { color: var(--muted); font-size: 11px;
    text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 4px; }
  .stat-grid .stat .value { font-size: 20px; font-weight: 600; }
  .delta-down { color: var(--good); }
  .delta-up { color: var(--bad); }
  .delta-flat { color: var(--muted); }
  .verdict-cell { font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 12px;
    color: var(--muted); white-space: nowrap; }
  .verdict-cell strong { color: var(--ink); }
</style>
</head>
<body>
<div class="page">

<h1>Clinical Red Team Platform — Status</h1>
<div class="sub">
  Deployed adversarial AI security platform attacking
  <a href="https://142-93-242-40.nip.io">https://142-93-242-40.nip.io</a>.
  See <a href="https://labs.gauntletai.com/coryvandenberg/clinical-redteam">GitLab</a>
  (primary) or the <a href="https://github.com/TradeUpCards/clinical-redteam">GitHub mirror</a>
  for source + architecture.
</div>

{% if trends.run_count > 0 %}
<h2>Trends <span style="color:var(--muted);font-size:12px;font-weight:400;">(over the last {{ trends.run_count }} run{{ "" if trends.run_count == 1 else "s" }})</span></h2>

{% if trends.verdict_shift %}
<div class="chart-card">
  <h3>Resilience shift</h3>
  <p class="chart-note">
    Fail rate over the last {{ trends.verdict_shift.recent_runs }} run{{ "" if trends.verdict_shift.recent_runs == 1 else "s" }} versus the prior {{ trends.verdict_shift.prior_runs }}.
    Negative delta = target getting more resilient.
  </p>
  <div class="stat-grid">
    <div class="stat">
      <div class="label">Prior fail rate</div>
      <div class="value">{{ "%.1f"|format(trends.verdict_shift.prior_fail_rate_pct) }}%</div>
      <div class="chart-note">{{ trends.verdict_shift.prior_judged }} judged</div>
    </div>
    <div class="stat">
      <div class="label">Recent fail rate</div>
      <div class="value">{{ "%.1f"|format(trends.verdict_shift.recent_fail_rate_pct) }}%</div>
      <div class="chart-note">{{ trends.verdict_shift.recent_judged }} judged</div>
    </div>
    <div class="stat">
      <div class="label">Δ (percentage points)</div>
      <div class="value {% if trends.verdict_shift.delta_pp < 0 %}delta-down{% elif trends.verdict_shift.delta_pp > 0 %}delta-up{% else %}delta-flat{% endif %}">
        {{ "%+.1f"|format(trends.verdict_shift.delta_pp) }} pp
      </div>
      <div class="chart-note">{% if trends.verdict_shift.delta_pp < 0 %}target more resilient{% elif trends.verdict_shift.delta_pp > 0 %}target less resilient{% else %}no change{% endif %}</div>
    </div>
  </div>
</div>
{% endif %}

{% if verdict_chart_svg %}
<div class="chart-card">
  <h3>Verdict counts per run</h3>
  <p class="chart-note">Stacked bars — pass / partial / uncertain / fail across the chronological run series. Hover a bar for the run-level breakdown.</p>
  {{ verdict_chart_svg | safe }}
</div>
{% endif %}

{% if coverage_chart_svg %}
<div class="chart-card">
  <h3>Cumulative attack coverage by category</h3>
  <p class="chart-note">Sum of attacks attempted per category across runs, in chronological order.</p>
  {{ coverage_chart_svg | safe }}
</div>
{% endif %}

{% if cost_chart_svg %}
<div class="chart-card">
  <h3>Cost trend</h3>
  <p class="chart-note">Per-run total spend (blue) and derived cost per attack (amber).</p>
  {{ cost_chart_svg | safe }}
</div>
{% endif %}
{% endif %}

<h2>Recent runs <span style="color:var(--muted);font-size:12px;font-weight:400;">({{ runs|length }} of last {{ limit }})</span></h2>
{% if runs %}
<table>
  <thead><tr>
    <th>Run ID</th><th>Started</th><th>Halt reason</th><th>Iterations</th><th>Verdicts (P/Pa/Un/F)</th><th>Cost (USD)</th>
  </tr></thead>
  <tbody>
  {% for r in runs %}
    <tr>
      <td><code>{{ r.run_id }}</code></td>
      <td>{{ r.started_at or "—" }}</td>
      <td>{{ r.halt_reason or "(running)" }}</td>
      <td>{{ r.iteration_count if r.iteration_count is not none else "—" }}</td>
      <td class="verdict-cell">
        {% set vc = r.verdict_counts or {} %}
        {% set vc_total = (vc.get("pass", 0) + vc.get("fail", 0) + vc.get("partial", 0) + vc.get("uncertain", 0)) %}
        {% if vc_total > 0 %}
          <strong>{{ vc.get("pass", 0) }}</strong>/{{ vc.get("partial", 0) }}/{{ vc.get("uncertain", 0) }}/<strong>{{ vc.get("fail", 0) }}</strong>
        {% else %}—{% endif %}
      </td>
      <td>{% if r.total_cost_usd is not none %}${{ "%.4f"|format(r.total_cost_usd) }}{% else %}—{% endif %}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% else %}
<div class="empty">No runs yet. The daemon writes a manifest at start of each iteration.</div>
{% endif %}

<h2>Vulnerability reports <span style="color:var(--muted);font-size:12px;font-weight:400;">({{ vulns|length }})</span></h2>
{% if vulns %}
<table>
  <thead><tr>
    <th>ID</th><th>Title</th><th>Severity</th><th>Status</th>
  </tr></thead>
  <tbody>
  {% for v in vulns %}
    <tr>
      <td><code>{{ v.id }}</code></td>
      <td>{{ v.title or "(untitled)" }}</td>
      <td>
        {% if v.severity %}
        <span class="badge badge-{{ (v.severity|lower)[:6] }}">{{ v.severity }}</span>
        {% else %}—{% endif %}
      </td>
      <td>{{ v.status or "—" }}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% else %}
<div class="empty">No vulnerability reports yet. The Documentation Agent files reports when the Judge confirms an exploit.</div>
{% endif %}

<h2>API</h2>
<div class="api-list">
  <code>GET /health</code>
  <code>GET /api/status</code>
  <code>GET /api/runs</code>
  <code>GET /api/runs/&lt;run_id&gt;</code>
  <code>GET /api/vulnerabilities</code>
</div>

</div>
</body>
</html>
"""


def create_app() -> Flask:
    """Application factory.

    Returns a configured Flask app. Tests instantiate this directly with
    a temp `EVALS_DIR` env override; production uses the default
    entrypoint (see `__main__` block below).
    """
    app = Flask(__name__)

    @app.route("/health")
    def health() -> Any:
        """Liveness probe.

        Always 200 OK if the process is running. Caddy uses this as the
        upstream health gate; monitoring uses it as the keepalive ping.
        Does NOT verify daemon health — the daemon is a sibling
        container; its health is its own concern.
        """
        return jsonify({"status": "ok", "service": "clinical-redteam-status"})

    @app.route("/")
    def index() -> Any:
        """HTML status page — last N runs + vuln reports + trend dashboard.

        Two read scopes:
          * `_RECENT_RUNS_LIMIT` (25) — table + per-run JSON summaries
          * `_TREND_RUNS_LIMIT`  (50) — chronological aggregation window
        The trend scope is wider on purpose: more history = more credible
        trend lines, but capped to keep response time bounded.
        """
        runs = [_run_summary(d) for d in _list_run_dirs()]
        trend_dirs = _list_run_dirs(limit=_TREND_RUNS_LIMIT)
        trends = _aggregate_trends(trend_dirs)
        verdict_chart_svg = _svg_verdict_stacked_bars(trends["verdict_series"])
        coverage_chart_svg = _svg_multiline(
            trends["category_series"],
            categories=trends["categories"],
            value_key="by_cat",
            title_text="Cumulative attack coverage by category",
        )
        cost_chart_svg = _svg_cost_lines(trends["cost_series"])
        vulns = _list_vulnerabilities()
        return render_template_string(
            _INDEX_TEMPLATE,
            runs=runs,
            vulns=vulns,
            limit=_RECENT_RUNS_LIMIT,
            trends=trends,
            verdict_chart_svg=verdict_chart_svg,
            coverage_chart_svg=coverage_chart_svg,
            cost_chart_svg=cost_chart_svg,
        )

    @app.route("/api/status")
    def api_status() -> Any:
        """Latest run's summary as JSON. Empty object if no runs yet."""
        dirs = _list_run_dirs(limit=1)
        if not dirs:
            return jsonify({})
        return jsonify(_run_summary(dirs[0]))

    @app.route("/api/runs")
    def api_runs() -> Any:
        """List of recent runs, newest first, capped at _RECENT_RUNS_LIMIT."""
        return jsonify([_run_summary(d) for d in _list_run_dirs()])

    @app.route("/api/runs/<run_id>")
    def api_run_detail(run_id: str) -> Any:
        """Full manifest + cost ledger + coverage for one run.

        404 if the run dir doesn't exist. The 404 is a safety boundary,
        not just "not found" — it ALSO catches attempted path traversal
        (run_id with `..` or `/` segments). The Path resolution below
        canonicalizes, then we re-check containment.
        """
        if "/" in run_id or "\\" in run_id or ".." in run_id:
            abort(400)
        run_dir = (_results_dir() / run_id).resolve()
        try:
            run_dir.relative_to(_results_dir())
        except ValueError:
            abort(400)
        if not run_dir.is_dir():
            abort(404)
        return jsonify(
            {
                "manifest": _read_json_safe(run_dir / "manifest.json"),
                "cost_ledger": _read_json_safe(run_dir / "cost-ledger.json"),
                "coverage_state": _read_json_safe(run_dir / "coverage.json"),
            }
        )

    @app.route("/api/vulnerabilities")
    def api_vulns() -> Any:
        """Vuln-report index with parsed severity + status."""
        return jsonify(_list_vulnerabilities())

    return app


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entrypoint for the status service.

    Configuration via env:
      STATUS_HOST    (default 0.0.0.0 — must bind all interfaces for Caddy)
      STATUS_PORT    (default 8080)
      EVALS_DIR      (default ./evals — same as run.py)
      RESULTS_DIR    (default <EVALS_DIR>/results — same as run.py)
      LOG_LEVEL      (default INFO)

    In Docker the service runs via gunicorn (see Dockerfile); this
    `main()` is the local-dev entrypoint via `python -m clinical_redteam.web`.
    """
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    app = create_app()
    host = os.getenv("STATUS_HOST", "0.0.0.0")  # noqa: S104 — public deploy
    port = int(os.getenv("STATUS_PORT", "8080"))
    logger.info("Starting clinical-redteam-status on %s:%d", host, port)
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()


# Suppress the unused-import warning for `escape` — kept around because
# any future template injection that bypasses Jinja autoescaping (e.g.
# raw HTML in a vuln title) will want it. Defensive belt for §H-1 of the
# threat model when this surface evolves.
_ = escape
