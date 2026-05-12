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


def _run_summary(run_dir: Path) -> dict[str, Any]:
    """Compact per-run summary suitable for index listings.

    Pulls just the fields a grader / operator needs to see at a glance:
    when, what halted it, how many verdicts of each shape, what it cost.
    Avoids returning the full per-attack JSON tree to keep responses
    small.
    """
    manifest = _read_json_safe(run_dir / "manifest.json") or {}
    cost = _read_json_safe(run_dir / "cost-ledger.json") or {}
    coverage = _read_json_safe(run_dir / "coverage-state.json") or {}
    return {
        "run_id": run_dir.name,
        "started_at": manifest.get("started_at"),
        "ended_at": manifest.get("ended_at"),
        "halt_reason": manifest.get("halt_reason"),
        "iteration_count": manifest.get("iteration_count"),
        "verdict_counts": manifest.get("verdict_counts"),
        "total_cost_usd": cost.get("total_cost_usd"),
        "category_coverage": coverage.get("by_category"),
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
</style>
</head>
<body>
<div class="page">

<h1>Clinical Red Team Platform — Status</h1>
<div class="sub">
  Deployed adversarial AI security platform attacking
  <a href="https://142-93-242-40.nip.io">https://142-93-242-40.nip.io</a>.
  See <a href="https://github.com/TradeUpCards/clinical-redteam">GitHub</a>
  for source + architecture.
</div>

<h2>Recent runs <span style="color:var(--muted);font-size:12px;font-weight:400;">({{ runs|length }} of last {{ limit }})</span></h2>
{% if runs %}
<table>
  <thead><tr>
    <th>Run ID</th><th>Started</th><th>Halt reason</th><th>Iterations</th><th>Verdicts</th><th>Cost (USD)</th>
  </tr></thead>
  <tbody>
  {% for r in runs %}
    <tr>
      <td><code>{{ r.run_id }}</code></td>
      <td>{{ r.started_at or "—" }}</td>
      <td>{{ r.halt_reason or "(running)" }}</td>
      <td>{{ r.iteration_count if r.iteration_count is not none else "—" }}</td>
      <td>{% if r.verdict_counts %}{{ r.verdict_counts | tojson }}{% else %}—{% endif %}</td>
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
        """HTML status page — last N runs + vuln reports."""
        runs = [_run_summary(d) for d in _list_run_dirs()]
        vulns = _list_vulnerabilities()
        return render_template_string(
            _INDEX_TEMPLATE,
            runs=runs,
            vulns=vulns,
            limit=_RECENT_RUNS_LIMIT,
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
                "coverage_state": _read_json_safe(run_dir / "coverage-state.json"),
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
