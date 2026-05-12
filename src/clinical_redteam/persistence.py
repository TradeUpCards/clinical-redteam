"""Filesystem persistence for run artifacts (ARCH §9.1).

The continuous-mode daemon survives restarts via filesystem checkpoints
BEFORE every external call. This module owns that contract.

Directory layout per run:

    <RESULTS_DIR>/<run-id>/
        manifest.json                 # run-level state, updated atomically
        attacks/<attack_id>.json      # one AttackCandidate per file
        verdicts/<verdict_id>.json    # one JudgeVerdict per file
        vulnerabilities/<vuln_id>.md  # YAML frontmatter + markdown body

All writes are atomic: write to a sibling `.tmp` file, fsync, then rename
over the destination. A crash mid-write either leaves the previous version
intact or leaves nothing — never a half-written JSON. This is what makes
"resume after kill -9" actually work (Phase 1b A4).

NOT in scope here:
- Eval seed cases (evals/seed/*.yaml) — those are committed inputs, owned
  by Bram; read-only from the daemon's perspective
- Cost ledger writes — composed in cost_ledger.py (Phase 1a #11), this
  module provides the atomic-write primitive that ledger reuses
- Langfuse trace persistence — observability.py (Phase 1a #12)
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from clinical_redteam.schemas import (
    AttackCandidate,
    JudgeVerdict,
    VulnerabilityReportFrontmatter,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


MANIFEST_FILENAME = "manifest.json"
ATTACKS_SUBDIR = "attacks"
VERDICTS_SUBDIR = "verdicts"
VULNERABILITIES_SUBDIR = "vulnerabilities"

MANIFEST_SCHEMA_VERSION = 1
"""Bump when the manifest layout changes incompatibly. Readers refuse to
resume from a manifest with a different schema version."""


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PersistenceError(Exception):
    """Base class for persistence errors."""


class ManifestSchemaMismatchError(PersistenceError):
    """Resume target's manifest schema version doesn't match this code."""


class DuplicateArtifactError(PersistenceError):
    """A second save of the same attack_id / verdict_id / vuln_id at a
    different content hash. Re-saving identical content is a no-op (idempotent),
    but the same ID with diverged content is a bug worth surfacing."""


# ---------------------------------------------------------------------------
# Atomic-write primitive (also used by cost_ledger.py at Phase 1a #11)
# ---------------------------------------------------------------------------


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write `data` to `path` atomically.

    Strategy: open a NamedTemporaryFile in the same directory, write + fsync,
    close, then rename over the destination. Same-directory tempfile is
    important — `os.replace` is only atomic within a single filesystem.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        prefix=path.name + ".",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            # Some filesystems (e.g., certain mounted volumes on Windows) don't
            # support fsync. Best-effort durability is the contract.
            with contextlib.suppress(OSError):
                os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    """Atomic JSON write with sorted keys + 2-space indent for stable diffs."""
    data = json.dumps(payload, indent=2, sort_keys=True, default=str).encode("utf-8")
    atomic_write_bytes(path, data)


def atomic_write_text(path: Path, text: str) -> None:
    """Atomic UTF-8 text write."""
    atomic_write_bytes(path, text.encode("utf-8"))


# ---------------------------------------------------------------------------
# Run handle
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class RunHandle:
    """Per-run filesystem handle. One per continuous-mode session."""

    run_id: str
    run_dir: Path

    @property
    def manifest_path(self) -> Path:
        return self.run_dir / MANIFEST_FILENAME

    @property
    def attacks_dir(self) -> Path:
        return self.run_dir / ATTACKS_SUBDIR

    @property
    def verdicts_dir(self) -> Path:
        return self.run_dir / VERDICTS_SUBDIR

    @property
    def vulnerabilities_dir(self) -> Path:
        return self.run_dir / VULNERABILITIES_SUBDIR

    # ------------------------------------------------------------------ writes

    def save_attack(self, attack: AttackCandidate) -> Path:
        """Persist an AttackCandidate. Idempotent on identical content."""
        path = self.attacks_dir / f"{attack.attack_id}.json"
        payload = attack.model_dump(mode="json")
        self._save_unique(path, payload, identity=attack.attack_id)
        self._touch_manifest_index("attack_ids", attack.attack_id)
        return path

    def save_verdict(self, verdict: JudgeVerdict) -> Path:
        """Persist a JudgeVerdict. Idempotent on identical content."""
        path = self.verdicts_dir / f"{verdict.verdict_id}.json"
        payload = verdict.model_dump(mode="json")
        self._save_unique(path, payload, identity=verdict.verdict_id)
        self._touch_manifest_index("verdict_ids", verdict.verdict_id)
        return path

    def save_vuln_draft(
        self,
        frontmatter: VulnerabilityReportFrontmatter,
        body_markdown: str,
    ) -> Path:
        """Persist a vulnerability report (YAML frontmatter + markdown body).

        High/critical severity reports stay as DRAFT — caller MUST set
        `status="draft-pending-review"`. We do not enforce that here (the
        Documentation Agent is responsible per Tate hard rules), but we
        write whatever status was supplied and never promote on save.
        """
        path = self.vulnerabilities_dir / f"{frontmatter.vuln_id}.md"
        rendered = render_vuln_report(frontmatter, body_markdown)
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(path, rendered)
        self._touch_manifest_index("vuln_ids", frontmatter.vuln_id)
        return path

    # ------------------------------------------------------------------ reads

    def load_manifest(self) -> dict[str, Any]:
        """Read the run's manifest. Raises if absent or schema mismatched."""
        if not self.manifest_path.exists():
            raise PersistenceError(
                f"No manifest at {self.manifest_path}. start_run() must be "
                "called before reads."
            )
        with self.manifest_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        schema_version = data.get("schema_version")
        if schema_version != MANIFEST_SCHEMA_VERSION:
            raise ManifestSchemaMismatchError(
                f"Manifest at {self.manifest_path} has schema_version="
                f"{schema_version!r}; this code expects "
                f"{MANIFEST_SCHEMA_VERSION}. Migrate or start a new run."
            )
        return data

    def load_attack(self, attack_id: str) -> AttackCandidate:
        path = self.attacks_dir / f"{attack_id}.json"
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return AttackCandidate.model_validate(data)

    def load_verdict(self, verdict_id: str) -> JudgeVerdict:
        path = self.verdicts_dir / f"{verdict_id}.json"
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return JudgeVerdict.model_validate(data)

    # ------------------------------------------------------------------ internals

    def _save_unique(
        self, path: Path, payload: dict[str, Any], *, identity: str
    ) -> None:
        """Atomic write with duplicate detection on identical IDs."""
        if path.exists():
            with path.open("r", encoding="utf-8") as f:
                existing = json.load(f)
            if existing == payload:
                return  # idempotent re-save
            raise DuplicateArtifactError(
                f"Refusing to overwrite {path}: another artifact with id "
                f"{identity!r} already persisted with different content."
            )
        atomic_write_json(path, payload)

    def _touch_manifest_index(self, list_key: str, item: str) -> None:
        """Append `item` to manifest[list_key] if not already present."""
        manifest = self.load_manifest()
        ids = manifest.setdefault(list_key, [])
        if item not in ids:
            ids.append(item)
            manifest["last_updated_at"] = _now_iso()
            atomic_write_json(self.manifest_path, manifest)


# ---------------------------------------------------------------------------
# Module-level entry points
# ---------------------------------------------------------------------------


def start_run(
    run_id: str,
    *,
    results_dir: Path,
    target_url: str,
    target_version_sha: str | None = None,
    extra_metadata: dict[str, Any] | None = None,
) -> RunHandle:
    """Create the run directory + manifest. Idempotent if the manifest
    already matches the same target_url + schema_version — supports calling
    `start_run` from `resume_run` without clobbering existing state.
    """
    run_dir = Path(results_dir) / run_id
    handle = RunHandle(run_id=run_id, run_dir=run_dir)
    handle.attacks_dir.mkdir(parents=True, exist_ok=True)
    handle.verdicts_dir.mkdir(parents=True, exist_ok=True)
    handle.vulnerabilities_dir.mkdir(parents=True, exist_ok=True)

    if handle.manifest_path.exists():
        existing = handle.load_manifest()
        if existing.get("target_url") != target_url:
            raise PersistenceError(
                f"Run {run_id} already exists with target_url="
                f"{existing.get('target_url')!r}; cannot reuse for "
                f"{target_url!r}."
            )
        return handle

    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "run_id": run_id,
        "started_at": _now_iso(),
        "last_updated_at": _now_iso(),
        "target_url": target_url,
        "target_version_sha": target_version_sha,
        "attack_ids": [],
        "verdict_ids": [],
        "vuln_ids": [],
        "metadata": dict(extra_metadata or {}),
    }
    atomic_write_json(handle.manifest_path, manifest)
    return handle


def resume_run(run_id: str, *, results_dir: Path) -> RunHandle:
    """Open an existing run by id. Raises if no manifest exists."""
    run_dir = Path(results_dir) / run_id
    handle = RunHandle(run_id=run_id, run_dir=run_dir)
    handle.load_manifest()  # raises if missing or schema mismatch
    return handle


# ---------------------------------------------------------------------------
# Vulnerability-report rendering
# ---------------------------------------------------------------------------


def render_vuln_report(
    frontmatter: VulnerabilityReportFrontmatter, body_markdown: str
) -> str:
    """Render YAML frontmatter + body in the layout ARCH §12.4 prescribes.

    Uses PyYAML via json round-trip avoidance — we hand-roll the YAML here
    rather than depending on yaml.dump's quoting decisions, so the rendered
    file matches the ARCH §12.4 example byte-for-byte where it can.

    Public so the Documentation Agent (agents/documentation.py) can use it
    when writing canonical drafts to repo-root `evals/vulnerabilities/`
    without going through a per-run RunHandle.
    """
    fm = frontmatter.model_dump(mode="json")
    lines: list[str] = ["---"]
    lines.extend(_yaml_lines(fm, indent=0))
    lines.append("---")
    lines.append("")
    lines.append(body_markdown.rstrip() + "\n")
    return "\n".join(lines)


def _yaml_lines(value: Any, *, indent: int) -> list[str]:
    """Tiny YAML emitter for the subset we use in vuln-report frontmatter.

    Handles: dict[str, Any], list[Any], str, int, float, bool, None.
    Strings are emitted unquoted when safe, else double-quoted with escapes.
    """
    pad = "  " * indent
    if value is None:
        return ["null"]
    if isinstance(value, bool):
        return ["true" if value else "false"]
    if isinstance(value, (int, float)):
        return [str(value)]
    if isinstance(value, str):
        return [_yaml_scalar(value)]
    if isinstance(value, list):
        if not value:
            return ["[]"]
        out = []
        for item in value:
            sub_lines = _yaml_lines(item, indent=indent + 1)
            if isinstance(item, dict):
                out.append(f"{pad}-")
                out.extend(f"{pad}  {ln}" for ln in sub_lines)
            else:
                out.append(f"{pad}- {sub_lines[0]}")
                out.extend(f"{pad}  {ln}" for ln in sub_lines[1:])
        return out
    if isinstance(value, dict):
        out = []
        for k, v in value.items():
            sub = _yaml_lines(v, indent=indent + 1)
            if isinstance(v, (dict, list)) and v:
                out.append(f"{pad}{k}:")
                out.extend(sub)
            else:
                out.append(f"{pad}{k}: {sub[0]}")
        return out
    return [_yaml_scalar(str(value))]


def _yaml_scalar(value: str) -> str:
    """Quote a string for YAML if it contains characters that would parse
    ambiguously; otherwise emit unquoted."""
    needs_quoting = (
        not value
        or value[0] in "!&*-:?,[]{}#|>%@`\"'"
        or any(c in value for c in "\n:")
        or value.lower() in {"true", "false", "null", "yes", "no", "on", "off"}
    )
    if needs_quoting:
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return value


__all__ = [
    "ATTACKS_SUBDIR",
    "DuplicateArtifactError",
    "MANIFEST_FILENAME",
    "MANIFEST_SCHEMA_VERSION",
    "ManifestSchemaMismatchError",
    "PersistenceError",
    "RunHandle",
    "VERDICTS_SUBDIR",
    "VULNERABILITIES_SUBDIR",
    "atomic_write_bytes",
    "atomic_write_json",
    "atomic_write_text",
    "render_vuln_report",
    "resume_run",
    "start_run",
]
