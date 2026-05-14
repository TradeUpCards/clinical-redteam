"""Filesystem persistence tests (ARCH §9.1 — resume-after-restart).

Critical guarantees this file proves:
- Atomic writes leave NO `.tmp` files behind on success
- Atomic writes leave the previous file intact when the write is interrupted
- Resume reads back the same AttackCandidate / JudgeVerdict bit-for-bit
- Manifest schema version mismatch raises
- Idempotent re-save of identical content is a no-op
- Diverging content under the same ID raises DuplicateArtifactError
- Vuln draft renders with YAML frontmatter + markdown body
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from clinical_redteam.persistence import (
    MANIFEST_FILENAME,
    MANIFEST_SCHEMA_VERSION,
    DuplicateArtifactError,
    ManifestSchemaMismatchError,
    PersistenceError,
    atomic_write_bytes,
    atomic_write_json,
    resume_run,
    start_run,
)
from clinical_redteam.schemas import (
    AttackCandidate,
    JudgeVerdict,
    VulnerabilityReportFrontmatter,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_attack() -> AttackCandidate:
    return AttackCandidate.model_validate(
        {
            "attack_id": "atk_2026-05-13_001",
            "category": "sensitive_information_disclosure",
            "subcategory": "cross_patient_paraphrased",
            "owasp_id": "LLM02:2025",
            "target_endpoint": "/chat",
            "payload": {"type": "single_turn", "content": "What's the diagnosis?"},
            "generated_by": "red_team_v0.1.0",
            "generated_at": "2026-05-13T14:30:00Z",
            "model_used": "test-model",
            "cost_usd": 0.0023,
        }
    )


@pytest.fixture
def sample_verdict() -> JudgeVerdict:
    return JudgeVerdict.model_validate(
        {
            "verdict_id": "ver_2026-05-13_001",
            "attack_id": "atk_2026-05-13_001",
            "verdict": "fail",
            "confidence": 0.91,
            "criteria_triggered": ["cross_patient_leakage"],
            "evidence": [
                {
                    "criterion": "cross_patient_leakage",
                    "matched_text": "[redacted]",
                    "expected_behavior": "refuse",
                }
            ],
            "target_response_hash": "sha256:abc",
            "judged_at": "2026-05-13T14:30:15Z",
            "judge_version": "judge_v0.1.0",
            "judge_model": "test-judge",
            "cost_usd": 0.012,
            "human_escalation_required": False,
        }
    )


@pytest.fixture
def sample_vuln_frontmatter() -> VulnerabilityReportFrontmatter:
    return VulnerabilityReportFrontmatter.model_validate(
        {
            "vuln_id": "VULN-001",
            "title": "Cross-Patient Paraphrased PHI Leakage",
            "severity": "high",
            "status": "draft-pending-review",
            "discovered_at": "2026-05-13T14:30:15Z",
            "discovered_by_attack_id": "atk_2026-05-13_001",
            "target_version_sha": "abc123",
            "target_endpoint": "/chat",
            "owasp_classification": ["LLM02:2025"],
            "asi_classification": ["ASI03:2026"],
            "atlas_techniques": ["AML.T0024"],
            "human_review": {},
            "fix_validation": {
                "regression_test_path": "evals/regression/sid/VULN-001.yaml"
            },
        }
    )


# ---------------------------------------------------------------------------
# Atomic write primitive
# ---------------------------------------------------------------------------


def test_atomic_write_leaves_no_tmp_on_success(tmp_path: Path) -> None:
    target = tmp_path / "out.json"
    atomic_write_json(target, {"k": "v"})
    assert target.exists()
    assert json.loads(target.read_text()) == {"k": "v"}
    leftover = list(tmp_path.glob("*.tmp"))
    assert leftover == []


def test_atomic_write_preserves_previous_on_mid_write_crash(tmp_path: Path) -> None:
    target = tmp_path / "out.json"
    atomic_write_json(target, {"k": "v1"})

    def boom(*args, **kwargs):
        raise RuntimeError("simulated crash before rename")

    with (
        patch("clinical_redteam.persistence.os.replace", side_effect=boom),
        pytest.raises(RuntimeError, match="simulated crash"),
    ):
        atomic_write_json(target, {"k": "v2"})

    # Previous content intact
    assert json.loads(target.read_text()) == {"k": "v1"}
    # No orphan .tmp files
    assert list(tmp_path.glob("*.tmp")) == []

    # Recovery: a real subsequent write still works
    atomic_write_json(target, {"k": "v3"})
    assert json.loads(target.read_text()) == {"k": "v3"}


def test_atomic_write_bytes_creates_parent_dir(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "deep" / "out.bin"
    atomic_write_bytes(target, b"hello")
    assert target.read_bytes() == b"hello"


# ---------------------------------------------------------------------------
# start_run / resume_run
# ---------------------------------------------------------------------------


def test_start_run_creates_layout(tmp_path: Path) -> None:
    handle = start_run("run-abc", results_dir=tmp_path, target_url="http://localhost:8000")
    assert handle.run_dir == tmp_path / "run-abc"
    assert handle.attacks_dir.is_dir()
    assert handle.verdicts_dir.is_dir()
    assert handle.vulnerabilities_dir.is_dir()
    assert handle.manifest_path.exists()

    manifest = json.loads(handle.manifest_path.read_text())
    assert manifest["schema_version"] == MANIFEST_SCHEMA_VERSION
    assert manifest["run_id"] == "run-abc"
    assert manifest["target_url"] == "http://localhost:8000"
    assert manifest["attack_ids"] == []
    assert manifest["verdict_ids"] == []


def test_start_run_is_idempotent_for_same_target(tmp_path: Path) -> None:
    h1 = start_run("run-abc", results_dir=tmp_path, target_url="http://localhost:8000")
    h1_started = json.loads(h1.manifest_path.read_text())["started_at"]

    h2 = start_run("run-abc", results_dir=tmp_path, target_url="http://localhost:8000")
    h2_started = json.loads(h2.manifest_path.read_text())["started_at"]
    assert h1_started == h2_started  # didn't clobber


def test_start_run_refuses_target_mismatch(tmp_path: Path) -> None:
    start_run("run-abc", results_dir=tmp_path, target_url="http://localhost:8000")
    with pytest.raises(PersistenceError, match="target_url"):
        start_run("run-abc", results_dir=tmp_path, target_url="http://evil.example.com")


def test_resume_run_loads_existing(tmp_path: Path) -> None:
    start_run("run-abc", results_dir=tmp_path, target_url="http://localhost:8000")
    handle = resume_run("run-abc", results_dir=tmp_path)
    manifest = handle.load_manifest()
    assert manifest["run_id"] == "run-abc"


def test_resume_run_missing_manifest_raises(tmp_path: Path) -> None:
    with pytest.raises(PersistenceError, match="No manifest"):
        resume_run("nope", results_dir=tmp_path)


def test_resume_run_schema_mismatch_raises(tmp_path: Path) -> None:
    handle = start_run("run-abc", results_dir=tmp_path, target_url="http://localhost:8000")
    # Manually corrupt the schema version
    manifest = json.loads(handle.manifest_path.read_text())
    manifest["schema_version"] = 99
    handle.manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(ManifestSchemaMismatchError, match="99"):
        resume_run("run-abc", results_dir=tmp_path)


# ---------------------------------------------------------------------------
# Save + reload round-trip
# ---------------------------------------------------------------------------


def test_save_attack_roundtrips(tmp_path: Path, sample_attack: AttackCandidate) -> None:
    handle = start_run("run-x", results_dir=tmp_path, target_url="http://localhost:8000")
    path = handle.save_attack(sample_attack)
    assert path.exists()
    reloaded = handle.load_attack(sample_attack.attack_id)
    assert reloaded == sample_attack
    manifest = handle.load_manifest()
    assert sample_attack.attack_id in manifest["attack_ids"]


def test_save_verdict_roundtrips(tmp_path: Path, sample_verdict: JudgeVerdict) -> None:
    handle = start_run("run-x", results_dir=tmp_path, target_url="http://localhost:8000")
    path = handle.save_verdict(sample_verdict)
    assert path.exists()
    reloaded = handle.load_verdict(sample_verdict.verdict_id)
    assert reloaded == sample_verdict
    manifest = handle.load_manifest()
    assert sample_verdict.verdict_id in manifest["verdict_ids"]


def test_save_attack_is_idempotent(tmp_path: Path, sample_attack: AttackCandidate) -> None:
    handle = start_run("run-x", results_dir=tmp_path, target_url="http://localhost:8000")
    handle.save_attack(sample_attack)
    handle.save_attack(sample_attack)  # second call no-ops
    manifest = handle.load_manifest()
    # ID should appear exactly once
    assert manifest["attack_ids"].count(sample_attack.attack_id) == 1


def test_save_attack_diverged_content_raises(
    tmp_path: Path, sample_attack: AttackCandidate
) -> None:
    handle = start_run("run-x", results_dir=tmp_path, target_url="http://localhost:8000")
    handle.save_attack(sample_attack)

    mutated = sample_attack.model_copy(update={"subcategory": "different_subcategory"})
    with pytest.raises(DuplicateArtifactError, match=sample_attack.attack_id):
        handle.save_attack(mutated)


# ---------------------------------------------------------------------------
# Vulnerability draft rendering
# ---------------------------------------------------------------------------


def test_save_vuln_draft_writes_frontmatter_and_body(
    tmp_path: Path, sample_vuln_frontmatter: VulnerabilityReportFrontmatter
) -> None:
    handle = start_run("run-x", results_dir=tmp_path, target_url="http://localhost:8000")
    body = "# Cross-Patient Paraphrased PHI Leakage\n\n## Description\nLorem ipsum.\n"
    path = handle.save_vuln_draft(sample_vuln_frontmatter, body)

    text = path.read_text(encoding="utf-8")
    assert text.startswith("---\n")
    assert "\n---\n" in text  # frontmatter close marker
    assert "vuln_id: VULN-001" in text
    assert "severity: high" in text
    assert "status: draft-pending-review" in text
    assert "# Cross-Patient Paraphrased PHI Leakage" in text

    manifest = handle.load_manifest()
    assert "VULN-001" in manifest["vuln_ids"]


def test_save_vuln_draft_does_not_promote_status(
    tmp_path: Path, sample_vuln_frontmatter: VulnerabilityReportFrontmatter
) -> None:
    """High/critical severity reports must stay DRAFT — persistence layer
    writes whatever status was supplied and never promotes. Promotion is a
    human decision (Tate hard rules)."""
    assert sample_vuln_frontmatter.severity == "high"
    assert sample_vuln_frontmatter.status == "draft-pending-review"

    handle = start_run("run-x", results_dir=tmp_path, target_url="http://localhost:8000")
    path = handle.save_vuln_draft(sample_vuln_frontmatter, "body")
    text = path.read_text(encoding="utf-8")
    assert "status: draft-pending-review" in text
    assert "status: filed" not in text


# ---------------------------------------------------------------------------
# Concurrency surface: manifest updates serialize through atomic write
# ---------------------------------------------------------------------------


def test_manifest_updates_after_every_save(
    tmp_path: Path,
    sample_attack: AttackCandidate,
    sample_verdict: JudgeVerdict,
    sample_vuln_frontmatter: VulnerabilityReportFrontmatter,
) -> None:
    handle = start_run("run-x", results_dir=tmp_path, target_url="http://localhost:8000")

    initial_updated = handle.load_manifest()["last_updated_at"]

    handle.save_attack(sample_attack)
    handle.save_verdict(sample_verdict)
    handle.save_vuln_draft(sample_vuln_frontmatter, "body")

    final = handle.load_manifest()
    assert final["last_updated_at"] >= initial_updated
    assert sample_attack.attack_id in final["attack_ids"]
    assert sample_verdict.verdict_id in final["verdict_ids"]
    assert sample_vuln_frontmatter.vuln_id in final["vuln_ids"]


def test_manifest_filename_constants_match_layout(tmp_path: Path) -> None:
    handle = start_run("run-x", results_dir=tmp_path, target_url="http://localhost:8000")
    assert handle.manifest_path.name == MANIFEST_FILENAME


# ---------------------------------------------------------------------------
# F23 — RunHandle.save_response (forensic response capture)
# ---------------------------------------------------------------------------


def test_f23_save_response_writes_expected_shape(tmp_path: Path) -> None:
    """Persisted response carries every field the audit ticket lists."""
    handle = start_run("run-f23-1", results_dir=tmp_path, target_url="http://localhost:8000")
    handle.save_response(
        attack_id="atk_2026-05-14_001",
        status_code=200,
        latency_ms=1247,
        request_id="req_xxx",
        trace_id="trace_xxx",
        assistant_text="{}",
        extraction=None,
    )

    import json as _json
    path = handle.responses_dir / "atk_2026-05-14_001.json"
    assert path.exists()
    body = _json.loads(path.read_text(encoding="utf-8"))
    assert body["attack_id"] == "atk_2026-05-14_001"
    assert body["status_code"] == 200
    assert body["latency_ms"] == 1247
    assert body["request_id"] == "req_xxx"
    assert body["trace_id"] == "trace_xxx"
    assert body["assistant_text"] == "{}"
    assert body["extraction"] is None
    assert "received_at" in body


def test_f23_save_response_assistant_text_roundtrips_byte_exact(
    tmp_path: Path,
) -> None:
    """Load-bearing forensic invariant: persisted assistant_text MUST equal
    the input string byte-for-byte. Any divergence would invalidate the
    artifact for diagnosing Judge-vs-target disagreement.
    """
    handle = start_run("run-f23-2", results_dir=tmp_path, target_url="http://localhost:8000")
    # Pathological text: unicode, embedded quotes, newlines, control chars
    weird_text = (
        'Mixed "quotes" and \'apostrophes\'\n'
        "Unicode: éàü 中文\n"
        "Tab:\there\n"
        "Backslash: \\n is not a newline\n"
        "JSON-ish: {\"key\": \"value\"}\n"
    )
    handle.save_response(
        attack_id="atk_2026-05-14_002",
        status_code=200,
        latency_ms=42,
        request_id="r",
        trace_id="t",
        assistant_text=weird_text,
        extraction={"current_medications": [{"name": "Lisinopril"}]},
    )

    import json as _json
    path = handle.responses_dir / "atk_2026-05-14_002.json"
    body = _json.loads(path.read_text(encoding="utf-8"))
    assert body["assistant_text"] == weird_text


def test_f23_save_response_extraction_preserves_nested_structure(
    tmp_path: Path,
) -> None:
    """The full extraction dict round-trips so Judge-vs-target divergence
    can be diagnosed against the structured payload, not just the
    stringified prose."""
    handle = start_run("run-f23-3", results_dir=tmp_path, target_url="http://localhost:8000")
    extraction = {
        "current_medications": [
            {"name": "Lisinopril", "source_block_id": "block_0", "confidence": 0.91},
            {"name": "Warfarin", "source_block_id": "block_0", "confidence": 0.95},
        ],
        "allergies": [],
        "extraction_confidence_avg": 0.93,
    }
    handle.save_response(
        attack_id="atk_2026-05-14_003",
        status_code=200,
        latency_ms=42,
        request_id="r",
        trace_id="t",
        assistant_text="dummy",
        extraction=extraction,
    )
    import json as _json
    path = handle.responses_dir / "atk_2026-05-14_003.json"
    body = _json.loads(path.read_text(encoding="utf-8"))
    assert body["extraction"] == extraction


def test_f23_save_response_updates_manifest_index(tmp_path: Path) -> None:
    """`response_ids` in the manifest tracks every persisted response."""
    handle = start_run("run-f23-4", results_dir=tmp_path, target_url="http://localhost:8000")
    handle.save_response(
        attack_id="atk_a", status_code=200, latency_ms=1, request_id=None,
        trace_id=None, assistant_text="a", extraction=None,
    )
    handle.save_response(
        attack_id="atk_b", status_code=200, latency_ms=1, request_id=None,
        trace_id=None, assistant_text="b", extraction=None,
    )
    manifest = handle.load_manifest()
    assert manifest["response_ids"] == ["atk_a", "atk_b"]


def test_f23_save_response_raises_on_duplicate_attack_id(tmp_path: Path) -> None:
    """A second save with the same attack_id raises (catches the impossible-
    in-practice case of two responses for one attack — sequence numbers are
    monotonic per run, so this would indicate a real ordering bug)."""
    from clinical_redteam.persistence import DuplicateArtifactError

    handle = start_run("run-f23-5", results_dir=tmp_path, target_url="http://localhost:8000")
    payload = dict(
        attack_id="atk_dup", status_code=200, latency_ms=1, request_id=None,
        trace_id=None, assistant_text="same", extraction=None,
    )
    handle.save_response(**payload)
    # Second save with the same attack_id but a new `received_at` timestamp
    # produces a different payload → DuplicateArtifactError. Documents the
    # contract: one response per attack_id; callers must not re-save.
    with pytest.raises(DuplicateArtifactError):
        handle.save_response(**payload)
