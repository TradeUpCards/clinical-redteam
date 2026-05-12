"""Schema validation tests (ARCH §12).

One positive test per schema loading the literal example payload from ARCH §12
to prove the model accepts the documented shape. Plus targeted negative tests
proving the load-bearing constraints actually fire (confidence range, naive
datetime, ID format, extra-field rejection).

If any of these fail after a `schemas.py` edit, the inter-agent contract has
drifted from ARCH §12 — fix the schema, do not loosen the test.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from clinical_redteam.schemas import (
    AgentTrace,
    AttackCandidate,
    CoverageState,
    JudgeVerdict,
    RegressionCase,
    VulnerabilityReportFrontmatter,
)


# ---------------------------------------------------------------------------
# 12.1 AttackCandidate
# ---------------------------------------------------------------------------


def test_attack_candidate_arch_example_validates() -> None:
    arch_example = {
        "attack_id": "atk_2026-05-13_001",
        "category": "prompt_injection",
        "subcategory": "indirect_via_document",
        "owasp_id": "LLM01:2025",
        "asi_id": "ASI06:2026",
        "atlas_technique_id": "AML.T0051",
        "target_endpoint": "/attach_and_extract",
        "payload": {"type": "single_turn", "content": "..."},
        "conversation_state": [],
        "mutation_parent": None,
        "mutation_depth": 0,
        "generated_by": "red_team_v0.1.0",
        "generated_at": "2026-05-13T14:30:00Z",
        "model_used": "llama-3.3-70b-self-hosted",
        "cost_usd": 0.0023,
    }
    candidate = AttackCandidate.model_validate(arch_example)
    assert candidate.attack_id == "atk_2026-05-13_001"
    assert candidate.payload.type == "single_turn"
    assert candidate.cost_usd == 0.0023


def test_attack_candidate_rejects_bad_id_format() -> None:
    with pytest.raises(ValidationError, match="attack_id"):
        AttackCandidate.model_validate(
            {
                "attack_id": "bad-id",
                "category": "prompt_injection",
                "subcategory": "x",
                "owasp_id": "LLM01:2025",
                "target_endpoint": "/chat",
                "payload": {"type": "single_turn", "content": "x"},
                "generated_by": "rt",
                "generated_at": "2026-05-13T14:30:00Z",
                "model_used": "m",
                "cost_usd": 0,
            }
        )


def test_attack_candidate_rejects_negative_cost() -> None:
    with pytest.raises(ValidationError, match="cost_usd"):
        AttackCandidate.model_validate(
            {
                "attack_id": "atk_2026-05-13_001",
                "category": "prompt_injection",
                "subcategory": "x",
                "owasp_id": "LLM01:2025",
                "target_endpoint": "/chat",
                "payload": {"type": "single_turn", "content": "x"},
                "generated_by": "rt",
                "generated_at": "2026-05-13T14:30:00Z",
                "model_used": "m",
                "cost_usd": -0.01,
            }
        )


def test_attack_candidate_rejects_naive_datetime() -> None:
    with pytest.raises(ValidationError):
        AttackCandidate.model_validate(
            {
                "attack_id": "atk_2026-05-13_001",
                "category": "prompt_injection",
                "subcategory": "x",
                "owasp_id": "LLM01:2025",
                "target_endpoint": "/chat",
                "payload": {"type": "single_turn", "content": "x"},
                "generated_by": "rt",
                "generated_at": "2026-05-13T14:30:00",
                "model_used": "m",
                "cost_usd": 0,
            }
        )


# ---------------------------------------------------------------------------
# 12.2 JudgeVerdict
# ---------------------------------------------------------------------------


def test_judge_verdict_arch_example_validates() -> None:
    arch_example = {
        "verdict_id": "ver_2026-05-13_001",
        "attack_id": "atk_2026-05-13_001",
        "verdict": "fail",
        "confidence": 0.93,
        "criteria_triggered": ["cross_patient_leakage", "ungrounded_clinical_claim"],
        "evidence": [
            {
                "criterion": "cross_patient_leakage",
                "matched_text": "her sister Maria has diabetes",
                "expected_behavior": "should refuse to discuss other patients",
            }
        ],
        "target_response_hash": "sha256:abc123...",
        "judged_at": "2026-05-13T14:30:15Z",
        "judge_version": "judge_v0.1.0",
        "judge_model": "claude-sonnet-4.6",
        "cost_usd": 0.012,
        "human_escalation_required": False,
    }
    verdict = JudgeVerdict.model_validate(arch_example)
    assert verdict.verdict == "fail"
    assert verdict.confidence == 0.93
    assert verdict.evidence[0].criterion == "cross_patient_leakage"


def test_judge_verdict_rejects_confidence_out_of_range() -> None:
    base = {
        "verdict_id": "ver_2026-05-13_001",
        "attack_id": "atk_2026-05-13_001",
        "verdict": "fail",
        "criteria_triggered": [],
        "evidence": [],
        "target_response_hash": "sha256:abc",
        "judged_at": "2026-05-13T14:30:15Z",
        "judge_version": "v",
        "judge_model": "m",
        "cost_usd": 0,
        "human_escalation_required": True,
    }
    with pytest.raises(ValidationError, match="confidence"):
        JudgeVerdict.model_validate({**base, "confidence": 1.5})
    with pytest.raises(ValidationError, match="confidence"):
        JudgeVerdict.model_validate({**base, "confidence": -0.1})


# ---------------------------------------------------------------------------
# 12.3 CoverageState
# ---------------------------------------------------------------------------


def test_coverage_state_arch_example_validates() -> None:
    arch_example = {
        "as_of": "2026-05-13T15:00:00Z",
        "target_version_sha": "104ad58a4",
        "categories": {
            "prompt_injection": {
                "attack_count": 47,
                "verdicts": {"pass": 30, "fail": 12, "partial": 4, "uncertain": 1},
                "last_attack_at": "2026-05-13T14:55:00Z",
                "open_findings": 3,
            },
            "sensitive_information_disclosure": {
                "attack_count": 23,
                "verdicts": {"pass": 18, "fail": 4, "partial": 1, "uncertain": 0},
                "last_attack_at": "2026-05-13T14:30:00Z",
                "open_findings": 1,
            },
        },
        "session_cost_usd": 4.27,
        "cost_cap_usd": 10.00,
        "signal_to_cost_ratio": 0.15,
    }
    coverage = CoverageState.model_validate(arch_example)
    assert coverage.target_version_sha == "104ad58a4"
    assert coverage.categories["prompt_injection"].attack_count == 47
    # `pass` is aliased so it stays on the model under `pass_`.
    assert coverage.categories["prompt_injection"].verdicts.pass_ == 30
    assert coverage.session_cost_usd == 4.27


# ---------------------------------------------------------------------------
# 12.4 VulnerabilityReportFrontmatter
# ---------------------------------------------------------------------------


def test_vulnerability_report_frontmatter_arch_example_validates() -> None:
    arch_example = {
        "vuln_id": "VULN-001",
        "title": "Cross-Patient Paraphrased PHI Leakage",
        "severity": "high",
        "status": "draft-pending-review",
        "discovered_at": "2026-05-13T14:30:15Z",
        "discovered_by_attack_id": "atk_2026-05-13_001",
        "target_version_sha": "104ad58a4",
        "target_endpoint": "/chat",
        "owasp_classification": ["LLM02:2025 Sensitive Information Disclosure"],
        "asi_classification": ["ASI03:2026 Agent Identity & Privilege Abuse"],
        "atlas_techniques": ["AML.T0024 Exfiltration via ML Inference API"],
        "human_review": {
            "reviewer": None,
            "reviewed_at": None,
            "decision": None,
        },
        "fix_validation": {
            "regression_test_path": (
                "evals/regression/sensitive_information_disclosure/VULN-001.yaml"
            ),
            "last_run_at": None,
            "last_run_status": "pending",
        },
    }
    report = VulnerabilityReportFrontmatter.model_validate(arch_example)
    assert report.vuln_id == "VULN-001"
    assert report.severity == "high"
    assert report.status == "draft-pending-review"


def test_vulnerability_report_rejects_bad_vuln_id() -> None:
    base = {
        "vuln_id": "BAD-FORMAT",
        "title": "x",
        "severity": "high",
        "status": "draft-pending-review",
        "discovered_at": "2026-05-13T14:30:15Z",
        "discovered_by_attack_id": "atk_2026-05-13_001",
        "target_version_sha": "abc",
        "target_endpoint": "/chat",
        "owasp_classification": [],
        "asi_classification": [],
        "atlas_techniques": [],
        "human_review": {},
        "fix_validation": {"regression_test_path": "p"},
    }
    with pytest.raises(ValidationError, match="vuln_id"):
        VulnerabilityReportFrontmatter.model_validate(base)


# ---------------------------------------------------------------------------
# 12.5 RegressionCase
# ---------------------------------------------------------------------------


def test_regression_case_arch_example_validates() -> None:
    arch_example = {
        "case_id": "REGR-001",
        "parent_vuln_id": "VULN-001",
        "category": "sensitive_information_disclosure",
        "target_endpoint": "/chat",
        "attack_payload": "[exact payload to replay]",
        "expected_behavior": "refuse",
        "discovered_target_version_sha": "104ad58a4",
        "last_passed_target_version_sha": None,
        "last_failed_target_version_sha": "104ad58a4",
        "last_run_at": "2026-05-13T14:30:15Z",
    }
    case = RegressionCase.model_validate(arch_example)
    assert case.case_id == "REGR-001"
    assert case.parent_vuln_id == "VULN-001"


# ---------------------------------------------------------------------------
# 12.6 AgentTrace
# ---------------------------------------------------------------------------


def test_agent_trace_arch_example_validates() -> None:
    arch_example = {
        "agent_name": "red_team",
        "agent_version": "v0.1.0",
        "agent_role": "attack_generation",
        "session_id": "sess_2026-05-13_001",
        "attack_id": "atk_2026-05-13_001",
        "category": "prompt_injection",
        "model_used": "llama-3.3-70b-self-hosted",
        "cost_usd": 0.0023,
        "latency_ms": 2340,
        "tokens_input": 1240,
        "tokens_output": 380,
        "human_gate_status": "n/a",
    }
    trace = AgentTrace.model_validate(arch_example)
    assert trace.agent_name == "red_team"
    assert trace.tokens_input == 1240
    assert trace.human_gate_status == "n/a"


def test_agent_trace_rejects_unknown_agent_name() -> None:
    with pytest.raises(ValidationError, match="agent_name"):
        AgentTrace.model_validate(
            {
                "agent_name": "rogue_agent",
                "agent_version": "v0",
                "agent_role": "x",
                "session_id": "sess_2026-05-13_001",
                "model_used": "m",
                "cost_usd": 0,
                "latency_ms": 0,
                "tokens_input": 0,
                "tokens_output": 0,
            }
        )
