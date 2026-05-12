"""Inter-agent message schemas (ARCH §12).

Load-bearing contract between Red Team / Judge / Orchestrator / Documentation
agents. Every external call serializes through these models so behavior is
verifiable across the agent boundary. Schema changes require user /
architecture sign-off (Tate hard rules).

Field names and structure mirror ARCH §12 examples exactly; any divergence is
a bug, not a refinement.
"""

from __future__ import annotations

from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Shared aliases
# ---------------------------------------------------------------------------

Category = Literal[
    "sensitive_information_disclosure",
    "prompt_injection",
    "unbounded_consumption",
]
"""MVP attack categories (ARCH §9.4). Multi-turn variants live inside the
payload, not as separate categories."""

Verdict = Literal["pass", "fail", "partial", "uncertain"]
"""Judge verdict states (ARCH §12.2)."""

Severity = Literal["low", "medium", "high", "critical"]
"""Vulnerability severity (ARCH §12.4). High + critical stay DRAFT pending
human review — Documentation Agent does NOT auto-promote."""

ReportStatus = Literal[
    "draft-pending-review",
    "filed",
    "resolved",
    "wontfix",
]

HumanGateStatus = Literal["n/a", "pending", "approved", "rejected"]


# ---------------------------------------------------------------------------
# 12.1 AttackCandidate
# ---------------------------------------------------------------------------


class Turn(BaseModel):
    """One conversational turn within a multi-turn attack payload."""

    model_config = ConfigDict(extra="forbid")

    role: Literal["user", "assistant", "system", "tool"]
    content: str


class Payload(BaseModel):
    """Attack payload — either single-turn `content` or multi-turn `turns`.

    MVP supports `single_turn` only per ARCH §9.4; `multi_turn` is Phase 2.
    """

    model_config = ConfigDict(extra="forbid")

    type: Literal["single_turn", "multi_turn"]
    content: str | None = None
    turns: list[Turn] | None = None


class AttackCandidate(BaseModel):
    """Red Team Agent → Target client → Judge Agent."""

    model_config = ConfigDict(extra="forbid")

    attack_id: str = Field(pattern=r"^atk_\d{4}-\d{2}-\d{2}_\d{3,}$")
    category: Category
    subcategory: str
    owasp_id: str
    asi_id: str | None = None
    atlas_technique_id: str | None = None
    target_endpoint: str
    payload: Payload
    conversation_state: list[Turn] = Field(default_factory=list)
    mutation_parent: str | None = None
    mutation_depth: int = Field(default=0, ge=0)
    generated_by: str
    generated_at: AwareDatetime
    model_used: str
    cost_usd: float = Field(ge=0)


# ---------------------------------------------------------------------------
# 12.2 JudgeVerdict
# ---------------------------------------------------------------------------


class Evidence(BaseModel):
    """One piece of evidence the Judge cites for a triggered criterion."""

    model_config = ConfigDict(extra="forbid")

    criterion: str
    matched_text: str
    expected_behavior: str


class JudgeVerdict(BaseModel):
    """Judge Agent → Orchestrator / Documentation Agent.

    `human_escalation_required` is True when confidence < threshold OR when
    `criteria_triggered` is empty but verdict is non-pass (anomalous).
    """

    model_config = ConfigDict(extra="forbid")

    verdict_id: str = Field(pattern=r"^ver_\d{4}-\d{2}-\d{2}_\d{3,}$")
    attack_id: str = Field(pattern=r"^atk_\d{4}-\d{2}-\d{2}_\d{3,}$")
    verdict: Verdict
    confidence: float = Field(ge=0, le=1)
    criteria_triggered: list[str]
    evidence: list[Evidence]
    target_response_hash: str = Field(pattern=r"^sha256:[0-9a-fA-F]+(\.\.\.)?$")
    judged_at: AwareDatetime
    judge_version: str
    judge_model: str
    cost_usd: float = Field(ge=0)
    human_escalation_required: bool


# ---------------------------------------------------------------------------
# 12.3 CoverageState
# ---------------------------------------------------------------------------


class VerdictCounts(BaseModel):
    """Per-category verdict tally. All four states keyed even when zero.

    `pass` is a Python keyword so the model field is `pass_`. `populate_by_name`
    means both the alias (`pass` — what ARCH §12.3 example uses on the wire)
    AND the field name (`pass_` — what model_dump emits by default) are accepted
    on validation. Round-tripping through `.model_dump()` → `.model_validate()`
    works without callers having to remember `by_alias=True`.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    pass_: int = Field(default=0, ge=0, alias="pass")
    fail: int = Field(default=0, ge=0)
    partial: int = Field(default=0, ge=0)
    uncertain: int = Field(default=0, ge=0)


class CategoryCoverage(BaseModel):
    """Coverage stats for one attack category."""

    model_config = ConfigDict(extra="forbid")

    attack_count: int = Field(ge=0)
    verdicts: VerdictCounts
    last_attack_at: AwareDatetime | None = None
    open_findings: int = Field(ge=0)


class CoverageState(BaseModel):
    """Read by Orchestrator to pick the next attack target (ARCH §3.6.1)."""

    model_config = ConfigDict(extra="forbid")

    as_of: AwareDatetime
    target_version_sha: str
    categories: dict[str, CategoryCoverage]
    session_cost_usd: float = Field(ge=0)
    cost_cap_usd: float = Field(ge=0)
    signal_to_cost_ratio: float = Field(ge=0)


# ---------------------------------------------------------------------------
# 12.4 VulnerabilityReport (frontmatter only; markdown body lives in the file)
# ---------------------------------------------------------------------------


class HumanReview(BaseModel):
    """Human review block on a vuln report — gated for severity ∈ {high, critical}."""

    model_config = ConfigDict(extra="forbid")

    reviewer: str | None = None
    reviewed_at: AwareDatetime | None = None
    decision: Literal["approved", "rejected", "needs_revision"] | None = None


class FixValidation(BaseModel):
    """Regression-test linkage for the vulnerability."""

    model_config = ConfigDict(extra="forbid")

    regression_test_path: str
    last_run_at: AwareDatetime | None = None
    last_run_status: Literal["pending", "passed", "failed"] = "pending"


class VulnerabilityReportFrontmatter(BaseModel):
    """YAML frontmatter for `evals/vulnerabilities/VULN-NNN-*.md` (ARCH §12.4).

    The markdown body (Description / Clinical Impact / Repro / Remediation)
    lives below the frontmatter in the file itself — not modeled here.
    """

    model_config = ConfigDict(extra="forbid")

    vuln_id: str = Field(pattern=r"^VULN-\d{3,}$")
    title: str
    severity: Severity
    status: ReportStatus
    discovered_at: AwareDatetime
    discovered_by_attack_id: str = Field(pattern=r"^atk_\d{4}-\d{2}-\d{2}_\d{3,}$")
    target_version_sha: str
    target_endpoint: str
    owasp_classification: list[str]
    asi_classification: list[str]
    atlas_techniques: list[str]
    human_review: HumanReview
    fix_validation: FixValidation


# ---------------------------------------------------------------------------
# 12.5 RegressionCase
# ---------------------------------------------------------------------------


class RegressionCase(BaseModel):
    """One regression case re-run on every target version change (ARCH §12.5).

    Differentiates 'fixed' from 'behavior-changed-suspicious' per §4.3.
    """

    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(pattern=r"^REGR-\d{3,}$")
    parent_vuln_id: str = Field(pattern=r"^VULN-\d{3,}$")
    category: Category
    target_endpoint: str
    attack_payload: str
    expected_behavior: str
    discovered_target_version_sha: str
    last_passed_target_version_sha: str | None = None
    last_failed_target_version_sha: str | None = None
    last_run_at: AwareDatetime | None = None


# ---------------------------------------------------------------------------
# 12.6 AgentTrace (Langfuse span attributes)
# ---------------------------------------------------------------------------


class AgentTrace(BaseModel):
    """Data substrate the Orchestrator reads to make routing decisions (ARCH §5)."""

    model_config = ConfigDict(extra="forbid")

    agent_name: Literal["red_team", "judge", "orchestrator", "documentation"]
    agent_version: str
    agent_role: str
    session_id: str = Field(pattern=r"^sess_\d{4}-\d{2}-\d{2}_\d{3,}$")
    attack_id: str | None = None
    category: Category | None = None
    model_used: str
    cost_usd: float = Field(ge=0)
    latency_ms: int = Field(ge=0)
    tokens_input: int = Field(ge=0)
    tokens_output: int = Field(ge=0)
    human_gate_status: HumanGateStatus = "n/a"


__all__ = [
    "AgentTrace",
    "AttackCandidate",
    "Category",
    "CategoryCoverage",
    "CoverageState",
    "Evidence",
    "FixValidation",
    "HumanGateStatus",
    "HumanReview",
    "JudgeVerdict",
    "Payload",
    "RegressionCase",
    "ReportStatus",
    "Severity",
    "Turn",
    "Verdict",
    "VerdictCounts",
    "VulnerabilityReportFrontmatter",
]
