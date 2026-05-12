# Week 3 Architecture & Threat Model Rewrite Recommendations

Overall direction: do not fully rewrite the architecture. The foundation is already strong. The goal is to tighten it into something that feels:

- more executable within the Week 3 timeframe
- more directly aligned to PRD grading criteria
- easier to defend verbally under pressure
- more obviously implementable as a real system

The current drafts read like a strong security architecture paper. The recommendation is to make them feel slightly more operational and execution-grounded.

---

# 1. Rewrite the Executive Summary to be Shorter and Sharper

The current executive summary is strong but dense. Reduce it by roughly 30–40%.

The revised summary should focus on:

- what the system does
- why multi-agent is necessary
- what is actually implemented in MVP
- what is intentionally deferred
- what trust boundaries exist

## Suggested Rewrite Direction

## Executive Summary

The Clinical Red Team Platform is a multi-agent adversarial evaluation system designed to continuously test the AgentForge Clinical Co-Pilot for prompt injection, PHI leakage, tool misuse, state corruption, and denial-of-service vulnerabilities. Unlike a static eval suite, the platform continuously generates, mutates, evaluates, and regression-tests attacks as the target system evolves.

The platform is composed of four agents with deliberately separated responsibilities:

- Red Team Agent generates and mutates attacks
- Judge Agent independently evaluates attack success
- Orchestrator Agent prioritizes coverage and controls cost
- Documentation Agent converts validated exploits into structured reports

This separation is intentional. An agent that both generates and evaluates attacks is biased by construction and cannot provide trustworthy regression validation.

The MVP implementation focuses on a narrow but complete vertical slice:

1. execute attacks against the deployed Co-Pilot
2. independently judge exploit success
3. persist reproducible regression cases
4. generate structured vulnerability reports

The platform initially targets three attack categories:

- prompt injection
- cross-patient PHI leakage
- document-based indirect injection

Known finding `C-7` from Week 2 is intentionally used as the platform’s first rediscovery target to validate that the system can autonomously reproduce a real previously-confirmed vulnerability before attempting novel exploit discovery.

The system operates under explicit trust boundaries:

- no autonomous remediation
- no autonomous production changes
- human approval required for high-severity findings
- bounded token and runtime budgets enforced by the Orchestrator

---

# 2. Add a “What is Actually Built vs Planned” Section

This is probably the single highest-value addition.

Right now the docs blur architecture vision and MVP implementation.

Add a dedicated section clarifying:

- what exists in MVP
- what is intentionally deferred
- what is stretch/future scope

## Suggested Structure

# MVP Scope (Week 3)

## Implemented in MVP

- deployed target integration
- attack execution runner
- attack mutation engine (basic variants)
- independent judge flow
- regression case persistence
- structured vulnerability reports
- Langfuse observability
- three attack categories

## Deferred Beyond MVP

- autonomous exploit chaining
- self-improving attack strategies
- distributed fuzzing
- automated remediation suggestions
- local fine-tuned attack models
- reinforcement-learning-based prioritization

This communicates discipline and scope control.

---

# 3. Add Explicit Inter-Agent Schemas

The architecture currently describes inputs and outputs conceptually.

Add concrete JSON contracts.

## Example: AttackCandidate

```json
{
  "attack_id": "atk_00123",
  "category": "prompt_injection",
  "target_endpoint": "/graph_chat",
  "payload": "...",
  "conversation_state": [],
  "mutation_parent": "atk_00110"
}
```

## Example: JudgeVerdict

```json
{
  "verdict": "fail",
  "confidence": 0.93,
  "criteria_triggered": [
    "cross_patient_leakage"
  ],
  "evidence": []
}
```

Additional suggested schemas:

- CoverageState
- VulnerabilityReport
- RegressionCase
- AgentTrace

This increases perceived engineering maturity substantially.

---

# 4. Add an Explicit “Why Multi-Agent?” Section

The PRD strongly emphasizes that this must be a true multi-agent system.

Make the justification explicit rather than implied.

## Suggested Section

# Why a Multi-Agent Architecture is Required

This problem cannot be solved reliably with a single-agent architecture because attack generation, exploit evaluation, orchestration, and reporting have conflicting incentives and different trust requirements.

| Responsibility | Why Separate |
|---|---|
| Red Team | incentivized to maximize exploit discovery |
| Judge | must remain unbiased and deterministic |
| Orchestrator | optimizes coverage, runtime, and cost |
| Documentation | transforms validated findings into human-consumable reports |

Combining these roles introduces bias, weakens regression guarantees, and reduces observability into system behavior under adversarial pressure.

---

# 5. Simplify Framework Density

The current draft references:

- OWASP LLM Top 10
- OWASP ASI
- MITRE ATLAS
- NIST AI RMF
- HHS AI Strategy

This is strong, but risks feeling framework-heavy for a one-week build.

Recommended:

## Keep Primary Focus On

- OWASP LLM Top 10
- MITRE ATLAS
- brief NIST mention

## Reduce Emphasis On

- OWASP ASI unless actively testing inter-agent compromise
- excessive governance discussion

The goal is to avoid “framework accumulation.”

---

# 6. Add an Attack Lifecycle Diagram

The architecture diagrams are strong, but the docs need a runtime execution flow.

## Suggested Diagram

```text
Red Team Agent
    ↓
Target Co-Pilot
    ↓
Judge Agent
    ↓
Exploit confirmed?
    ↓ yes
Regression Store
    ↓
Documentation Agent
    ↓
Human approval
```

This helps significantly during architecture defense discussions.

---

# 7. Add Explicit Evaluation Metrics

The PRD heavily emphasizes evaluation and regression.

Add measurable metrics.

## Suggested Metrics

- attack success rate
- coverage by attack category
- judge agreement rate
- mutation yield
- regression pass/fail rate
- cost per successful exploit
- time-to-rediscovery
- exploit reproducibility rate

This strengthens both the observability and regression sections.

---

# 8. Add “Failure Modes of the Platform Itself”

This addition would differentiate the architecture significantly.

## Suggested Failure Modes

- Judge hallucination
- adversarial poisoning of regression corpus
- infinite mutation loops
- coordinated agent drift
- exploit deduplication failures
- Red Team discovering platform exploits instead of target exploits
- runaway token spend
- evaluator collapse (everything becomes pass/fail)

## Suggested Mitigations

- human escalation thresholds
- bounded recursion depth
- token/runtime ceilings
- regression corpus versioning
- independent model providers
- exploit deduplication hashing
- replay validation

This demonstrates strong systems thinking.

---

# 9. Strongest Existing Architectural Decisions (Do NOT Remove)

These are among the strongest aspects of the current architecture and should remain central:

## Keep

- known vulnerability rediscovery strategy
- bounded autonomy discussion
- explicit trust boundaries
- independent judge architecture
- regression-first philosophy
- separation between attack generation and evaluation

Especially retain the core principle:

> a system that both generates and judges attacks is compromised by design

That is one of the strongest and most defensible architectural statements in the current draft.

---

# 10. Most Important Strategic Recommendation

The biggest risk is not architectural weakness.

The biggest risk is over-scoping implementation.

Prioritize building a clean vertical slice:

```text
Red Team seed/mutation
    ↓
live target execution
    ↓
Judge verdict
    ↓
saved regression case
    ↓
draft vulnerability report
```

If this flow works end-to-end with observability and reproducibility, the architecture will feel real and defensible even if advanced features remain deferred.

