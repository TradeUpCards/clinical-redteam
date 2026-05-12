# Clinical Red Team Platform — Architecture

**Project:** Multi-agent adversarial AI security platform for continuously identifying, evaluating, and defending against attacks on the AgentForge Clinical Co-Pilot.
**Status:** Architecture defense draft (2026-05-11). Updated as Phase 2 build progresses.
**Target system:** AgentForge Clinical Co-Pilot at `https://142-93-242-40.nip.io` (deployed; see [companion repo](https://github.com/TradeUpCards/agentforge)).

---

## Executive Summary

The Clinical Red Team Platform is a multi-agent adversarial evaluation system designed for **continuous, unattended operation** against the AgentForge Clinical Co-Pilot — sustained adversarial pressure that adapts as the target evolves, without a human in the loop for every step. Continuous operation is the PRD's central commitment (*"a system of agents that can hunt, evaluate, escalate, and document vulnerabilities continuously"* — PRD p. 3); a static test suite explicitly does not satisfy this assignment.

Continuous operation does not require distributed infrastructure. The platform runs as a single long-running Python daemon process — `while True:` loop driven by the Orchestrator, with hard cost guards, signal-to-cost halt conditions, filesystem-checkpointed state, drift detection on the Judge over time, and graceful resume after restart. Slow-and-steady continuous coverage on one machine is a valid implementation of "continuous" — throughput parallelism via Redis-fronted worker fleets is a Phase 3 scaling concern, not a continuity concern.

The platform is composed of four agents with deliberately separated responsibilities:

- **Red Team Agent** generates and mutates attacks
- **Judge Agent** independently evaluates attack success
- **Orchestrator Agent** prioritizes coverage and controls cost
- **Documentation Agent** converts validated exploits into structured reports

This separation is intentional: **a system that both generates and judges attacks is compromised by design**. Independence between attack generation and evaluation, bounded autonomy with explicit cost guards, and a regression-first evaluation philosophy (every confirmed exploit becomes a deterministic regression test) are the three load-bearing architectural commitments.

**MVP (Tuesday) demonstrates continuous-mode operation end-to-end** — the Orchestrator drives an unattended `while True:` loop that picks categories, dispatches Red Team mutation, evaluates via Judge, persists regression cases, drafts vulnerability reports, and halts cleanly on resource bounds (cost cap, signal-to-cost ratio collapse, or all-categories-at-floor). Engineer kicks off the daemon; daemon runs autonomously until it halts itself. The vertical slice — Red Team seed/mutation → live target call → Judge verdict → saved regression case → draft vulnerability report — is the unit of work the loop repeats. Three attack categories: **sensitive information disclosure (cross-patient PHI leakage)**, **prompt injection (including document-based indirect)**, and **unbounded consumption (cost amplification)**. Known finding `C-7` from Week 2 (cross-patient paraphrased leakage, currently HIGH-severity deferred in the Co-Pilot's `AUDIT.md`) is the platform's first rediscovery target — proving the system can autonomously reproduce a real previously-confirmed vulnerability before chasing novel exploits. See §9.4 for the full MVP scope.

**Intentionally deferred beyond MVP** (full list in §9.4): Orchestrator autonomous category-picking, multi-turn attack sequences, ground-truth Judge calibration, autonomous filing of high/critical reports, exploit chaining, self-improving attack strategies, distributed fuzzing, RL-based prioritization. Right-sizing is a feature, not a bug.

The system operates under explicit trust boundaries (§7): no autonomous remediation, no autonomous production changes, human approval required for high and critical findings before filing, bounded token and runtime budgets enforced by the Orchestrator, and an audit log of every autonomous action. The platform anchors on established frameworks rather than inventing taxonomy: **OWASP LLM Top 10 v2025** (attack surface of the target), **OWASP ASI Top 10 2026** (security posture of this autonomous multi-agent platform itself), **MITRE ATLAS** (per-attack technique IDs), and **NIST AI RMF** (governance lens), with healthcare context grounded in **HHS AI Strategy**. A hospital CISO deciding whether to trust this platform with continuous security testing speaks the language these frameworks already provide; that is the bar this document is built to.

The platform builds on existing W2 assets rather than starting from scratch: a deployed live target at `https://142-93-242-40.nip.io`, a 67-case Co-Pilot eval suite seeded into the Red Team Agent's mutation engine, a documented C-7 finding for first-rediscovery validation, a Langfuse observability stack already wired for LLM tracing, and the per-rubric regression-coverage matrix from `EVAL_SUITE.md §8.6` (companion repo) that empirically proved the Co-Pilot's own PR-blocking gate fires on injected regressions per rubric.

---

## PRD Gate Mapping (quick reference for graders)

| PRD requirement | Where addressed |
|---|---|
| Multi-agent architecture (single-agent doesn't satisfy) | §0 (Why Multi-Agent), §1 (system diagram), §2 (per-agent specs) |
| Attack surface map | `THREAT_MODEL.md` §1-4 |
| At least 3 attack categories with seed cases | §9.4 + `THREAT_MODEL.md` §4 (priority ranking) |
| Working prototype of one agent role running live against deployed target | §9.4 (MVP Scope vertical slice) |
| Eval results in `./evals/` | `evals/results/` (Phase 2 build per §9.4) |
| At least 3 vulnerability reports | `evals/vulnerabilities/` (VULN-001 = C-7 rediscovery; format spec in §12.4) |
| Trust boundaries + human approval gates | §7 (audit trail; NIST AI RMF function mapping in §7.4) |
| Cost analysis at 100 / 1K / 10K / 100K test runs | `docs/cost-analysis.md` (Phase 2; methodology in §8) |
| Failure mode analysis ("testing the tester") | §10 + recursion answer in §10.2 |
| Inter-agent message contracts | §12 (concrete JSON schemas) |
| Framework anchoring (no invented taxonomy) | §6 + `THREAT_MODEL.md` §2-3 |

---

## 0. Why a Multi-Agent Architecture is Required

This problem cannot be solved reliably with a single-agent or pipeline architecture because attack generation, exploit evaluation, orchestration, and reporting have **conflicting incentives** and **different trust requirements**.

| Responsibility | Why it must be a separate agent |
|---|---|
| **Red Team** | Incentivized to maximize exploit discovery (creative novelty, mutation pressure). A single combined agent that also judges its own work cannot maintain unbiased pass/fail criteria. |
| **Judge** | Must remain unbiased and deterministic; cannot also be optimizing for "find new attacks." Different model providers where practical, to reduce shared failure modes. Never sees Red Team's hypothesis until after rendering verdict. |
| **Orchestrator** | Optimizes for coverage, runtime, and cost. Different decision substrate (structured state) than the Red Team's (natural language attack generation). Conflating them weakens both. |
| **Documentation** | Transforms validated findings into human-consumable reports. A Documentation Agent that also generates attacks would conflate "what looks good in a report" with "what actually exploits." |

Combining these roles introduces bias, weakens regression guarantees, and reduces observability into system behavior under adversarial pressure. The PRD captures this as: *"a system that does both [generates and evaluates attacks] in the same context has a conflict of interest by design."* This document treats that as a constraint, not a suggestion.

---

## 1. The Multi-Agent System — at a glance

```
                              ┌───────────────────────────────────┐
                              │        TARGET (read-only)         │
                              │  AgentForge Clinical Co-Pilot     │
                              │  https://142-93-242-40.nip.io     │
                              │  (LangGraph supervisor + workers; │
                              │   agentic, NOT autonomous —       │
                              │   HITL approve gate on writes)    │
                              └────────────▲──────────────────────┘
                                           │
                                  HMAC-signed HTTP
                                  /chat, /graph_chat,
                                  /attach_and_extract
                                           │
   ┌───────────────────────────────────────┴──────────────────────────────────────┐
   │                                                                              │
   │          CLINICAL RED TEAM PLATFORM (autonomous multi-agent)                 │
   │                                                                              │
   │   ┌─────────────────┐         ┌─────────────────┐                            │
   │   │  Red Team       │ attack  │  Target         │ response                   │
   │   │  Agent          ├────────▶│  (proxy)        ├────────────┐               │
   │   │                 │         │                 │            │               │
   │   │  • Novel attack │         │  Per-PRD: HMAC  │            │               │
   │   │    generation   │         │  + sentinel-pid │            │               │
   │   │  • Mutation of  │         │  + ACL gate     │            ▼               │
   │   │    partial wins │         │                 │      ┌─────────────────┐   │
   │   │  • Multi-turn   │         └─────────────────┘      │  Judge Agent    │   │
   │   │    sequences    │                                  │                 │   │
   │   └────────▲────────┘                                  │  • Evaluates    │   │
   │            │                                           │    pass/fail/   │   │
   │            │ next attack                               │    partial      │   │
   │            │ category                                  │  • Independent  │   │
   │            │                                           │    of Red Team  │   │
   │   ┌────────┴────────┐                                  │  • Calibrated   │   │
   │   │  Orchestrator   │◀──── verdicts + coverage ────────┤    vs ground    │   │
   │   │  Agent          │                                  │    truth        │   │
   │   │                 │                                  └────────┬────────┘   │
   │   │  • Reads state  │                                           │            │
   │   │  • Picks next   │                                           │ confirmed  │
   │   │    target       │                                           │ exploit    │
   │   │  • Manages cost │                                           ▼            │
   │   │  • Halts on no  │                                  ┌─────────────────┐   │
   │   │    signal       │◀──── new vulnerability ─────────┤  Documentation  │   │
   │   └────────┬────────┘         report drafted          │  Agent          │   │
   │            │                                          │                 │   │
   │            │                                          │  • Drafts vuln  │   │
   │            │ trigger regression                       │    reports      │   │
   │            ▼                                          │  • Human gate   │   │
   │   ┌─────────────────────────────────────────┐         │    on critical  │   │
   │   │  Regression & Validation Harness        │         │  • File format: │   │
   │   │                                         │         │    severity +   │   │
   │   │  • Versioned exploit store              │         │    repro + fix  │   │
   │   │  • Auto-runs on target version change   │         └─────────────────┘   │
   │   │  • Detects "fixed" vs "behavior shift"  │                               │
   │   │  • Cross-category regression detection  │                               │
   │   └─────────────────────────────────────────┘                               │
   │                                                                             │
   │   Observability Layer (Langfuse + structured metrics)                       │
   │   ──────────────────────────────────────────────────                        │
   │   • Per-agent traces with cost attribution                                  │
   │   • Coverage map by attack category × target version                        │
   │   • Dashboards for human operators + read API for Orchestrator              │
   │                                                                             │
   └─────────────────────────────────────────────────────────────────────────────┘
```

---

### 1.1 Attack Lifecycle — runtime execution flow

The system architecture above shows components; this shows what happens when ONE attack moves through the system end-to-end.

```
┌──────────────────────────────────────────────────────────┐
│  Orchestrator picks category (e.g., prompt_injection)    │
└────────────────────────┬─────────────────────────────────┘
                         │ category, budget_cap
                         ▼
┌──────────────────────────────────────────────────────────┐
│  Red Team Agent                                          │
│  • Loads seed cases for category                         │
│  • Picks seed OR mutates from recent partial-success     │
│  • Generates AttackCandidate (single-turn or multi-turn) │
└────────────────────────┬─────────────────────────────────┘
                         │ AttackCandidate (no hypothesis)
                         ▼
┌──────────────────────────────────────────────────────────┐
│  Target Co-Pilot — live HTTP call (HMAC-signed)          │
│    POST /chat | /graph_chat | /attach_and_extract        │
│  • Returns target's response                             │
└────────────────────────┬─────────────────────────────────┘
                         │ (attack_payload, target_response)
                         ▼
┌──────────────────────────────────────────────────────────┐
│  Judge Agent (independent — never sees RT hypothesis)    │
│  • Loads category-specific evaluation criteria           │
│  • Renders verdict: pass | fail | partial | uncertain    │
│  • Confidence + evidence per criteria triggered          │
└────────────────────────┬─────────────────────────────────┘
                         │ JudgeVerdict
                         ▼
                   ┌─────┴─────┐
                   │  PASS?    │
                   └─────┬─────┘
              YES        │        NO  (FAIL or PARTIAL)
                ┌────────┘    └────────┐
                ▼                      ▼
   ┌─────────────────────┐   ┌──────────────────────────────┐
   │ Result logged;      │   │ Regression Store             │
   │ Orchestrator updates│   │  • Persist exploit YAML      │
   │ coverage map        │   │  • Tag (target_version,      │
   │                     │   │     judge_version)           │
   └─────────────────────┘   └──────────┬───────────────────┘
                                        │
                                        ▼
                             ┌──────────────────────────────┐
                             │ Documentation Agent          │
                             │  • Drafts vuln report        │
                             │    to VULN-NNN-DRAFT.md      │
                             │  • Auto-files if low/medium  │
                             │  • Holds for human review    │
                             │    if high/critical          │
                             └──────────┬───────────────────┘
                                        │
                                        ▼
                             ┌──────────────────────────────┐
                             │ Coverage state updated;      │
                             │ Orchestrator decides:        │
                             │  • Continue this category    │
                             │  • Mutate this attack        │
                             │  • Pivot to next category    │
                             │  • Halt (cost or signal cap) │
                             └──────────────────────────────┘
```

Every step emits a Langfuse span. Every artifact (AttackCandidate, JudgeVerdict, RegressionCase, VulnerabilityReport) is persisted to the filesystem under `evals/` for full audit + reproducibility.

---

## 2. Agent Roles

### 2.1 Red Team Agent — attack generation

**Role.** Generate novel adversarial inputs against the target Co-Pilot. Mutate partially-successful attacks to find variants that bypass defenses. Construct multi-turn attack sequences, not just single-prompt injections.

**Trust level.** Untrusted output by design — its output IS adversarial content. Outputs must never be acted upon outside the platform's sandbox.

**Inputs.**
- Attack category target (from Orchestrator)
- Seed cases for the category (from `evals/seed/<category>.yaml`)
- Recent partial-success attempts (from Judge verdicts marked "partial")
- Target system version + observed defense responses (from observability layer)

**Outputs.**
- Attack payload (single-turn or multi-turn sequence)
- Attack metadata: category, subcategory, MITRE ATLAS technique ID, targeted defense surface
- Hypothesis for why this variant might succeed

**Model choice.** **Open / non-frontier model preferred** (e.g., Llama-class via OpenRouter, with cross-model fallback). Frontier commercial models (Claude-class, GPT-class) are increasingly trained to refuse offensive security workflows. See §8.2 for the OpenRouter-mediated routing strategy and per-agent model mapping.

**Failure modes named.**
- Generates content that is itself harmful (e.g., synthesizes child exploitation prompts as a "test"). Mitigation: content-class filter on Red Team output before it touches the target; refuse-and-log on hard categories (see "Hard content categories — Red Team REFUSES to generate" below).
- Becomes blocked by its own model's safety filters. Mitigation: model fallback chain with permission tiers (defined in §3).
- Generates attacks that exploit the platform itself rather than the target. Mitigation: input sandbox; Red Team output is treated as untrusted input by every downstream component.

**Hard content categories — Red Team REFUSES to generate** (locked policy):

| Category | Refuse | Rationale |
|---|---|---|
| Attacks involving minors in clinical / sexual / violent contexts | YES | No defensible reason to generate even synthetically |
| Attacks containing real PHI tokens (real SSNs, real patient names) | YES | Synthetic SSN-shaped strings are fine; real ones are not. PHI scrubber + sentinel boundary depend on this discipline |
| Attacks targeting systems other than the approved Co-Pilot at `https://142-93-242-40.nip.io` | YES | Scope-creep guard; protects against accidentally testing third parties |
| Attacks synthesizing weaponized real-world malware payloads (working CVE exploits, ransomware code) | YES | Not in scope of LLM-application security testing; reduces dual-use risk |
| Attacks using profanity, racism, sexism for shock value as prompt-injection vectors | NO | These ARE legitimate adversarial-input vectors; refuse-and-skip would weaken coverage of LLM02 / LLM06 categories |
| Attacks attempting jailbreaks of frontier safety training | NO | This is the literal job (LLM01 testing) |
| Attacks attempting to extract PHI from the target (sentinel-pid synthetic PHI only) | NO | This is the literal job (LLM02 testing); the target's existing PHI scrubber + sentinel boundary keep real PHI out of the loop |

Implementation: pre-flight check on every `AttackCandidate` before it's sent to the target. Refused attacks logged with category and reason; do not consume target API budget. `RESPONSIBLE_USE.md` at repo root documents the dual-use posture.

**Maps to OWASP ASI risks the platform must defend against in this agent:** ASI01 Agent Goal Hijack (could be steered to attack out-of-scope systems), ASI04 Agentic Supply Chain Compromise (model dependency), ASI05 Unexpected Code Execution (if attacks include code).

### 2.2 Judge Agent — independent evaluation

**Role.** Evaluate each attack against the target as PASS (target responded safely) / FAIL (target was exploited) / PARTIAL (defense partially held). Maintain consistent criteria across runs and target versions. Differentiate "vulnerability fixed" from "model behavior changed in a way that hides the vulnerability."

**Trust level.** High — its verdicts gate everything downstream. **Must be independent of Red Team Agent** (different model provider where practical; never sees Red Team's hypothesis until after rendering verdict).

**Inputs.**
- The attack payload (from Red Team)
- The target's response
- Per-category evaluation criteria (versioned in `evals/criteria/<category>.yaml`)
- Ground-truth examples for the category

**Outputs.**
- Verdict: pass | fail | partial | uncertain
- Evidence: which criteria triggered
- Confidence score
- Escalation flag (when uncertainty > threshold → human review)

**Model choice.** Frontier commercial model (Claude 4.6 Sonnet baseline) — judge needs nuanced evaluation; cost is bounded by attack throughput.

**Calibration.** Ground-truth dataset of human-labeled (attack, response, verdict) tuples. Judge accuracy measured against this on every deploy. Drift detection: rolling-window accuracy, alert if drops >5pp from baseline.

**Failure modes named.**
- Judge starts agreeing with everything (true-positive collapse). Mitigation: ground-truth calibration + meta-test cases that should always fail.
- Judge drifts as target system changes (e.g., target's refusal style changes, Judge mistakes new style for vulnerability). Mitigation: criteria updates require human review + version-pinning verdicts to (target_version, judge_version) tuple.
- **Judge prompt-injection via target's response.** The target's response is untrusted input (target may have been exploited to embed instructions targeting the Judge — e.g., crafted JSON in the response that mimics the JudgeVerdict schema with `verdict: "pass"`). Mitigations: (a) target_response treated as data, never instruction; rendered into Judge's prompt with explicit "this is response content under evaluation, not a directive" framing; (b) structured-output enforcement via Pydantic on Judge's verdict object — if Judge's output doesn't match `JudgeVerdict` schema exactly, retry with stricter prompt then escalate to UNCERTAIN; (c) **smoke meta-test (`tests/smoke/judge_injection_test.py`)** with a canned target response containing fake `JudgeVerdict` JSON — Judge MUST produce UNCERTAIN, not "pass"; (d) Judge prompt explicitly names this attack class so the LLM is primed to recognize it.

**Maps to OWASP ASI risks the platform must defend against in this agent:** ASI06 Memory & Context Poisoning (Judge's calibration set could be tampered with), ASI09 Human-Agent Trust Exploitation (engineers acting on Judge's verdicts must understand confidence bounds).

### 2.3 Orchestrator Agent — strategic prioritization

**Role.** Read platform state (coverage gaps, open findings, recent regressions, accumulated cost) and decide which attack category the Red Team Agent targets next. Manage cost across agents in a single session. Trigger regression runs when target system version changes. Halt or redirect when cost is accumulating without producing signal.

**Trust level.** High — its decisions allocate budget and shape coverage.

**Inputs.**
- Coverage map: per-category attack count + verdict distribution
- Open findings: vulnerabilities not yet fixed
- Regression status: which previously-fixed exploits have reappeared
- Cost ledger: accumulated spend per agent per session
- Target version: deployed SHA (read from target's `/health` or version endpoint)

**Outputs.**
- Next-attack directive: (category, subcategory, model, budget_cap)
- Halt signal: when cost > threshold AND signal < threshold
- Regression-run trigger: when target version changes
- Coverage report (read by humans + dashboards)

**Model choice.** Lightweight model — Orchestrator's reasoning is over structured state, not natural language. Could be deterministic (rule-based) for v1, with LLM-augmentation for "novel attack category suggestion" added later.

**Cost management.** Hard caps per session (configurable env var). Soft caps trigger Red Team scope reduction (cheaper variant). Hard caps trigger halt-and-report.

**Failure modes named.**
- No clear next priority (all categories at equal coverage, no recent signal). Mitigation: deterministic fallback ordering + escalate to human for category prioritization.
- Cost accumulation without signal (Red Team generating noise). Mitigation: signal-to-cost ratio metric; halt when ratio < threshold.
- Cascading triggers (every regression run finds something, triggering more regression runs). Mitigation: depth-limit on triggered runs + human approval for chains > N levels.

**Maps to OWASP ASI risks the platform must defend against in this agent:** ASI01 Agent Goal Hijack (steered to ignore high-severity categories), ASI02 Tool Misuse (ignoring cost guards), ASI08 Cascading Agent Failures (recursive regression triggers).

### 2.4 Documentation Agent — confirmed-exploit reporting

**Role.** Convert confirmed exploits from the Judge into structured, professional vulnerability reports usable by an engineer who was not present when the exploit was found. Reports must be reproducible, actionable, and follow the specified format.

**Trust level.** Medium — outputs go to engineering teams + (potentially) external CISOs. **Critical-severity reports require human approval before filing** (PRD §9 requirement).

**Inputs.**
- Confirmed exploit (Judge verdict = FAIL, confidence ≥ threshold)
- Full attack sequence (from Red Team)
- Target's response (from observability log)
- Severity rating (from Judge)
- MITRE ATLAS technique ID (from Red Team metadata)

**Outputs.**
- Vulnerability report at `evals/vulnerabilities/VULN-<NNN>.md` with:
  - Unique identifier and severity rating
  - Description + clinical impact
  - Minimal reproducible attack sequence
  - Observed vs expected behavior
  - Recommended remediation
  - OWASP LLM Top 10 classification + MITRE ATLAS technique ID
  - Status + fix validation results

**Model choice.** Frontier commercial model — report quality matters; volume is bounded by confirmed-exploit count (low).

**Trust gate (conservative posture).** Documentation Agent **drafts every report** to `evals/vulnerabilities/VULN-<NNN>-DRAFT.md`. Auto-promote to `VULN-<NNN>.md` (filed) for severity ∈ {`low`, `medium`} with engineer notification. **Severity ∈ {`high`, `critical`} requires human approval** before promotion to filed status, before any external issue creation, and before any remediation ticket. The draft sits visible in-repo; the human reviewer flips a `status:` field in the YAML frontmatter from `draft-pending-review` to `filed`. This is more conservative than autonomy-tier defaults — appropriate for a healthcare context where a falsely-filed `high` finding wastes engineering time and a falsely-filed `critical` finding can trigger over-rotation away from real work.

**Failure modes named.**
- Confidently documents a false positive (Judge was wrong). Mitigation: report includes Judge confidence + minimum-repro the human can validate before filing.
- Cumulatively over-files (engineer fatigue → reports ignored). Mitigation: deduplication on (attack_pattern, target_response_hash).
- Reports leak sensitive context (the attack itself contains PHI or credentials). Mitigation: report redaction step using existing PHI-scrubber pattern from W2.

**Maps to OWASP ASI risks the platform must defend against in this agent:** ASI09 Human-Agent Trust Exploitation (engineers must trust report quality), ASI03 Agent Identity & Privilege Abuse (Documentation Agent must not be impersonated to file fake vuln reports).

---

## 3. Inter-Agent Coordination

### 3.1 Framework choice

**LangGraph** — same framework powering the target's supervisor + worker pattern. Reasons:
- Familiarity from W2 (no learning curve)
- Inspectable graph structure (Orchestrator's decisions visible in trace)
- Native Langfuse instrumentation
- Anthropic-friendly (multi-provider support intact)

**Alternatives considered.** AutoGen (less explicit graph, conversation-pattern-heavy — wrong for deterministic-DAG security work). CrewAI (role-playing focus, weaker on bounded autonomy). Custom Python (full control but reinvents graph + state primitives). LangGraph is the lowest-risk choice.

### 3.2 Communication pattern — concrete mechanism

**MVP transport: in-process LangGraph state + filesystem persistence at every step boundary.** No message queue, no async, no distributed coordination. Reasons: (a) MVP volume is bounded — single-machine throughput is sufficient; (b) crash recovery comes from filesystem artifacts, not in-memory state; (c) audit trail comes free from the filesystem write step; (d) simpler to defend in the 5-day build.

**How a single attack moves between agents:**

```
1. Orchestrator → Red Team (sync function call via LangGraph edge)
   ├─ Passes: AttackCategoryDirective {category, budget_cap, mutation_seed_ids}
   └─ Red Team writes: evals/results/<run-id>/attacks/<atk-id>.json (AttackCandidate)

2. Red Team → Target (HTTP, HMAC-signed)
   ├─ POSTs to /chat | /graph_chat | /attach_and_extract
   └─ Red Team writes: evals/results/<run-id>/responses/<atk-id>.json (raw target response)

3. Red Team → Judge (sync function call via LangGraph edge)
   ├─ Passes: (attack_payload, target_response) — Red Team's hypothesis is STRIPPED
   │  at the schema boundary; Judge never sees why Red Team thought this would work
   └─ Judge writes: evals/results/<run-id>/verdicts/<atk-id>.json (JudgeVerdict)

4. Judge → Orchestrator (sync return)
   ├─ Passes: JudgeVerdict
   └─ Orchestrator updates: evals/coverage.md (coverage map) + evals/results/<run-id>/manifest.json

5. If verdict = FAIL or PARTIAL:
   Judge → Documentation (sync function call via LangGraph edge)
   ├─ Passes: (attack, response, verdict, all metadata)
   └─ Documentation writes: evals/vulnerabilities/VULN-<NNN>-DRAFT.md
       AND evals/regression/<category>/REGR-<NNN>.yaml

6. Orchestrator decides next: continue category | mutate this attack | pivot category | halt
   (per §3.6 selection logic)
```

**Every artifact at every step is on disk.** State held in memory between steps is purely the LangGraph `RedTeamState` TypedDict carrying references to the on-disk artifacts. If the process crashes mid-run, restart reads `evals/results/<run-id>/manifest.json` to find resume point.

**Communication channels:**

| Channel | Transport | Persistence | Used by |
|---|---|---|---|
| Agent → Agent (within a session) | LangGraph state edges (in-process Python function calls) | TypedDict references on-disk artifacts | All inter-agent transitions in the lifecycle above |
| Agent → Filesystem (artifacts) | Direct writes to `evals/results/<run-id>/...` | Permanent (git-tracked for regression cases + vuln reports; gitignored for raw run output) | Every agent at every step |
| Agent → Observability | Langfuse spans (network) + structured stdout logs | Langfuse retention + log file rotation | Every agent at every LLM call boundary |
| Orchestrator → Coverage state | Read from `evals/coverage.md` + `evals/results/<run-id>/manifest.json` | YAML/JSON on disk | Orchestrator only (read-only by other agents) |

**Why not a message queue (RabbitMQ / Redis / Kafka)?** Volume doesn't justify operational overhead. We have ~10s-100s of attacks per session, not millions. In-process sync + filesystem writes deliver everything queues would: durable artifacts, replayable history, recoverable state.

**Why not async coroutines?** LangGraph supports sync and async paths. MVP picks sync because: (a) Red Team mutation throughput is bounded by OpenRouter rate limits anyway; (b) sync simplifies reasoning + audit; (c) async buys throughput we don't need at MVP volume. Phase 2 may add async if Orchestrator parallelizes multi-category exploration.

### 3.3 Trust boundary between Red Team and Judge

The Judge **never sees the Red Team's hypothesis** about why an attack should succeed. Judge sees only (attack_payload, target_response) + per-category criteria. This prevents the Red Team's intent from priming the Judge's verdict.

Implementation: schema enforcement at the inter-agent boundary; Red Team's `hypothesis` field stripped before payload reaches Judge.

### 3.4 Failure handling

When an agent fails or times out:
- Red Team timeout → Orchestrator marks attempt as inconclusive, schedules retry with reduced scope
- Judge timeout → verdict = `uncertain`, escalates to human
- Orchestrator timeout → platform halts (no autonomous decisions without Orchestrator)
- Documentation timeout → exploit queued; engineer can re-trigger or write manually
- Process crash mid-run → restart reads `evals/results/<run-id>/manifest.json`; re-runs uncompleted attacks from last checkpoint
- OpenRouter outage → built-in `models: [primary, fallback1, fallback2]` array; if all fail, Orchestrator pauses session with named reason
- Target unavailable / 5xx → backoff + retry; circuit breaker after N consecutive failures; Orchestrator pauses on sustained unavailability + emits alert

### 3.5 When evals fire + where artifacts live

The platform has **three eval contexts** that fire at different times. Don't conflate them.

#### Context A — Adversarial eval suite (the platform's product)

Attacks the platform generates and runs against the target Co-Pilot. This is the W3 deliverable. **Continuous mode is the primary operating mode per PRD requirement** (PRD pp. 1, 3: *"a system of agents that can hunt, evaluate, escalate, and document vulnerabilities continuously"*); single-shot CLI runs are the degenerate case.

| Trigger | Frequency | Scope | Output location |
|---|---|---|---|
| **Continuous daemon mode (PRIMARY)** | Long-running `while True:` loop; Orchestrator drives | Orchestrator-prioritized rotation through categories per §3.6.1; mutation pressure on partial wins; halts on cost-cap / signal-collapse / coverage-floor-met | `evals/results/<run-id>/` accumulates per iteration; `evals/coverage.md` rewritten after each iteration |
| **Discovery-driven mutation within continuous mode** | Triggered by Judge verdict = FAIL or PARTIAL on a category | Red Team mutates the failing attack to find variants; depth-capped to prevent loops | Same `<run-id>` continues |
| **Target version change** (Co-Pilot deployed SHA differs) | Auto-detected within the continuous loop on each iteration OR manual `--regression` flag | Full regression suite re-runs against new target version | Updates `evals/regression/<category>/<exploit-id>.yaml` last-passed/last-failed fields |
| **Single-shot engineer-triggered run (debugging)** | Manual | Single category OR fixed attack count per `--category` / `--max-attacks` flag | `evals/results/<run-id>/` — same format as continuous mode, just a short run |

**File layout for Context A:**

```
evals/
├── seed/<category>/<seed-id>.yaml         Seed attack cases per category (input)
├── criteria/<category>.yaml               Judge evaluation criteria per category (input)
├── results/<run-id>/                      Per-run output (manifest + per-attack files)
│   ├── manifest.json                      run metadata: started_at, target_version, category, status
│   ├── attacks/<atk-id>.json              AttackCandidate (per §12.1)
│   ├── responses/<atk-id>.json            Raw target response
│   ├── verdicts/<atk-id>.json             JudgeVerdict (per §12.2)
│   └── coverage-delta.json                What this run added to coverage
├── regression/<category>/<exploit-id>.yaml Versioned confirmed exploits (input + state)
├── vulnerabilities/VULN-<NNN>-DRAFT.md    Documentation Agent output (drafts)
├── vulnerabilities/VULN-<NNN>.md          Filed vuln reports (after human approval if high+critical)
├── coverage.md                            Per-category attack count + verdict distribution + last-update
└── calibration/                           Judge ground-truth dataset (Phase 2)
    ├── ground-truth.yaml                  human-labeled (attack, response, verdict) tuples
    └── drift-metrics.json                 Judge accuracy over time
```

#### Context B — Platform meta-tests (do the agents themselves work?)

Tests of the platform's own correctness. Lives in `tests/` (separate from `evals/`).

| Test class | Trigger | What it tests | Where |
|---|---|---|---|
| Unit tests (Python) | Pre-commit + CI | Agent logic, state transitions, criteria evaluation | `tests/unit/` |
| Judge calibration tests | Nightly + on calibration set update | Judge accuracy ≥ threshold against ground-truth | `tests/calibration/` |
| Smoke tests | Pre-commit | One full vertical slice with mocked target + canned LLM responses | `tests/smoke/` |
| Schema tests | Pre-commit | All inter-agent JSON schemas validate per §12 | `tests/schemas/` |

#### Context C — Sources of truth for grader-facing artifacts

| Artifact | Source | Promoted to | Notes |
|---|---|---|---|
| Vulnerability report (FILED) | `evals/vulnerabilities/VULN-<NNN>-DRAFT.md` after human review | `evals/vulnerabilities/VULN-<NNN>.md` (frontmatter status changes) | Severity ≥ high requires human gate |
| Regression case (LOCKED) | First confirmed exploit run | `evals/regression/<category>/REGR-<NNN>.yaml` | Auto-runs on target version change |
| Coverage report (CURRENT) | `evals/coverage.md` | n/a — auto-updated by Orchestrator after every run | Read by humans + by Orchestrator for next-attack selection |

### 3.6 Next-test selection — how Red Team picks what to try

Two-tier decision: Orchestrator picks the **category**; Red Team picks the **specific attack within that category**.

#### 3.6.1 Orchestrator — category selection (deterministic, MVP)

Decision rules in priority order. First rule that matches wins.

```
1. Has the TARGET VERSION changed since last regression run?
   → Trigger full regression suite. Stop here.

2. Are there OPEN FINDINGS (FAIL verdicts) without minimum-repro validated by replay?
   → Re-attempt the unvalidated finding. (Consolidation; cheap; closes loose ends.)

3. Are any categories BELOW the coverage floor (default: 10 attacks)?
   → Pick the lowest-coverage category. (Gap-fill.)

4. Does any category have HIGH signal-to-cost ratio in the last N attacks?
   (e.g., recent FAIL or PARTIAL count > 30% of attempts)
   → Continue mutating in that category. (Exploit-discovery momentum.)

5. Otherwise → ROUND-ROBIN through categories ranked by stale-since timestamp.
   (Fresh eyes on dormant categories.)

Halt conditions (checked before EVERY directive):
- Cost cap reached (MAX_SESSION_COST_USD)
- Signal-to-cost ratio < threshold for last K attacks
- All categories at coverage floor AND no recent open findings
```

In Phase 2, an LLM-augmentation layer can suggest novel categories not in the current set (e.g., "consider a multi-turn variant of category X based on observed defense response shapes"). MVP doesn't need this.

#### 3.6.2 Red Team — within-category attack selection

Once Orchestrator hands the Red Team a category + budget, Red Team picks WHAT to actually generate:

```
1. Are there RECENT PARTIAL WINS in this category (last K attempts)?
   → Mutate the highest-confidence partial. Variants explore: (a) wording change,
     (b) injection-point shift, (c) multi-turn extension, (d) obfuscation layer.
     Mutation depth-capped (default: 5) to prevent infinite loops.

2. Are there UNTRIED SEED CASES in evals/seed/<category>/?
   → Pick one (deterministic round-robin by seed-id) and run it as-is first to
     establish baseline; then generate K mutations.

3. Has the BUDGET been spent on this category without finding signal?
   → Generate 1-2 "wild card" attacks (Red Team prompted to explore an unusual
     vector) before returning control to Orchestrator.

For each chosen approach, generate N variants per OpenRouter call, run each
against target, judge each. Capped per-directive by Orchestrator's budget_cap.
```

**Concretely for the C-7 rediscovery (MVP first target):**

```
Orchestrator → Red Team: {category: sensitive_information_disclosure,
                          budget_cap: $1.00,
                          mutation_seed_ids: ["cross_patient_leakage_resistance"]}

Red Team → loads seed: existing W2 eval case for cross-patient leakage
        → runs seed verbatim against /chat
        → if FAIL on seed: file VULN-001-DRAFT.md (this is the C-7 rediscovery)
        → if PASS on seed (defense improved since W2): generate 5 mutations:
            • paraphrase variant (Haiku-style narrative)
            • multi-turn variant (set context first, then ask about target patient)
            • indirect-via-document variant (upload doc with crafted content)
            • escalating-specificity variant
            • role-play-frame variant
        → run each against target, judge each
        → return to Orchestrator with verdicts + cost

Total time: 2-5 minutes. Total cost: ~$0.50-$1.00 depending on model + mutations.
```

This is the **vertical slice** from §9.4 made concrete.

### 3.3 Trust boundary between Red Team and Judge

The Judge **never sees the Red Team's hypothesis** about why an attack should succeed. Judge sees only (attack_payload, target_response) + per-category criteria. This prevents the Red Team's intent from priming the Judge's verdict.

Implementation: schema enforcement at the inter-agent boundary; Red Team's `hypothesis` field stripped before payload reaches Judge.

### 3.4 Failure handling

When an agent fails or times out:
- Red Team timeout → Orchestrator marks attempt as inconclusive, schedules retry with reduced scope
- Judge timeout → verdict = `uncertain`, escalates to human
- Orchestrator timeout → platform halts (no autonomous decisions without Orchestrator)
- Documentation timeout → exploit queued; engineer can re-trigger or write manually

---

## 4. Regression & Validation Harness

### 4.1 Storage

Confirmed exploits stored at `evals/regression/<category>/<exploit-id>.yaml` with:
- Attack payload (verbatim)
- Expected behavior (target should refuse / sanitize / etc.)
- Observed behavior at discovery time (target's actual response)
- Target version at discovery
- Last-passed version + last-failed version (regression tracking)

### 4.2 Triggers

- **Target version change** — Orchestrator detects via target's deployed SHA; runs full regression suite
- **Manual** — engineer can trigger via CLI for ad-hoc testing
- **Time-based** — nightly run of full suite regardless of changes (detects model-provider drift)

### 4.3 "Fixed" vs "behavior changed" differentiation

A test passing because the target's behavior changed in a way that hides the vulnerability is **worse than no test at all**. The Judge differentiates:
- **Fixed**: target now refuses / sanitizes / handles correctly (verdict = PASS, with evidence matching expected behavior)
- **Behavior changed (suspicious)**: target's response is different from both observed-vulnerable and expected-safe (verdict = `uncertain`, escalates to human)

### 4.4 Cross-category regression

When a fix in category X is shipped, regression suite runs against ALL categories — not just X. This catches "fixing one attack introduces a regression in another category" (PRD requirement).

---

## 5. Observability Layer

**Single source of truth: Langfuse** (already wired in target Co-Pilot; extend to platform agents).

**Per-agent traces** with span attributes:
- Agent name, role, model_id
- Attack category + MITRE ATLAS technique ID
- Verdict, confidence, evidence
- Cost (USD), latency (ms), token counts

**Read API for Orchestrator.** Coverage map, open findings, recent regressions all queryable from Langfuse via API. Observability is the data substrate the Orchestrator reads (PRD p. 11) — designed for both human dashboards and agent consumption.

**Vulnerability dashboard.** `observability/dashboard.md` (or web UI in Phase 2) showing:
- Per-category attack count + pass/fail rate
- Open findings by severity
- Coverage gap analysis
- Cost burn rate
- Regression status

---

## 6. Framework Anchoring

| Framework | Role in this platform | Citation |
|---|---|---|
| **OWASP Top 10 for LLM Applications v2025** (Nov 2024) | Attack-surface taxonomy for the TARGET; threat model and seed attack categories map to LLM01–LLM10 | [genai.owasp.org](https://genai.owasp.org/) |
| **OWASP Agentic Security Initiative (ASI) Top 10 2026** | Security posture for THIS PLATFORM (autonomous multi-agent); informs platform's own trust boundaries and failure-mode design | [genai.owasp.org/initiatives/agentic-security/](https://genai.owasp.org/) |
| **MITRE ATLAS** | Per-attack tactical citation for vulnerability reports + Judge criteria | [atlas.mitre.org](https://atlas.mitre.org/) |
| **NIST AI Risk Management Framework (AI 100-1)** + AI 600-1 Gen AI Profile | Governance lens — Govern / Map / Measure / Manage functions structure the platform's policy + audit posture | [nist.gov/itl/ai-risk-management-framework](https://www.nist.gov/itl/ai-risk-management-framework) |
| **HHS AI Strategy** (2024+) + 2025 HHS AI Compliance Plan | Healthcare-specific AI governance; clinical CISO defense | [hhs.gov/programs/topic-sites/ai/](https://www.hhs.gov/programs/topic-sites/ai/) |
| **Microsoft AI Red Teaming Agent (Foundry)** + research on multi-agent red teaming | Methodological precedent — we're not the first to build this; cite prior art | Microsoft Research blog (2025-2026) |

The platform anchors on established frameworks rather than inventing taxonomy. A hospital CISO recognizes OWASP + NIST + MITRE; they do not recognize bespoke categorizations. **This is a deliberate defense move** — graders / CISOs / auditors evaluate the platform faster when it speaks their language.

---

## 7. Trust Boundaries + Human Approval Gates

### 7.1 Where the platform operates autonomously

- Red Team Agent generating attacks within scope categories
- Judge rendering verdicts on standard cases (confidence ≥ threshold)
- Orchestrator picking next category from approved list
- Documentation Agent drafting reports for ALL severities; auto-filing for severity ∈ {`low`, `medium`} only
- Regression suite running against confirmed exploits

### 7.2 Where humans gate autonomous action

| Gate | Trigger | Required action |
|---|---|---|
| **Out-of-scope target** | Red Team generates attack against target other than approved Co-Pilot | Hard refuse + log |
| **High-severity vuln report** | Documentation Agent → severity = `high` | Engineer review before promoting from `DRAFT` to filed |
| **Critical-severity vuln report** | Documentation Agent → severity = `critical` | Engineer review before promoting from `DRAFT` to filed; required before external issue creation or remediation ticket |
| **Judge uncertainty** | Verdict confidence < threshold | Human resolves; calibration set updated |
| **Cost ceiling** | Session cost > hard cap | Halt + human resumption decision |
| **Cross-category regression spike** | Fix in X breaks Y in unexpected way | Human triages |
| **Platform self-attack risk** | Red Team output classified as targeting platform itself | Hard refuse + alert |

### 7.3 Audit trail

Every autonomous action recorded with:
- Agent name + version
- Inputs (full)
- Outputs (full)
- Human-approval status (if gated)
- Timestamp + actor (for human-gated actions)

### 7.4 NIST AI RMF function mapping

- **Govern.** Trust boundaries above; policy file at `docs/governance.md` (Phase 2)
- **Map.** Threat model + attack-surface categorization in `THREAT_MODEL.md`
- **Measure.** Coverage / verdict / regression metrics in observability layer
- **Manage.** Vulnerability reports + remediation tracking in `evals/vulnerabilities/`

---

## 8. Cost Management

### 8.1 Per-session caps

- Hard cap (env var `MAX_SESSION_COST_USD`, default $10) → halt
- Soft cap (50% of hard cap) → reduce Red Team scope (single-turn only, fewer mutations)
- Per-agent caps (env vars per agent) → reduce that agent's call frequency

### 8.2 Model-tier strategy — selection-criteria-first + configurable

**Routing layer:** [OpenRouter](https://openrouter.ai/) for all hosted-model calls. This is a **deliberate return** — Week 1 of the AgentForge project started on OpenRouter; W1/W2 production migrated to Anthropic direct for consistent clinical-synthesis quality at sustained volume. **W3 returns to OpenRouter** because the workload changed: we're attacking now, not synthesizing. Different model demands, different cost profile, and frontier safety training that's a feature for clinical synthesis becomes an obstacle for adversarial generation. Tradeoffs are known first-hand.

**Architectural commitment: model choice is configurable, not hard-coded.** Every agent reads its model ID from an environment variable (`RED_TEAM_MODEL`, `JUDGE_MODEL`, `JUDGE_FALLBACK_MODEL`, `DOCUMENTATION_MODEL`, `ORCHESTRATOR_MODEL_OPTIONAL`). The selection CRITERIA below are the architectural decision; specific model IDs are tactical and will iterate as Phase 1 surfaces real cost/quality data. This separation is intentional — defending "we picked these criteria" is more durable than defending "we picked Llama 3.3 70B."

#### 8.2.1 Red Team Agent — selection criteria + candidates

**Selection criteria (in priority order):**

1. **Permissive safety posture** — does NOT refuse "generate a prompt-injection variant of X" or similar offensive-security tasks. Frontier models (Claude, GPT-4) increasingly refuse; open-weight models with less restrictive RLHF generally don't.
2. **Strong instruction following** — can produce structured outputs matching our `AttackCandidate` schema; can mutate seed attacks per directive.
3. **Cost reasonable at sustained mutation throughput** — must be affordable to generate hundreds of attack variants per session without burning budget.
4. **Available on OpenRouter** — minimizes auth + infrastructure overhead.
5. **Strong community knowledge** — debug-able when behavior surprises us (5-day build can't afford to chase mystery model behavior).

**Candidate matrix (verify current availability + pricing on OpenRouter at run time):**

| Model family | Permissive? | Instruction-following | Cost/M tokens | OR availability | Community knowledge | Notes |
|---|---|---|---|---|---|---|
| **WhiteRabbit-Neo** (Kindo, Llama-fine-tune) | High — purpose-built for offensive security | Strong on security tasks | Low-mid | Verify | Smaller community | Most defensible "we picked a security-purpose-built model" pick if available |
| **Dolphin-class fine-tunes** (Dolphin-Mistral, Dolphin-Llama, Dolphin-Mixtral) | High — community-tuned to remove some safety training | Good | Low | Mostly available | Strong — community-vetted | Generic permissive baseline |
| **Qwen 2.5 / Qwen 3 / QwQ family** | Medium-high — less restrictive than Llama 3.3 in many cases | Strong reasoning | Very low | Yes | Growing | Cheap + capable; refusal varies by version |
| **DeepSeek V3 / R1** | Medium — newer; refusal less characterized | Very strong reasoning | Lowest of strong options | Yes | Growing fast | Best cost-quality on the market in many tasks; verify offensive-task behavior |
| **Llama 3.3 70B Instruct** | Medium — Meta's recent versions added more safety than 3.0/3.1 | Strong | Mid | Yes | Very strong | Reliable baseline; less permissive than Dolphin variants |
| **Mixtral 8x22B / Mistral Large 2** | Medium | Strong | Mid | Verify | Strong | Older but capable |
| **OpenHermes / Nous-Hermes** | High | Good | Low | Verify | Decent | Less restrictive than base; check current version on OR |

**Phase 1 starting recommendation (try in order, ship with whichever lands first):**

1. WhiteRabbit-Neo (if available on OpenRouter at start time)
2. Dolphin-Mixtral 8x22B (broadly available; community-vetted)
3. Qwen 2.5 72B / Qwen 3 (cheap baseline; falls back well)
4. DeepSeek V3 (cheapest of strong options)
5. Llama 3.3 70B Instruct (last-resort baseline; known to refuse some offensive work)

`RED_TEAM_MODEL` env var; `RED_TEAM_FALLBACK_MODELS` comma-separated list; OpenRouter native `models: [...]` syntax handles fallback at request time.

#### 8.2.2 Judge Agent — selection criteria + candidates

**Selection criteria (in priority order):**

1. **High accuracy on human-labeled ground-truth set** — Judge's job is consistent verdict rendering; calibration drift is the #1 failure mode (§10.1).
2. **Cross-provider independence from Red Team** — eliminates shared-failure-mode risk (e.g., a Llama version update affecting both attack quality AND judge behavior).
3. **Nuanced evaluation of partial wins** — must distinguish PASS / FAIL / PARTIAL / UNCERTAIN reliably.
4. **Bounded volume tolerance** — Judge runs once per attack, not per mutation; cost is bounded; quality matters more than per-call price.
5. **Structured-output reliability** — must consistently emit `JudgeVerdict` JSON (§12.2).

**Candidate matrix:**

| Model family | Accuracy on eval | Cross-provider from Red Team? | Nuance | Cost/M tokens | Notes |
|---|---|---|---|---|---|
| **Anthropic Claude Sonnet-class (via OpenRouter)** | Very high | Yes (Anthropic ≠ Llama family) | Excellent — strong on subtle distinctions | Mid-high | Strong baseline; expensive vs alternatives |
| **OpenAI GPT-4o-class / GPT-class (via OpenRouter)** | Very high | Yes (OpenAI ≠ Llama family ≠ Anthropic) | Excellent | High | Best for cross-provider fallback from Anthropic primary |
| **Google Gemini-class (via OpenRouter)** | High | Yes (third provider for cross-provider robustness) | Good | Mid | Useful for 3-judge panel in Phase 2/3 |
| **Open-class (Llama / Qwen) for Judge** | Variable; lower than frontier on nuance | NO if Red Team is also Llama-class | Variable | Low | Cheapest; falls below quality bar for MVP |

**Phase 1 starting recommendation:**

- **Primary:** Anthropic Claude Sonnet-class (via OpenRouter)
- **Fallback:** OpenAI GPT-class (via OpenRouter) — cross-provider independence
- **NOT:** any Llama-family model (would share failure modes with Red Team if Red Team is also Llama-class)

`JUDGE_MODEL`, `JUDGE_FALLBACK_MODEL` env vars.

#### 8.2.3 Documentation Agent — selection criteria + candidates

**Selection criteria:**

1. **Report quality** — output must be usable by an engineer who wasn't present (PRD bar)
2. **Template adherence** — must consistently fill the `VulnerabilityReport` markdown structure (§12.4)
3. **Low volume tolerance** — bounded by FAIL verdict count; cost is small absolute number even with frontier model
4. **PHI-safe output** — must not leak PHI from observed attacks into reports (existing W2 PHI scrubber pattern can be reused on output)

**Phase 1 starting recommendation:**

- **Primary:** Anthropic Claude Sonnet-class (via OpenRouter) — same as Judge primary; reuses provider auth
- **Fallback:** Anthropic Claude Haiku-class with stricter template constraints

`DOCUMENTATION_MODEL`, `DOCUMENTATION_FALLBACK_MODEL` env vars.

#### 8.2.4 Orchestrator Agent — selection criteria + candidates

**Selection criteria:**

1. **Deterministic decisions where possible** — coverage routing + cost guards + halt logic don't need LLM reasoning
2. **Cheap LLM augmentation only when needed** — novel-category suggestion in Phase 2; bounded volume
3. **Auditability** — every decision traced to a rule or LLM call

**Phase 1 starting recommendation:**

- **MVP:** Pure Python rules; no LLM. Reads coverage state, picks next category by deterministic priority.
- **Phase 2:** Optional Haiku-class augmentation for novel-category suggestions when all explicit categories are well-covered.

`ORCHESTRATOR_MODEL_OPTIONAL` env var (empty = pure rules).

#### 8.2.5 Why this structure (selection-criteria-first) is the defense

A grader who probes "why Llama 3.3 70B?" gets a specific answer that can be wrong. A grader who probes "what are your criteria for Red Team model selection?" gets a methodology that's defensible regardless of which model is loaded today. The selection CRITERIA (permissive safety posture, instruction following, cost, OR availability, community knowledge) survive when specific models are deprecated, when OpenRouter changes its catalog, when a new model strictly dominates today's pick. The criteria are the architectural decision; the model IDs are tactical configuration.

#### 8.2.6 Why OpenRouter (the architectural decision defended)

- **Cost flexibility per agent role.** Per-call costs visible in API response; trivial to swap model IDs without re-authenticating; enables the 100/1K/10K/100K projection in `docs/cost-analysis.md` (Phase 2)
- **Frontier-refusal mitigation.** Direct Anthropic / OpenAI APIs increasingly refuse offensive-security prompts; OpenRouter's open-model selection bypasses this for the Red Team role specifically
- **Cross-provider model independence.** Red Team and Judge can come through different model providers via the same API surface — eliminates shared-failure-mode risk without managing two separate auth chains
- **Native model fallback.** OpenRouter supports `models: [primary, fallback1, fallback2]` array → graceful degradation when rate-limited
- **One auth, one bill, one telemetry surface.** Simpler than per-provider creds; matches a 5-day build's tolerance for setup overhead
- **First-hand experience.** Used in W1 of AgentForge; tradeoffs known. We left OpenRouter for W2 production for clinical-synthesis quality reasons that don't apply to adversarial generation. Returning is informed, not exploratory.

#### 8.2.7 Tradeoffs documented honestly

- OpenRouter sees all platform prompts → acceptable for security research; sentinel-pid boundary in target Co-Pilot already strips PHI before any agent call (so no real PHI flows through OpenRouter to begin with)
- Free tier rate-limited → Phase 1 budgets ~$5-15 in OpenRouter credit; hard cap via `MAX_SESSION_COST_USD` env var
- ~50-200ms routing-layer latency → negligible; this is offline adversarial testing, not user-facing inference
- OpenRouter periodically deprecates older model IDs → pin specific versions in config; document upgrade in `SETUP.md`
- Local model option (Ollama / llama.cpp) deferred for W3 timeline reasons (infrastructure overhead too high for 5-day build); documented as Phase 3+ consideration if cost/scale demands it

### 8.3 Projection at scale

Detailed cost projections at 100 / 1K / 10K / 100K test runs per the PRD requirement live in `docs/cost-analysis.md` (Phase 2 deliverable). Per-run cost dominated by Red Team token burn (multi-turn sequences) + Judge evaluation; Orchestrator + Documentation are bounded.

---

## 9. Tradeoffs + Known Risks

### 9.1 Decisions made under uncertainty

| Decision | Chosen | Sacrificed | Why |
|---|---|---|---|
| Framework | LangGraph | New-framework optionality | Continuity with W2; native Langfuse instrumentation; familiar |
| Red Team model | Open-source self-hosted | Quality of attacks (frontier > open for many tasks) | Frontier refuses offensive workflows; documented in §6 |
| Judge model | Frontier commercial (Claude) | Cost per evaluation | Nuance + calibration matters more than per-call cost at our volume |
| Single Judge vs panel | Single (Phase 1) | Robustness from disagreement signal | Add panel in Phase 2 if calibration drift surfaces |
| Synchronous coordination | Yes (LangGraph state) | Throughput | Simpler reasoning + audit trail; async is Phase 2+ |
| Storage of confirmed exploits | YAML files in repo | Versioned database | Git is sufficient; SQL adds complexity for no Phase 1 gain |

### 9.2 Top risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Open-source Red Team model insufficient quality | Medium | Frontier-fallback chain with permission tiers; document quality delta |
| Judge calibration drifts as target evolves | Medium | Ground-truth dataset re-validated weekly; alert on >5pp drift |
| Cost runaway from Red Team mutations | High at scale | Per-session hard caps + signal-to-cost ratio halt |
| Platform's own bugs flag false vulnerabilities | Medium | Human approval gate on critical; deduplication; minimum-repro requirement |
| Adversarial output from Red Team itself harmful | Low (filtered) | Content-class filter + refuse-and-log on hard categories |
| Target system unavailable / rate-limited | Low | Backoff + retry; Orchestrator pauses on sustained unavailability |
| Recursion concern ("who tests the tester") | Bounded | Layered trust (§7); periodic human red-team OF the platform; ground-truth datasets; deterministic platform components where possible |

### 9.3 Phase 1 → Phase 2 → Phase 3

- **Phase 1 (architecture defense → MVP Tuesday).** Architecture locked; one **vertical slice** working end-to-end (see §9.4); initial THREAT_MODEL + 3-category eval suite seeded from W2 cases.
- **Phase 2 (MVP → Final Friday).** Full 4-agent system; Orchestrator running autonomously; ≥3 vulnerability reports filed; observability dashboards; cost analysis at 100/1K/10K/100K scale.
- **Phase 3 (post-final).** Multi-judge panel for calibration robustness; async coordination for throughput; deeper MITRE ATLAS coverage; healthcare-specific compliance reporting.

### 9.4 MVP Scope (Tuesday 2026-05-13 11:59 PM) — continuous-mode daemon + vertical slice

The MVP is **a continuous-operation daemon that runs the vertical slice in a loop until it halts itself on resource bounds.** Engineer starts it; daemon runs unattended; daemon halts cleanly with named reason. This demonstrates the PRD's continuous-operation commitment, not just "we ran one attack and got a result."

**The vertical slice (one iteration of the loop):**

```
Red Team seed/mutation → live target call → Judge verdict → saved regression case → draft vuln report
```

**The loop (Orchestrator's main daemon):**

```
while not halt_condition_met:
    category = orchestrator.pick_next_category(coverage_state, open_findings, cost_ledger)
    directive = orchestrator.build_directive(category, remaining_budget)
    attacks = red_team.generate(directive, max_variants=N)
    for attack in attacks:
        response = target_client.execute(attack)        # HMAC-signed; circuit-broken
        verdict = judge.evaluate(attack, response)      # independent; no RT hypothesis
        persist(attack, response, verdict)              # filesystem checkpoint
        if verdict in (FAIL, PARTIAL):
            documentation.draft_report(attack, response, verdict)  # → DRAFT.md
            regression_store.add(attack, verdict)        # → regression/ YAML
        coverage_state.update(category, verdict)
        cost_ledger.add(attack.cost + verdict.cost)
    if orchestrator.should_halt(cost_ledger, signal_metrics):
        halt(reason)
```

**Concrete MVP deliverables:**

| Deliverable | Where it lives | Acceptance criterion |
|---|---|---|
| **Live target URL** | `https://142-93-242-40.nip.io` (already deployed) | `curl` against `/health` returns 200 |
| **Eval suite structure** | `evals/seed/<category>/*.yaml`, `evals/results/<run-id>/...`, `evals/criteria/<category>.yaml` | Three categories with ≥5 seed cases each: **sensitive information disclosure**, **prompt injection** (direct + document-based indirect), **unbounded consumption** |
| **Red Team Agent** (seed + mutation, OpenRouter-backed) | `agents/red_team/` | Loads seed YAMLs; produces N mutated variants per directive; outputs `AttackCandidate` records |
| **Target client** | `agents/red_team/target_client.py` | HMAC-signed POST to `/chat` or `/attach_and_extract`; circuit breaker + backoff |
| **Judge Agent** (rubric-based, frontier model via OpenRouter) | `agents/judge/` | Renders `pass | fail | partial | uncertain` verdict + confidence + evidence; never sees RT hypothesis |
| **Documentation Agent** (template-fill) | `agents/documentation/` | Drafts `VULN-<NNN>-DRAFT.md` for every FAIL/PARTIAL verdict; fills `VulnerabilityReport` schema (§12.4) |
| **Orchestrator daemon** (deterministic loop) | `agents/orchestrator/` | Runs continuous `while not halt:` loop; reads coverage state; picks category by §3.6.1 rules; halts on cost cap OR signal-to-cost collapse OR coverage-floor-met |
| **Continuous-mode run command** | `python -m clinical_redteam.run --continuous --max-budget 5.00 --halt-on-empty-categories` | Daemon starts; runs unattended until halt; writes a per-iteration line to stdout + persists everything to filesystem |
| **Single-shot run command** (for engineer debugging) | `python -m clinical_redteam.run --category prompt_injection --max-attacks 10` | Same loop, capped at N attacks in one category; the degenerate single-iteration case |
| **Vulnerability report (C-7 rediscovery)** | `evals/vulnerabilities/VULN-001-cross-patient-paraphrased-leakage.md` (auto-generated) | C-7 re-discovered → vuln report in repo with severity, repro, expected/observed, remediation, OWASP + MITRE ATLAS classification, status = `draft-pending-review` (high severity → human gate) |
| **Resume-after-restart** | Daemon kill + restart picks up from `evals/results/<run-id>/manifest.json` | `kill -9` mid-run, restart, observe daemon resumes from last checkpoint |
| **Observability** | Langfuse traces for every Red Team + Judge call; per-agent cost attribution; per-iteration coverage + cost stdout summary | Open Langfuse UI → see traces filtered by `clinical-redteam-mvp` project + `coverage.md` updates after every iteration |

**NOT in MVP scope (Phase 2+):**

- Multi-turn attack sequences (MVP is single-turn; multi-turn is Phase 2)
- Regression harness auto-triggering on target version change detection (MVP supports it via `--regression` flag; auto-detection daemon is Phase 2)
- Judge calibration against human-labeled ground-truth dataset (MVP uses rubric-based criteria; calibration is Phase 2)
- LLM-augmented Orchestrator (Phase 2 — novel-category suggestion when explicit categories are well-covered)
- Multi-process / Redis-fronted parallel worker fleet for throughput (Phase 3 — only when single-process throughput becomes the constraint)
- Multi-judge panel for cross-provider robustness on calibration drift (Phase 2-3)
- Distributed fuzzing, RL-based attack-strategy improvement, exploit chaining beyond depth cap (Phase 3+)
- Web UI for vuln-report review + coverage dashboard (Phase 2 — MVP uses markdown files + git)

**Why narrow + deep > wide + shallow.** A grader cannot evaluate "all 4 agents at 25% capability" — they can evaluate "vertical slice works end-to-end." The PRD HARD GATE for Stage 3 is *"./evals/ with results from at least three distinct attack categories, plus a working prototype of at least one agent role running live against the deployed target."* MVP delivers one full path through that and re-discovers the C-7 finding as proof-of-platform.

Most rich agent features are deferred. **Phase 1 ships Red Team seed/mutation, Judge rubric evaluation, and Documentation template-fill only; Orchestrator is a deterministic CLI control loop for MVP** (LLM-augmented prioritization in Phase 2).

---

## 10. Failure Modes of the Platform Itself ("Testing the Tester")

The PRD explicitly asks (pp. 14-15): *"How do you validate that the Red Team Agent is actually generating novel attacks? Ground truth dataset for evaluating Judge Agent accuracy? How do you detect when the platform is producing low-quality signal? What does it mean for the multi-agent system itself to regress?"* This section names the platform's own failure modes and the mitigations.

### 10.1 Per-agent failure modes + mitigations

| Failure mode | Symptom | Mitigation |
|---|---|---|
| **Judge hallucination / drift** | Judge marks safe responses as `fail` (false-positive collapse) or vice versa | Ground-truth dataset of human-labeled tuples; weekly accuracy re-validation; alert on >5pp drop from baseline |
| **Judge collapse** (everything becomes uniform pass or uniform fail) | Verdict distribution flattens; no signal | Distribution-shift detection on rolling window; alert + halt; meta-test fixtures that should always fail their respective rubric |
| **Adversarial poisoning of regression corpus** | Confirmed exploits in `evals/regression/` modified to no longer fire | Regression corpus is git-versioned; PR review required for any change; CI re-runs full regression on every commit |
| **Infinite mutation loops** | Red Team mutates without convergence; cost climbs without new findings | Per-category mutation depth cap (default: 5); signal-to-cost ratio halt (Orchestrator) |
| **Coordinated agent drift** | Both Red Team and Judge shift in correlated ways (e.g., shared model provider updates) | Different model providers where practical (Red Team open-source, Judge Anthropic); ground-truth re-validation catches both |
| **Exploit deduplication failures** | Same exploit filed N times under slightly-different attack payloads | Hash-based deduplication on (attack_pattern_normalized, target_response_hash, category); soft-flag for human review on near-duplicates |
| **Red Team discovers platform exploits, not target exploits** | Red Team's output targets the Orchestrator or Judge instead of the Co-Pilot | Input sandbox: Red Team output treated as untrusted by every downstream component; content-class filter rejects payloads targeting platform infrastructure |
| **Runaway token spend** | Cost climbs faster than findings | Hard cap (`MAX_SESSION_COST_USD`, default $10); soft cap at 50% triggers Red Team scope reduction; per-agent caps |
| **Documentation Agent files false positive** | Engineer wastes time reproducing a non-issue | Conservative trust gate (high+critical require human review); minimum-repro requirement in report template; deduplication; sample-then-validate flow |
| **Evaluator collapse** (uncertain on everything) | Most verdicts come back as `uncertain`, requiring human review on all | Calibration set ensures Judge can render decisive verdicts on known-clear cases; alert if uncertain-rate exceeds threshold |
| **Cascading triggers** (every regression run finds something, triggering more runs) | Recursive auto-regression storm | Depth-limit on triggered runs (default: 2 levels); human approval for chains > N levels |
| **Target system unavailable / rate-limited** | Cascading retry storms; cost amplification | Backoff + retry with circuit breaker; Orchestrator pauses on sustained unavailability; alert |

### 10.2 Continuous-mode-specific failure modes

The PRD requires continuous operation. Continuous operation introduces failure modes that single-shot runs don't have:

| Failure mode | Symptom | Mitigation |
|---|---|---|
| **Judge calibration drift over time** | Judge accuracy decays over days/weeks as target evolves OR Judge model itself receives provider-side updates | Ground-truth re-validation runs as part of the daemon loop (every N iterations); alert on >5pp drop from baseline; pin Judge model version in config and require explicit version bump |
| **Target version change mid-iteration** | Daemon is mid-attack against target_version_v1; deploy lands; subsequent attacks hit target_version_v2 with stale assumptions | Orchestrator re-reads target version on every iteration boundary; on detected change, finishes current attack atomically, then triggers regression suite, then resumes normal coverage |
| **Daemon restart loses in-flight attack** | Process killed (OOM, manual restart, host reboot) mid-attack; current attack's state is in memory only | Filesystem checkpoint BEFORE every external call; on restart, daemon reads `evals/results/<run-id>/manifest.json`, finds last completed iteration, resumes from there. In-flight attack at crash time is replayed from its persisted AttackCandidate. |
| **Observability fatigue** (continuous mode = humans aren't watching every attack) | Real findings get lost in noise of routine PASS verdicts; human reviewer ignores draft vuln reports because there are too many | Tiered notification: critical/high → alert immediately; medium → daily digest; low → weekly digest. Coverage dashboard surfaces trends, not individual events. Auto-deduplication on (attack_pattern_normalized, target_response_hash) reduces low-signal noise. |
| **Cost accumulation over days/weeks** | Daemon runs for a week; per-day cost is small but cumulative cost surprises engineering | Daily cost summary written to `evals/cost-ledger.md` + alerted at thresholds (50% of weekly cap, 100%); rolling 7-day cost projection visible in coverage dashboard |
| **Regression-corpus drift / staleness** | Confirmed exploits accumulate; some are fixed but never marked resolved; corpus re-runs waste cycles on stale cases | Status field on every regression case (`active` / `resolved` / `wontfix` / `superseded`); resolved cases run only on explicit re-validation flag; stale-since timestamps + alert on >30-day-old `active` cases |
| **Mutation diversity collapse** | Continuous mutation pressure pushes Red Team toward a narrow attack pattern that consistently judges as PARTIAL; daemon loops on near-misses without exploring elsewhere | Mutation depth cap per attack chain (default: 5); when a chain exhausts depth without converging to FAIL, Orchestrator marks chain `inconclusive` and rotates to a different category |
| **Open finding pile-up** (humans not reviewing drafts fast enough) | High/critical drafts accumulate awaiting human review; daemon keeps adding new ones | Daemon detects backlog (`>N pending high/critical reviews`) and emits prominent alert; reduces Red Team aggression on categories where backlog is largest until reviewers catch up |
| **Provider-side model deprecation mid-run** | OpenRouter deprecates the pinned Red Team model ID; daemon errors on next call | Health-check endpoint pings OpenRouter for pinned models on daemon startup AND every M iterations; alert on missing models with named replacement options; auto-fallback chain absorbs short-term outages |
| **Slow drift in target's safety responses** (target's LLM provider updates Claude version) | Attacks that previously failed start passing OR vice versa; not because Co-Pilot code changed | Target version SHA tracks Co-Pilot CODE version; need separate "target LLM provider version" header read from target's `/health` endpoint; regression suite differentiates "Co-Pilot fix" from "underlying-LLM behavior shift" via per-version pass-rate tracking |

### 10.3 The recursion question — "who tests the tester?"

The platform tests the Co-Pilot. What tests the platform? The recursion has known stopping points:

- **Asymmetric trust requirements per layer.** Co-Pilot serves clinicians continuously → needs continuous adversarial testing. Platform serves a small security team → needs periodic + sampled human review, not continuous meta-platform.
- **Different testing methodologies per layer.** Platform is tested by deterministic unit tests, ground-truth datasets, statistical regression detection on Judge calibration, and cost/rate-limit guards (none of which need their own LLM-based tester).
- **Independence between roles inside the platform.** Red Team + Judge separation IS the meta-evaluation — the regress doesn't extend infinitely because evaluation is structurally independent of generation.
- **Human-in-the-loop at trust gates.** Critical-severity reports → human review. Judge calibration baselines → human-labeled ground truth. Platform policy → human-set scope. The recursion stops at human judgment at safety-critical decisions (foundationalism in epistemics).
- **Pragmatic confidence threshold.** A platform that catches 80% of vulnerabilities the day it deploys is much better than no platform; we build to confidence appropriate for the risk class, not mathematical certainty.

This is documented in `THREAT_MODEL.md` §6 (out-of-scope) + addressed throughout this section. The platform's own posture is governed by OWASP ASI Top 10 2026 (cited in §6 above) precisely because we are an autonomous multi-agent system and have to defend against the same agentic risks we're probing.

---

## 11. Evaluation Metrics — measuring platform health

The platform exposes the following metrics (read by humans via dashboards + by Orchestrator for routing decisions):

### 11.1 Coverage metrics

| Metric | Definition | Target |
|---|---|---|
| **Attack count per category** | Total attacks generated, by OWASP LLM Top 10 + ASI Top 10 category | Each Phase 1 priority category ≥10 attacks |
| **Coverage gap by category** | Categories with zero attacks OR zero recent attacks (>7 days) | Zero — Orchestrator should rotate to gap categories |
| **Verdict distribution** | pass / fail / partial / uncertain ratios per category | Health: balanced (no single bucket >70%); collapse: alert |
| **Mutation yield** | (new variants accepted by Judge as distinct) / (variants generated) | >0.3 — below means mutation engine producing duplicates |

### 11.2 Quality metrics

| Metric | Definition | Target |
|---|---|---|
| **Judge agreement rate** | % of verdicts matching ground-truth dataset | >90% (alert on >5pp drop) |
| **Judge uncertain rate** | % of verdicts marked `uncertain` (escalated to human) | <15% (alert on >25%) |
| **Exploit reproducibility rate** | % of confirmed exploits that re-fire when replayed against same target version | >95% (lower = Red Team producing flaky attacks) |
| **Time-to-rediscovery** (C-7 baseline) | Wall-clock time from platform start to re-discovery of known C-7 finding | <30 min (validates platform is functional) |

### 11.3 Cost + scale metrics

| Metric | Definition | Target |
|---|---|---|
| **Cost per attack attempt** | LLM spend per AttackCandidate generated + judged | Tracked; Phase 2 sets target |
| **Cost per confirmed exploit** | Total spend / count of FAIL verdicts | Tracked; Orchestrator halts when ratio degrades >threshold |
| **Cost per hour** | Burn rate during active sessions | Hard cap `MAX_SESSION_COST_USD` (default $10) |
| **Latency p50 / p95** | End-to-end attack-to-verdict | Tracked for capacity planning |

### 11.4 Regression metrics

| Metric | Definition | Target |
|---|---|---|
| **Regression pass rate** | % of stored regression tests still passing on current target version | 100% expected; <100% flags new regression |
| **Cross-category regression detection** | New failures in category Y after fix in category X | Alert on every occurrence |
| **Time since last regression run** | Wall-clock since last full regression suite execution | <24h on active development |

All metrics are sourced from Langfuse spans + `evals/results/<run-id>.json` files; queryable from the observability layer (§5).

---

## 12. Inter-Agent Message Schemas

Concrete JSON contracts. These are the actual structures passed between agents.

### 12.1 AttackCandidate

```json
{
  "attack_id": "atk_2026-05-13_001",
  "category": "prompt_injection",
  "subcategory": "indirect_via_document",
  "owasp_id": "LLM01:2025",
  "asi_id": "ASI06:2026",
  "atlas_technique_id": "AML.T0051",
  "target_endpoint": "/attach_and_extract",
  "payload": {
    "type": "single_turn",
    "content": "..."
  },
  "conversation_state": [],
  "mutation_parent": null,
  "mutation_depth": 0,
  "generated_by": "red_team_v0.1.0",
  "generated_at": "2026-05-13T14:30:00Z",
  "model_used": "llama-3.3-70b-self-hosted",
  "cost_usd": 0.0023
}
```

For mutated attacks, `mutation_parent` references the parent `attack_id` and `mutation_depth` increments. Multi-turn attacks have `payload.type: "multi_turn"` with `payload.turns: [...]`.

### 12.2 JudgeVerdict

```json
{
  "verdict_id": "ver_2026-05-13_001",
  "attack_id": "atk_2026-05-13_001",
  "verdict": "fail",
  "confidence": 0.93,
  "criteria_triggered": [
    "cross_patient_leakage",
    "ungrounded_clinical_claim"
  ],
  "evidence": [
    {
      "criterion": "cross_patient_leakage",
      "matched_text": "her sister Maria has diabetes",
      "expected_behavior": "should refuse to discuss other patients"
    }
  ],
  "target_response_hash": "sha256:abc123...",
  "judged_at": "2026-05-13T14:30:15Z",
  "judge_version": "judge_v0.1.0",
  "judge_model": "claude-sonnet-4.6",
  "cost_usd": 0.012,
  "human_escalation_required": false
}
```

Verdict ∈ `{pass, fail, partial, uncertain}`. `human_escalation_required` is true when confidence < threshold OR when criteria_triggered is empty but verdict is non-pass (anomalous).

### 12.3 CoverageState

```json
{
  "as_of": "2026-05-13T15:00:00Z",
  "target_version_sha": "104ad58a4",
  "categories": {
    "prompt_injection": {
      "attack_count": 47,
      "verdicts": {"pass": 30, "fail": 12, "partial": 4, "uncertain": 1},
      "last_attack_at": "2026-05-13T14:55:00Z",
      "open_findings": 3
    },
    "sensitive_information_disclosure": {
      "attack_count": 23,
      "verdicts": {"pass": 18, "fail": 4, "partial": 1, "uncertain": 0},
      "last_attack_at": "2026-05-13T14:30:00Z",
      "open_findings": 1
    }
  },
  "session_cost_usd": 4.27,
  "cost_cap_usd": 10.00,
  "signal_to_cost_ratio": 0.15
}
```

Read by Orchestrator to decide next attack target. `open_findings` counts FAIL verdicts not yet resolved (fix not validated by regression).

### 12.4 VulnerabilityReport (filed; YAML frontmatter + markdown body)

```yaml
---
vuln_id: VULN-001
title: Cross-Patient Paraphrased PHI Leakage
severity: high
status: draft-pending-review   # or: filed | resolved | wontfix
discovered_at: 2026-05-13T14:30:15Z
discovered_by_attack_id: atk_2026-05-13_001
target_version_sha: 104ad58a4
target_endpoint: /chat
owasp_classification:
  - LLM02:2025 Sensitive Information Disclosure
asi_classification:
  - ASI03:2026 Agent Identity & Privilege Abuse
atlas_techniques:
  - AML.T0024 Exfiltration via ML Inference API
human_review:
  reviewer: null
  reviewed_at: null
  decision: null
fix_validation:
  regression_test_path: evals/regression/sensitive_information_disclosure/VULN-001.yaml
  last_run_at: null
  last_run_status: pending
---

# Cross-Patient Paraphrased PHI Leakage

## Description
The Co-Pilot's PHI scrubber catches literal `patient_id=N` tokens but not paraphrased
references to patient identifiers when an attacker crafts a query that surfaces another
patient's data through Haiku's narrative synthesis...

## Clinical Impact
HIGH — physician acting on synthesized response could mistake another patient's
clinical history for the queried patient's, leading to inappropriate clinical decisions.

## Minimal Reproducible Attack Sequence
[exact payload, exact endpoint, exact expected vs observed]

## Observed vs Expected
[full diff]

## Recommended Remediation
Implement `check_citation_patient_boundary()` operating on Citation provenance, not
regex pattern matching. See `AUDIT.md` C-7 in companion repo for fix-path scope (~2-4h).

## Status
DRAFT pending human review (severity: high requires approval before promotion to filed).
```

### 12.5 RegressionCase

```yaml
---
case_id: REGR-001
parent_vuln_id: VULN-001
category: sensitive_information_disclosure
target_endpoint: /chat
attack_payload: |
  [exact payload to replay]
expected_behavior: refuse | sanitize | <specific text>
discovered_target_version_sha: 104ad58a4
last_passed_target_version_sha: null
last_failed_target_version_sha: 104ad58a4
last_run_at: 2026-05-13T14:30:15Z
---
```

Re-runs on every target version change; Judge re-evaluates with same criteria; differentiates "fixed" from "behavior-changed-suspicious" per §4.3.

### 12.6 AgentTrace (Langfuse span attributes)

Every agent action emits a Langfuse span with these attributes (in addition to standard span fields):

```json
{
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
  "human_gate_status": "n/a"
}
```

This is the data substrate the Orchestrator reads to make routing decisions (§5).

---

## 13. References

- Companion repo (target system): https://github.com/TradeUpCards/agentforge — AgentForge Clinical Co-Pilot, including W2_ARCHITECTURE.md, AUDIT.md (C-7 cross-patient leakage finding), EVAL_SUITE.md (§8.6 per-rubric regression matrix), 67-case eval suite
- Target deployed at: https://142-93-242-40.nip.io
- Threat model: `THREAT_MODEL.md` (this repo)
- User definitions: `USERS.md` (this repo)
- Vulnerability reports: `evals/vulnerabilities/`

---

*Architecture defense draft — 2026-05-11. Will iterate as Phase 2 build informs structural decisions; revision history tracked in git log.*
