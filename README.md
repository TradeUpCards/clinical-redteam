# Clinical Red Team Platform

> Autonomous multi-agent adversarial AI security platform for continuously identifying, evaluating, and defending against attacks on the AgentForge Clinical Co-Pilot.

Built for the **GauntletAI Austin Admission Track, Week 3**.

This is a **standalone application** — not a fork of OpenEMR or AgentForge. The target system being tested (the AgentForge Clinical Co-Pilot from Weeks 1 and 2) lives in a [companion repo](https://github.com/TradeUpCards/agentforge); this repo is the attacker.

---

## What this is

A multi-agent system whose only job is to attack the deployed [AgentForge Clinical Co-Pilot](https://142-93-242-40.nip.io), evaluate which attacks succeed, document the confirmed exploits, and validate that fixes hold across system versions — autonomously, continuously, without a human in the loop for every step.

**Four coordinated agents:**

| Agent | Role |
|---|---|
| **Red Team Agent** | Generates novel adversarial inputs; mutates partially-successful attacks into variants; constructs multi-turn attack sequences |
| **Judge Agent** | Independently evaluates each attack as PASS / FAIL / PARTIAL against versioned criteria; calibrated against human-labeled ground truth |
| **Orchestrator Agent** | Reads platform state (coverage, findings, regressions, cost) and decides which attack category to target next; manages cost; halts when signal-to-cost falls below threshold |
| **Documentation Agent** | Converts confirmed exploits into structured vulnerability reports usable by an engineer who was not present when the exploit was found; human approval gate on critical-severity reports |

The system is built around three established frameworks rather than invented taxonomies — see [`ARCHITECTURE.md`](./ARCHITECTURE.md) §6:

- **OWASP Top 10 for LLM Applications v2025** — attack-surface taxonomy for the target
- **OWASP Agentic Security Initiative (ASI) Top 10 2026** — security posture for this platform
- **MITRE ATLAS** — per-attack tactical citation
- **NIST AI Risk Management Framework** — governance lens

---

## Try it

| | |
|---|---|
| **Target system (under attack)** | https://142-93-242-40.nip.io (AgentForge Clinical Co-Pilot — credentials provided via the GauntletAI submission portal; synthetic demo data only, no real PHI) |
| **Companion repo (target)** | https://github.com/TradeUpCards/agentforge |
| **Architecture** | [`ARCHITECTURE.md`](./ARCHITECTURE.md) — multi-agent platform design + agent interaction diagram |
| **Threat model** | [`THREAT_MODEL.md`](./THREAT_MODEL.md) — attack surface map, OWASP coverage, prioritization |
| **Eval suite** | [`evals/`](./evals/) — adversarial test cases by category + results |
| **Vulnerability reports** | [`evals/vulnerabilities/`](./evals/vulnerabilities/) — confirmed exploits in structured report format |
| **Demo video (final submission)** | *Final-submission video link added on final commit* |
| **Social post (final submission)** | *Posted on X; link added on final commit* |
| **GitHub mirror** | *Set up post-defense; URL added here* |
| **GitLab (primary)** | *Set up post-defense; URL added here* |

---

## Documentation map (W3 brief deliverables)

The W3 brief lists 9 required deliverables. Each maps to a file in this repo:

| # | Brief deliverable | Location | What's in it |
|---|---|---|---|
| 1 | **GitHub Repository** | This repo + [`SETUP.md`](./SETUP.md) (post-defense) | Standalone attacker platform; setup guide for running locally + against the deployed target |
| 2 | **Threat Model** | [`THREAT_MODEL.md`](./THREAT_MODEL.md) | Full attack surface map of the target Co-Pilot, anchored on OWASP LLM Top 10 v2025 + OWASP ASI Top 10 2026 + MITRE ATLAS; ~500-word exec summary; prioritization rationale |
| 3 | **User Doc** | [`USERS.md`](./USERS.md) (post-defense) | Users this platform addresses (security engineers, clinical CISO, Co-Pilot dev team), workflows, automation justification |
| 4 | **Architecture Doc** | [`ARCHITECTURE.md`](./ARCHITECTURE.md) | Multi-agent platform architecture; each agent role + inputs/outputs/trust + inter-agent comms + orchestration + regression harness + observability + tradeoffs; ~500-word exec summary; ASCII diagram |
| 5 | **Demo Video (3-5 min)** | *Final-submission video; link in "Try it" above* | Platform running live attacks against deployed target; key decisions; vulnerability reports |
| 6 | **Eval Dataset** | [`evals/`](./evals/) | Adversarial test suite ≥3 attack categories (prompt injection / sensitive info disclosure / unbounded consumption seed cases from W2 + new mutations) + reproducible results |
| 7 | **Vulnerability Reports** | [`evals/vulnerabilities/`](./evals/vulnerabilities/) | ≥3 distinct vuln reports following the required format (severity, repro, observed vs expected, remediation, OWASP + MITRE ATLAS classification) |
| 8 | **AI Cost Analysis** | [`docs/cost-analysis.md`](./docs/cost-analysis.md) (post-defense) | Actual platform dev burn + projections at 100 / 1K / 10K / 100K test runs |
| 9 | **Social Post** *(final only)* | *Posted on X; link added on final commit* | |

---

## Grader checklist — PRD hard gates → file locations

For graders verifying the W3 brief deliverables map cleanly to artifacts in this repo:

| PRD requirement | File / location | Defendable claim |
|---|---|---|
| **Stage 1 HARD GATE — Deployed target URL** | `https://142-93-242-40.nip.io` (this repo references it; the target itself is in the [companion repo](https://github.com/TradeUpCards/agentforge)) | Target is live and accessible; deploy guide in companion repo's `.deploy/README.md` |
| **Stage 2 HARD GATE — `THREAT_MODEL.md`** | [`THREAT_MODEL.md`](./THREAT_MODEL.md) | ~500-word exec summary at top; full attack surface map by OWASP LLM Top 10 v2025 + ASI Top 10 2026 + MITRE ATLAS; prioritization rationale; out-of-scope explicit |
| **Stage 3 HARD GATE — `evals/` with results from ≥3 attack categories + ≥1 working agent role running live against deployed target** | [`evals/`](./evals/) (Phase 2 build) — three categories: prompt injection, sensitive info disclosure, unbounded consumption | MVP vertical slice (`ARCHITECTURE.md` §9.4) names exact deliverables: seed cases, mutation engine, target client, judge, run command, output format |
| **Stage 4 HARD GATE — `ARCHITECTURE.md`** | [`ARCHITECTURE.md`](./ARCHITECTURE.md) | ~500-word exec summary at top; ASCII system diagram (§1) + runtime attack-lifecycle diagram (§1.1); each agent's role / inputs / outputs / trust level (§2); inter-agent coordination (§3); regression harness (§4); observability (§5); framework anchoring (§6); trust boundaries + human approval gates (§7); cost mgmt (§8); tradeoffs (§9); failure modes of platform itself / "testing the tester" (§10); evaluation metrics (§11); inter-agent JSON schemas (§12) |
| **Stage 4 HARD GATE — Deployed target URL submitted with every checkpoint** | `https://142-93-242-40.nip.io` | Top of this README + companion repo |
| **Submission — `USERS.md`** | [`USERS.md`](./USERS.md) | 4 personas (Security Engineer, Clinical AI Platform Owner, Hospital CISO, Compliance Officer) with workflow + automation justification per persona; explicit NOT-the-physician framing |
| **Submission — Demo Video (3-5 min)** | *Final-submission video; link in "Try it"* | Will show platform running live attacks against deployed target + key decisions + ≥3 vuln reports |
| **Submission — `evals/`** | [`evals/`](./evals/) | Same as Stage 3 above |
| **Submission — Vulnerability Reports (≥3 distinct)** | [`evals/vulnerabilities/`](./evals/vulnerabilities/) | VULN-001 = re-discovery of C-7 cross-patient paraphrased leakage (proof of platform); VULN-002 + VULN-003 = novel findings from Red Team mutations; format spec in `ARCHITECTURE.md` §12.4 |
| **Submission — AI Cost Analysis** | [`docs/cost-analysis.md`](./docs/cost-analysis.md) (Phase 2) | Actual W3 dev burn + projections at 100 / 1K / 10K / 100K test runs; per-agent cost attribution from observability layer |
| **Submission — Deployed Application** | `https://142-93-242-40.nip.io` (target) + the platform itself runs locally + against deployed target per `SETUP.md` | Per PRD: "the adversarial platform must be running live tests against the deployed target" |
| **Submission — Setup Guide** | [`SETUP.md`](./SETUP.md) (Phase 2) | How to run platform locally + against deployed target; env vars; HMAC config |
| **Submission — Social Post (Final only)** | *Posted on X/LinkedIn; link added on final commit; tag @GauntletAI* | |

---

## Repo structure

```
ClinicalRedTeam/
├── README.md                              ← this file
├── ARCHITECTURE.md                        ← multi-agent platform architecture
├── THREAT_MODEL.md                        ← attack surface map
├── USERS.md                               ← (post-defense)
├── SETUP.md                               ← (post-defense)
├── agents/                                ← (post-defense)
│   ├── red_team/                          Red Team Agent — attack generation
│   ├── judge/                             Judge Agent — independent evaluation
│   ├── orchestrator/                      Orchestrator Agent — strategic prioritization
│   └── documentation/                     Documentation Agent — confirmed-exploit reporting
├── evals/                                 Adversarial test suite
│   ├── seed/<category>/                   Seed cases per attack category
│   ├── regression/<category>/             Versioned confirmed exploits
│   ├── criteria/<category>.yaml           Judge evaluation criteria per category
│   ├── vulnerabilities/VULN-<NNN>.md      Confirmed-exploit reports
│   └── coverage.md                        Per-category attack count + verdict distribution
├── observability/                         Langfuse integration + dashboards
└── docs/
    ├── cost-analysis.md                   (post-defense)
    ├── governance.md                      (post-defense — NIST AI RMF Govern function)
    └── research/                          Background research artifacts
```

---

## Status

**Phase 1 — Architecture defense** *(in progress 2026-05-11)*
- ✓ Local repo scaffolded
- ✓ `ARCHITECTURE.md` drafted (multi-agent design, 4 agents, framework anchoring, trust boundaries)
- ✓ `THREAT_MODEL.md` drafted (full OWASP LLM + ASI coverage, prioritization)
- ⏳ Architecture defense
- ⏳ Remote setup (GitLab primary + GitHub mirror, mirroring W1/W2 convention)
- ⏳ `USERS.md`, `SETUP.md`, `evals/` scaffold

**Phase 2 — MVP** *(due Tuesday 2026-05-13 11:59 PM)*
- ⏳ ≥1 agent role running live against deployed target
- ⏳ Initial eval suite covering ≥3 attack categories
- ⏳ Reproducible test results

**Phase 3 — Final submission** *(due Friday 2026-05-15 noon)*
- ⏳ Full 4-agent system + Orchestrator running autonomously
- ⏳ ≥3 vulnerability reports filed
- ⏳ Observability dashboard
- ⏳ Cost analysis at 100 / 1K / 10K / 100K scale
- ⏳ Demo video
- ⏳ Social post

---

## License

TBD — likely match the AgentForge companion repo's GPL-3.0 inheritance (from upstream OpenEMR) unless grading guidance suggests otherwise.

---

*This is the W3 deliverable for the GauntletAI Austin Admission Track. The target it attacks (AgentForge Clinical Co-Pilot) shipped in Weeks 1 + 2 — see [companion repo](https://github.com/TradeUpCards/agentforge).*
