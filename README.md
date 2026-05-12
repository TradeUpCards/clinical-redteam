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
| **Target system (under attack)** | https://142-93-242-40.nip.io (AgentForge Clinical Co-Pilot — synthetic test data only, no real PHI) |
| **Attacker platform (this repo, deployed)** | https://redteam-142-93-242-40.nip.io — live status of the adversarial daemon: recent runs, vuln reports, cost ledger |
| **Companion repo (target)** | https://github.com/TradeUpCards/agentforge |
| **GitLab (primary)** | https://labs.gauntletai.com/coryvandenberg/clinical-redteam |
| **GitHub mirror** | https://github.com/TradeUpCards/clinical-redteam |
| **Architecture** | [`ARCHITECTURE.md`](./ARCHITECTURE.md) — multi-agent platform design + agent interaction diagram |
| **Threat model** | [`THREAT_MODEL.md`](./THREAT_MODEL.md) — attack surface map, OWASP coverage, prioritization |
| **Eval suite** | [`evals/seed/`](./evals/seed/) + [`evals/criteria/`](./evals/criteria/) — adversarial seed cases + Judge criteria YAMLs, across 3 attack categories |
| **Vulnerability reports** | [`evals/vulnerabilities/`](./evals/vulnerabilities/) — confirmed exploits in structured report format (VULN-001 ships Tue MVP; VULN-002 / VULN-003 ship by Fri Final) |
| **Demo video (Final submission)** | *Final-submission video link added on final commit* |
| **Social post (Final submission)** | *Posted on X; link added on final commit* |

---

## Running the platform

### Prerequisites

- Python 3.11+ (3.12 verified)
- An OpenRouter API key (used for all agent LLM calls)
- A Langfuse Hobby-tier project (for per-agent traces; optional but recommended)
- Network access to the deployed target Co-Pilot at `https://142-93-242-40.nip.io` — for production deployment, the platform runs co-located with the target on the same droplet so it talks to the Co-Pilot's internal agent service. For local development, you'll need an SSH tunnel to the droplet (see [`SETUP.md`](./SETUP.md), shipping immediately after this README pass).

### Install

```bash
git clone https://github.com/TradeUpCards/clinical-redteam.git
cd clinical-redteam
python -m venv .venv
source .venv/bin/activate        # macOS/Linux. Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

### Configure

Copy the env template and fill in the four required secrets:

```bash
cp .env.example .env
# Edit .env — fill these four:
#   OPENROUTER_API_KEY            (https://openrouter.ai/keys)
#   RED_TEAM_TARGET_HMAC_SECRET   (must match deployed Co-Pilot's OPENEMR_HMAC_SECRET)
#   LANGFUSE_PUBLIC_KEY           (https://cloud.langfuse.com/ → Settings → API keys)
#   LANGFUSE_SECRET_KEY           (same page)
```

Defaults for everything else (model IDs, cost cap $10, sentinel patient IDs, halt thresholds) are sensible for first-run.

### Run — single-shot mode (one attack against the live target)

```bash
python -m clinical_redteam.run \
    --category sensitive_information_disclosure \
    --max-attacks 1
```

Outputs JSON summary to stdout. Run artifacts persist atomically to `evals/results/<run-id>/`:
- `manifest.json` — run metadata
- `attacks/atk_*.json` — Red Team's AttackCandidate
- `verdicts/ver_*.json` — Judge's verdict + structured evidence
- `cost-ledger.json` — per-agent cost breakdown
- `coverage.json` — per-category attack count + verdict distribution

### Run — continuous mode (daemon loop until self-halt)

```bash
python -m clinical_redteam.run \
    --continuous \
    --max-budget 2.00 \
    --halt-on-empty-categories
```

Daemon picks categories per the Orchestrator's routing, dispatches Red Team mutations, processes verdicts, drafts vulnerability reports on FAIL/PARTIAL verdicts, halts on `cost_cap` / `signal_to_cost_collapse` / `coverage_floor_met_no_open` / `max_iterations` / `SIGINT`. Per-iteration JSON line to stdout; final `HaltReport` on exit.

### Resume after restart

The persistence layer atomically checkpoints state before every external call. To resume an interrupted run:

```bash
python -m clinical_redteam.run --continuous --run-id <existing-run-id>
```

---

## Documentation map (W3 brief deliverables)

The W3 brief lists 9 required deliverables. Each maps to a file in this repo:

| # | Brief deliverable | Location | What's in it |
|---|---|---|---|
| 1 | **GitHub Repository** | This repo + [`SETUP.md`](./SETUP.md) *(shipping immediately after this README pass)* | Standalone attacker platform; setup guide for running locally + against the deployed target (SSH tunnel walkthrough included) |
| 2 | **Threat Model** | [`THREAT_MODEL.md`](./THREAT_MODEL.md) | Full attack surface map of the target Co-Pilot, anchored on OWASP LLM Top 10 v2025 + OWASP ASI Top 10 2026 + MITRE ATLAS; ~500-word exec summary; prioritization rationale |
| 3 | **User Doc** | [`USERS.md`](./USERS.md) | 4 personas (Security Engineer, Clinical AI Platform Owner, Hospital CISO, Compliance Officer) + workflows + automation justification per persona |
| 4 | **Architecture Doc** | [`ARCHITECTURE.md`](./ARCHITECTURE.md) | Multi-agent platform architecture; each agent role + inputs/outputs/trust + inter-agent comms + orchestration + regression harness + observability + tradeoffs; ~500-word exec summary; ASCII diagrams |
| 5 | **Demo Video (3-5 min)** | *Final-submission video; link in "Try it" above* | Platform running live attacks against deployed target; key decisions; vulnerability reports |
| 6 | **Eval Dataset** | [`evals/seed/`](./evals/seed/) + [`evals/criteria/`](./evals/criteria/) + [`evals/results/`](./evals/results/) | Adversarial seed cases across 3 categories (SID 5 / PI 6 / UC 6 = 17 seeds); Judge criteria YAMLs per category; run-id'd reproducible results |
| 7 | **Vulnerability Reports** | [`evals/vulnerabilities/`](./evals/vulnerabilities/) | ≥3 distinct vuln reports following the ARCH §12.4 format (severity, repro, observed vs expected, remediation, OWASP + MITRE ATLAS classification). VULN-001 ships at MVP; VULN-002 / VULN-003 by Final. |
| 8 | **AI Cost Analysis** | [`docs/cost-analysis.md`](./docs/cost-analysis.md) (Phase 2) | Actual platform dev burn + projections at 100 / 1K / 10K / 100K test runs; per-agent cost attribution from the cost ledger |
| 9 | **Social Post** *(final only)* | *Posted on X; link added on final commit* | |

---

## Grader checklist — PRD hard gates → file locations

For graders verifying the W3 brief deliverables map cleanly to artifacts in this repo:

| PRD requirement | File / location | Defendable claim |
|---|---|---|
| **Stage 1 HARD GATE — Deployed target URL** | `https://142-93-242-40.nip.io` (this repo references it; the target itself is in the [companion repo](https://github.com/TradeUpCards/agentforge)) | Target is live and accessible; deploy guide in companion repo's `.deploy/README.md` |
| **Stage 2 HARD GATE — `THREAT_MODEL.md`** | [`THREAT_MODEL.md`](./THREAT_MODEL.md) | ~500-word exec summary at top; full attack surface map by OWASP LLM Top 10 v2025 + ASI Top 10 2026 + MITRE ATLAS; prioritization rationale; out-of-scope explicit |
| **Stage 3 HARD GATE — `evals/` with results from ≥3 attack categories + ≥1 working agent role running live against deployed target** | ✓ [`evals/seed/`](./evals/seed/) (17 seeds across 3 categories: SID 5 / PI 6 / UC 6), [`evals/criteria/`](./evals/criteria/) (3 Judge criteria YAMLs), [`evals/results/`](./evals/results/) (run-id'd artifacts from B6 v1 + v2 live runs) | All 4 agents running live end-to-end: Red Team mutates seeds via OpenRouter → HMAC-signed POST to deployed target → Judge renders structured verdict → Documentation auto-drafts on FAIL/PARTIAL → Orchestrator routes + halts. 30+ attacks executed against the live target; cost ledger + coverage state durably persisted. |
| **Stage 4 HARD GATE — `ARCHITECTURE.md`** | [`ARCHITECTURE.md`](./ARCHITECTURE.md) | ~500-word exec summary at top; ASCII system diagram (§1) + runtime attack-lifecycle diagram (§1.1); each agent's role / inputs / outputs / trust level (§2); inter-agent coordination (§3); regression harness (§4); observability (§5); framework anchoring (§6); trust boundaries + human approval gates (§7); cost mgmt (§8); tradeoffs (§9); failure modes of platform itself / "testing the tester" (§10); evaluation metrics (§11); inter-agent JSON schemas (§12) |
| **Stage 4 HARD GATE — Deployed target URL submitted with every checkpoint** | `https://142-93-242-40.nip.io` | Top of this README + companion repo |
| **Submission — `USERS.md`** | [`USERS.md`](./USERS.md) | 4 personas (Security Engineer, Clinical AI Platform Owner, Hospital CISO, Compliance Officer) with workflow + automation justification per persona; explicit NOT-the-physician framing |
| **Submission — Demo Video (3-5 min)** | *Final-submission video; link in "Try it"* | Will show platform running live attacks against deployed target + key decisions + ≥3 vuln reports |
| **Submission — `evals/`** | [`evals/`](./evals/) | Same as Stage 3 above |
| **Submission — Vulnerability Reports (≥3 distinct)** | [`evals/vulnerabilities/`](./evals/vulnerabilities/) | VULN-001 = re-discovery of C-7 cross-patient paraphrased leakage (proof of platform); VULN-002 + VULN-003 = novel findings from Red Team mutations; format spec in `ARCHITECTURE.md` §12.4 |
| **Submission — AI Cost Analysis** | [`docs/cost-analysis.md`](./docs/cost-analysis.md) (Phase 2) | Actual W3 dev burn + projections at 100 / 1K / 10K / 100K test runs; per-agent cost attribution from observability layer |
| **Submission — Deployed Application** | `https://142-93-242-40.nip.io` (target) + the platform itself runs locally + against deployed target per `SETUP.md` | Per PRD: "the adversarial platform must be running live tests against the deployed target" |
| **Submission — Setup Guide** | [`SETUP.md`](./SETUP.md) *(shipping immediately after this README pass)* | Full dev setup walkthrough: venv, env vars, OpenRouter / Langfuse keys, HMAC config, SSH tunnel to deployed target, first run |
| **Submission — Social Post (Final only)** | *Posted on X/LinkedIn; link added on final commit; tag @GauntletAI* | |

---

## Repo structure

```
ClinicalRedTeam/
├── README.md                                  ← this file
├── SETUP.md                                   ← dev setup walkthrough (incoming immediately after this README pass)
├── ARCHITECTURE.md                            ← multi-agent platform architecture (ARCH §0–§13)
├── THREAT_MODEL.md                            ← attack surface map (OWASP LLM v2025 + ASI 2026 + ATLAS + NIST)
├── USERS.md                                   ← 4 personas + workflows
├── RESPONSIBLE_USE.md                         ← dual-use posture, healthcare-specific guidance
├── LICENSE                                    ← Apache 2.0
├── .env.example                               ← env var template (16 vars across 7 sections)
├── pyproject.toml                             ← Python package metadata + ruff/pytest config
├── src/clinical_redteam/
│   ├── schemas.py                             Pydantic inter-agent contracts (ARCH §12)
│   ├── openrouter.py                          OpenRouter client + tier-based fallback chain
│   ├── target_client.py                       HMAC-signed target client + out-of-scope refusal
│   ├── persistence.py                         Atomic-write filesystem layer + resume-after-restart
│   ├── content_filter.py                      Hard refusal categories pre-flight (ARCH §2.1)
│   ├── cost_ledger.py                         Per-run cost tracking + halt-condition inputs
│   ├── coverage.py                            Per-category attack/verdict counters
│   ├── observability.py                       Langfuse + PHI scrubber
│   ├── run.py                                 Single-shot + continuous-mode CLI
│   └── agents/
│       ├── red_team.py                        Red Team Agent (attack generation + mutation)
│       ├── judge.py                           Judge Agent (independent evaluation + injection defense)
│       ├── documentation.py                   Documentation Agent (auto-draft vuln reports)
│       └── orchestrator.py                    Orchestrator daemon (category routing + halt)
├── tests/                                     pytest suite (255 tests at end of Phase 1b)
│   ├── test_schemas.py                        ARCH §12 contract validation
│   ├── test_openrouter.py                     wrapper + fallback semantics
│   ├── test_target_client.py                  HMAC scheme conformance + refusal paths
│   ├── test_persistence.py                    atomic writes + crash-recovery + manifest
│   ├── test_content_filter.py                 refusal coverage per category
│   ├── test_cost_ledger.py                    accounting + cap detection
│   ├── test_coverage.py                       category routing + signal-to-cost
│   ├── test_observability.py                  PHI scrubber + no-op mode
│   ├── test_run.py                            CLI dispatch + halt-reason → exit-code mapping
│   ├── agents/test_red_team.py                Red Team Agent
│   ├── agents/test_red_team_meta.py           Red Team meta-tests (mutation diversity, refusal coverage)
│   ├── agents/test_judge.py                   Judge Agent + Judge-injection regression
│   ├── agents/test_judge_meta.py              Judge meta-tests (calibration drift, prompt-injection corpus)
│   ├── agents/test_documentation.py           Documentation Agent + PHI-in-evidence regression
│   ├── agents/test_orchestrator.py            Orchestrator daemon + value-type tests
│   └── agents/test_orchestrator_meta.py       Orchestrator halt-state-machine meta-tests
├── evals/
│   ├── seed/<category>/                       Adversarial seed cases (17 total across 3 categories)
│   ├── criteria/<category>.yaml               Judge criteria YAMLs (3 categories)
│   ├── regression/<category>/                 Versioned confirmed exploits (Phase 2 build)
│   ├── vulnerabilities/VULN-<NNN>.md          Confirmed-exploit reports (Phase 2 build)
│   └── results/<run-id>/                      Per-run artifacts (untracked by default; atomic-written)
├── docs/
│   ├── cost-analysis.md                       Phase 2 deliverable
│   ├── presearch.html                         Pre-Search Decision Record (PRD App. pp. 13-15)
│   ├── presearch-conversation.md              Pre-Search Decision Dialogue (PRD App. instruction)
│   └── research/                              Pre-search synthesis + framework PDFs
├── .gitlab-ci.yml                             CI gate — fail-closed on regression (currently open in MR #14; lands when that MR merges)
├── .pre-commit-config.yaml                    Pre-commit hooks (currently open in MR #14)
└── scripts/
    └── generate_dashboard.py                  Phase 2 deliverable — static-HTML dashboard generator
```

---

## Status

**Phase 1a — Foundation modules** ✓ *(complete 2026-05-12)*
- ✓ Pydantic inter-agent contract schemas (ARCH §12; 6 models, round-trip-validated)
- ✓ OpenRouter client with tier-based fallback chain (429/5xx/connect/404 → next model)
- ✓ HMAC-signed target client — out-of-scope host refusal, sentinel-PID gate, scheme matches deployed Co-Pilot's `verify_hmac` exactly
- ✓ Filesystem persistence with atomic writes + resume-after-restart manifest
- ✓ Hard content category filter pre-flight (ARCH §2.1 — minors / real PHI / weaponized malware / out-of-scope redirection)
- ✓ Cost ledger + per-category coverage tracker — per-tier breakdown, hard/soft cap, signal-to-cost ratio
- ✓ Langfuse observability + PHI scrubber (sentinel-pid / SSN / name+DOB patterns; no-op when keys absent)
- ✓ Red Team Agent + first C-7 seed YAML + SID Judge criteria YAML
- ✓ Judge Agent with structured-output validation + Judge-injection defense
- ✓ End-to-end CLI — vertical slice live-verified against deployed target

**Phase 1b — Full system** ✓ *(complete 2026-05-12; merged to main)*
- ✓ Documentation Agent — auto-drafts vulnerability reports from FAIL/PARTIAL verdicts; high/critical stays DRAFT
- ✓ Orchestrator daemon — `while not halt:` loop, category selection, halt conditions per ARCH §10.2
- ✓ Continuous-mode CLI extension
- ✓ Resume-after-restart logic
- ✓ Agent-level meta-tests + Quality pass on 5 audit-finding tickets
- ✓ Pre-commit + GitLab CI gate
- ✓ Seed cases shipped across 3 categories — 5 SID, 6 PI, 6 UC seeds
- ✓ Judge criteria YAMLs for all 3 categories
- 🔄 VULN-001 (C-7 rediscovery report) — in progress

**Phase 2 — MVP submission** *(due Tuesday 2026-05-13 11:59 PM)*
- ✓ Multi-agent vertical slice live-verified end-to-end against deployed target
- ✓ Initial eval suite covering 3 attack categories
- ✓ Reproducible test results (run artifacts in `evals/results/<run-id>/`)
- ⏳ README + SETUP polish
- ⏳ VULN-001 finalized
- ⏳ Submission

**Phase 3 — Final submission** *(due Friday 2026-05-16 noon)*
- ⏳ ≥3 vulnerability reports filed (VULN-001 + VULN-002 + VULN-003 from continuous-mode runs)
- ⏳ Observability dashboard (static-HTML; Chart.js inline)
- ⏳ Cost analysis at 100 / 1K / 10K / 100K test runs
- ⏳ Demo video
- ⏳ Social post

---

## License

[Apache 2.0](./LICENSE). The companion target ([AgentForge](https://github.com/TradeUpCards/agentforge)) inherits OpenEMR's GPL-3.0 because it's a fork; this repo is a standalone application, so Apache 2.0 is the appropriate license.

See [`RESPONSIBLE_USE.md`](./RESPONSIBLE_USE.md) for the dual-use posture: this platform is built for *authorized adversarial testing against systems the operator has permission to attack*. Hard content categories — minors, real PHI, weaponized real-world malware, attacks on non-authorized targets — are refused at pre-flight by `content_filter.py` and again at the target client's boundary.

---

*This is the W3 deliverable for the GauntletAI Austin Admission Track. The target it attacks (AgentForge Clinical Co-Pilot) shipped in Weeks 1 + 2 — see [companion repo](https://github.com/TradeUpCards/agentforge).*
