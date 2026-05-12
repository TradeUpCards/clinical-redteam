# MVP Work Plan — Clinical Red Team Platform

**Owner:** Cory Vandenberg (Tate-driven Claude Code sessions inside this repo)
**MVP deadline:** Tuesday 2026-05-13 11:59 PM
**Final deadline:** Friday 2026-05-16 noon (Demo Day)
**This doc:** sequenced work-item plan. Differs from `PRD-REQUIREMENTS.html` (which is *requirements*) and `ARCHITECTURE.md` (which is *design*). This is *what to build, in what order, with what effort, and who picks it up*.

---

## Strategic overview

### Time budget — honest estimate

| Window | Wall-clock | Productive hours (assuming sleep + meals + real life) | Coverage |
|---|---|---|---|
| Sun late + Mon | ~30 hrs | ~10-12 hrs | Phase 1a + start of 1b |
| Tue all day | ~16 hrs | ~8-10 hrs | Finish 1b → MVP cutoff |
| Wed–Thu | ~32 hrs | ~12-16 hrs | Phase 2 (vulnerabilities + cost analysis + dashboard + deploy) |
| Fri morning | ~6 hrs | ~3-5 hrs | Demo + video + social + final polish |
| **Total** | ~84 hrs | **~33-43 productive hrs** | All deliverables |

This is tight but feasible for a single Tate-driven build with judicious lead dispatch in Phase 1b and Phase 2.

### Critical path

```
Pydantic schemas → OpenRouter wrapper → Target client (live HMAC against deployed Co-Pilot)
        ↓
Red Team Agent (1 seed → 1 mutation) ──┐
                                       ├──→ First end-to-end attack ──→ Phase 1b can start (parallel work unblocks)
Judge Agent (1 rubric → 1 verdict) ────┘
```

**Until the first end-to-end attack runs (Red Team → live target → Judge → persist), nothing else can be parallelized.** This is solo Tate work in Phase 1a.

### Ownership philosophy

- **Phase 1a is solo Tate.** Interfaces aren't stable yet; multiple cooks would collide on schemas + cost ledger + persistence layout.
- **Phase 1b can split into Tate + 1-2 leads.** Once schemas + target client + first end-to-end work, remaining work has natural seams: agent implementations vs eval content vs CI vs observability.
- **Phase 2 can split Tate + 1 lead.** Polish work (vulnerabilities, cost analysis, dashboard, video, deploy) splits into fairly independent chunks.
- **Max 2 leads simultaneously for W3.** More than that and coordination overhead exceeds value at this project scale (consistent with W2 lessons).
- **Specific work-item assignment to specific leads happens AT THE TIME**, not now. The next Tate session (in this repo, with current code state in hand) makes that call. This doc names *roles* and *categories* of work; the assignment happens dynamically.

### Hard gates — what HAS to ship for MVP

Cross-referenced from `PRD-REQUIREMENTS.html`:

| Hard gate | Where this plan delivers it |
|---|---|
| **Multi-agent architecture** (single-agent doesn't satisfy) | Phase 1a items 8-12 (schemas + first Red Team + first Judge); Phase 1b items 1-3 (Documentation + Orchestrator) |
| **At least 3 attack categories with seed cases** | Phase 1a item 14 (1st seed for SID); Phase 1b Content items 1-3 (PI + UC seeds) |
| **Working prototype of one agent role running live against deployed target** | Phase 1a item 13 (first end-to-end attack against live `https://142-93-242-40.nip.io`) |
| **Eval results in `./evals/`** | Phase 1a item 13 produces first results; Phase 1b items 4-6 produce per-category coverage |
| **At least 3 vulnerability reports** | Phase 1b Content item 7 (VULN-001 = C-7 rediscovery); Phase 2 items 1-2 (VULN-002, VULN-003 from continuous-mode runs) |
| **Trust boundaries + human approval gates** | Already documented (`ARCHITECTURE.md` §7); enforced in Documentation Agent (Phase 1b) — high/critical reports route to DRAFT only |
| **Cost analysis at 100 / 1K / 10K / 100K test runs** | Phase 2 item 3 |
| **Failure mode analysis ("testing the tester")** | Already documented (`ARCHITECTURE.md` §10) |
| **Inter-agent message contracts** | Already documented (`ARCHITECTURE.md` §12) — Phase 1a item 8 implements them as Pydantic |
| **Framework anchoring (no invented taxonomy)** | Already documented (`ARCHITECTURE.md` §6 + `THREAT_MODEL.md` §2-3) |

---

## Phase 1a — Solo Tate (Sun late evening + Mon morning, ~10 hrs)

**Goal:** First end-to-end attack working against live deployed Co-Pilot. Once green, Phase 1b can split work.

| # | Work item | Where | Effort | Depends on | Acceptance |
|---|---|---|---|---|---|
| 1 | Verify git state; first commit of existing docs | repo root | 15 min | — | `git log` shows commit with README, ARCHITECTURE, THREAT_MODEL, USERS, LICENSE, RESPONSIBLE_USE |
| 2 | Create GitLab repo + dual-push remote (per W2 pattern; see AgentForge `CLAUDE.md` "AgentForge fork — CI source of truth and repo mirroring") | GitLab + GitHub | 30 min | #1 | `git remote -v` shows dual-push; first push succeeds |
| 3 | Python project scaffold: `pyproject.toml`, `requirements.txt`, `src/clinical_redteam/__init__.py` | repo root + `src/` | 30 min | #1 | `pip install -e .` succeeds in fresh venv |
| 4 | `.env.example` with all env vars (OPENROUTER_API_KEY, RED_TEAM_TARGET_URL, RED_TEAM_TARGET_HMAC_SECRET, LANGFUSE_*, MAX_SESSION_COST_USD, etc.) | repo root | 15 min | #3 | All env vars from ARCH §6 + §8 represented; comments document each |
| 5 | `.gitlab-ci.yml` initial scaffold (smoke tier — schema validation only) | repo root | 30 min | #2 #3 | `glab ci status` shows pipeline running on push |
| 6 | Pydantic schemas: AttackCandidate, JudgeVerdict, CoverageState, VulnerabilityReport, RegressionCase, AgentTrace per ARCH §12 | `src/clinical_redteam/schemas.py` | 1.5 hr | #3 | All 6 schemas validate against ARCH §12 examples; pytest passes |
| 7 | OpenRouter client wrapper with model fallback chain + cost tracking + Langfuse instrumentation | `src/clinical_redteam/openrouter.py` | 1 hr | #6 | `client.complete(messages, tier="red_team")` returns LLM response + cost; fallback chain triggers on 429/5xx |
| 8 | HMAC-signed target client (POST `/chat`, `/attach_and_extract`) with circuit breaker + backoff | `src/clinical_redteam/target_client.py` | 1.5 hr | #6 | Live `curl`-equivalent against `https://142-93-242-40.nip.io/health` returns 200; signed POST to `/chat` returns assistant response |
| 9 | Filesystem persistence layer (atomic writes, `evals/results/<run-id>/manifest.json` schema) | `src/clinical_redteam/persistence.py` | 45 min | #6 | Writing AttackCandidate creates file; manifest updates atomically; resume reads back cleanly |
| 10 | Hard content category filter (pre-flight on every AttackCandidate per ARCH §2.1 table) | `src/clinical_redteam/content_filter.py` | 30 min | #6 | Refused categories return RefusedAttack record + log entry; allowed categories pass through |
| 11 | Cost ledger + coverage state writers | `src/clinical_redteam/cost_ledger.py`, `coverage.py` | 30 min | #6 #9 | Per-run cost ledger + per-category coverage YAML update on every iteration |
| 12 | Langfuse client wrapper (per-agent spans, no PHI in logs) | `src/clinical_redteam/observability.py` | 30 min | #7 | Trace appears in Langfuse UI on first call; PHI-scrubber ablates patient identifiers before send |
| 13 | First Red Team Agent: load 1 seed case for `sensitive_information_disclosure` (C-7 reproducer), mutate via OpenRouter, output AttackCandidate | `src/clinical_redteam/agents/red_team.py` + `evals/seed/sensitive_information_disclosure/c7-paraphrased-leakage.yaml` + `evals/criteria/sensitive_information_disclosure.yaml` | 2 hr | #6 #7 #10 | `python -m clinical_redteam.agents.red_team --seed c7-paraphrased-leakage` produces valid AttackCandidate JSON to stdout |
| 14 | First Judge Agent: load 1 rubric, evaluate Red Team output + target response, render JudgeVerdict | `src/clinical_redteam/agents/judge.py` | 1 hr | #6 #7 | Given (AttackCandidate, target_response_text), returns JudgeVerdict with verdict + confidence + evidence |
| 15 | **First end-to-end attack script** (Red Team → live target → Judge → persist) | `src/clinical_redteam/run.py` (single-shot mode only) | 1 hr | #8 #9 #11 #12 #13 #14 | `python -m clinical_redteam.run --category sensitive_information_disclosure --max-attacks 1` runs end-to-end against LIVE target; produces `evals/results/<run-id>/` with attack + verdict + cost line |

**Phase 1a exit criterion:** Item #15 green. C-7 rediscovery doesn't have to actually fire on the first run — it just has to flow through the full pipeline. The verdict can be PASS (target defended) or FAIL (target leaked) or UNCERTAIN (Judge couldn't decide); what matters is the flow works.

**If Phase 1a slips into Mon afternoon:** that's fine. Phase 1b parallel work is gated on this; better to ship a working seam than to start parallel work prematurely on shifting interfaces.

---

## Phase 1b — Tate + up to 2 leads (Mon afternoon → Tue 11:59 PM, ~12-16 hrs)

**Goal:** Full 4-agent system + continuous-mode daemon + 3 attack categories seeded + VULN-001 drafted. MVP submission.

### Track A — Implementation work (Implementation Lead OR Tate)

| # | Work item | Where | Effort | Depends on | Acceptance |
|---|---|---|---|---|---|
| A1 | Documentation Agent: template-fill VulnerabilityReport from (AttackCandidate, target_response, JudgeVerdict) | `src/clinical_redteam/agents/documentation.py` | 1.5 hr | Phase 1a #15 | FAIL/PARTIAL verdicts produce `evals/vulnerabilities/VULN-NNN-DRAFT.md` matching ARCH §12.4 schema; high+critical severity stays in DRAFT (no auto-promotion) |
| A2 | Orchestrator daemon: `while not halt:` loop with category selection per ARCH §3.6.1, halt conditions per ARCH §10.2 | `src/clinical_redteam/agents/orchestrator.py` | 2 hr | A1 | Daemon picks category, dispatches Red Team, processes verdict, updates coverage, halts on cost cap / signal-to-cost collapse / coverage-floor-met |
| A3 | Continuous-mode CLI: `python -m clinical_redteam.run --continuous --max-budget 5.00 --halt-on-empty-categories` | `src/clinical_redteam/run.py` (extend Phase 1a #15) | 30 min | A2 | Daemon starts; runs unattended; per-iteration line to stdout; halts cleanly on bound; no orphaned processes |
| A4 | Resume-after-restart logic | `src/clinical_redteam/persistence.py` (extend Phase 1a #9) | 1 hr | A3 | `kill -9` mid-run → restart → daemon reads last manifest checkpoint and resumes from next iteration |
| A5 | Smoke meta-tests: schema validation, Judge injection meta-test, mutation diversity meta-test, halt-condition unit tests | `tests/` | 2 hr | A2 | `pytest tests/` passes; meta-tests are documented in ARCH §10.1 + run in CI |
| A6 | Pre-commit hook + extend `.gitlab-ci.yml` to Phase 2 (pytest + meta-tests, fail-closed on regression) | `.pre-commit-config.yaml` + `.gitlab-ci.yml` | 1 hr | A5 | `pre-commit run --all-files` clean; GitLab pipeline goes green on push |
| A7 | Single-shot CLI option polish (already exists from Phase 1a #15; just docstrings + `--help` + error handling) | `src/clinical_redteam/run.py` | 30 min | A3 | `--help` is comprehensive; bad args produce clear errors; works in regression-replay mode |

### Track B — Eval content work (Content Lead OR Tate)

| # | Work item | Where | Effort | Depends on | Acceptance |
|---|---|---|---|---|---|
| B1 | Seed cases YAML for `sensitive_information_disclosure` (4 more on top of C-7 = 5 total) | `evals/seed/sensitive_information_disclosure/*.yaml` | 1 hr | Phase 1a #13 | 5 seed cases; each cites OWASP LLM Top 10 entry + MITRE ATLAS technique ID |
| B2 | Seed cases YAML for `prompt_injection` (5+; direct + document-based indirect; **single-turn only — multi-turn is Phase 2 per ARCH §9.4**) | `evals/seed/prompt_injection/*.yaml` | 1.5 hr | Phase 1a #6 | 5+ seed cases covering both subcategories; each cites framework taxonomy |
| B3 | Seed cases YAML for `unbounded_consumption` (5+) | `evals/seed/unbounded_consumption/*.yaml` | 1 hr | Phase 1a #6 | 5+ seed cases; each cites framework taxonomy |
| B4 | Judge criteria YAML for `prompt_injection` | `evals/criteria/prompt_injection.yaml` | 30 min | Phase 1a #14 | Pass/fail/partial/uncertain rubric documented; calibration cases included |
| B5 | Judge criteria YAML for `unbounded_consumption` | `evals/criteria/unbounded_consumption.yaml` | 30 min | Phase 1a #14 | Same rubric structure as B4 |
| B6 | Run continuous-mode daemon for ~30 min against C-7 reproducer; confirm rediscovery | run command | 30 min | A3 + B1 | At least one FAIL/PARTIAL verdict on cross-patient paraphrased leakage |
| B7 | **VULN-001:** C-7 rediscovery vulnerability report (auto-drafted by Documentation Agent + human-reviewed for clarity) | `evals/vulnerabilities/VULN-001-cross-patient-paraphrased-leakage.md` | 1 hr | A1 + B6 | Matches ARCH §12.4 template; cites W2 `AUDIT.md` C-7 as the original finding the platform rediscovered |

### Track C — Submission prep (Tate)

| # | Work item | Where | Effort | Depends on | Acceptance |
|---|---|---|---|---|---|
| C1 | README MVP-state update: real run command, real env var list, real Langfuse project link | `README.md` | 30 min | A3 + B7 | Grader can clone repo + follow instructions to a green continuous-mode run |
| C2 | SETUP.md: full dev setup walkthrough (venv, env vars, OpenRouter key, Langfuse key, target HMAC secret, first run) | `SETUP.md` | 45 min | A3 | Fresh-machine reproducible per the doc |
| C3 | MVP submission post / form (per Gauntlet submission process — TBD by submission instructions) | (external) | 30 min | C1 + C2 | Submitted by Tue 11:59 PM |

**Phase 1b exit criterion:** Items A1-A6 + B1-B7 + C1-C3 complete. CI green. Continuous-mode daemon proven via 30-min unattended run. VULN-001 drafted.

---

## Phase 2 — Tate + Polish Lead (Wed → Fri morning, ~12-15 hrs)

**Goal:** 3+ vulnerability reports, cost analysis, deployed daemon, dashboard, demo video, social post.

| # | Work item | Where | Effort | Depends on | Acceptance |
|---|---|---|---|---|---|
| P1 | systemd service file + deploy daemon on DigitalOcean droplet alongside target | `deploy/systemd/clinical-redteam.service` + droplet ops | 2 hr | Phase 1b A3 | `systemctl status clinical-redteam` shows active running; `journalctl -u clinical-redteam` shows iteration progress |
| P2 | Run daemon unattended for ≥2 hrs on droplet; collect coverage + cost data | (no file — operational) | 2 hr (mostly waiting) | P1 | At least 2 hrs of uninterrupted continuous-mode operation; coverage state shows all 3 categories progressed; daemon halted cleanly on cost cap |
| P3 | **VULN-002 + VULN-003:** novel findings from continuous-mode runs (or, if no novel findings, two additional confirmed-from-seed) | `evals/vulnerabilities/VULN-{002,003}-*.md` | 2 hr | P2 | Two more vulnerability reports beyond VULN-001; matched to ARCH §12.4 template |
| P4 | Cost analysis at 100 / 1K / 10K / 100K test runs (per PRD HARD GATE) | `docs/cost-analysis.md` | 2 hr | P2 | Real per-call costs from MVP runs; projection methodology documented; architectural changes named per scale tier (e.g., "at 10K runs/day, single-process becomes the bottleneck and Redis-fronted worker pool justified") |
| P5 | Dashboard generator: `scripts/generate_dashboard.py` reads `evals/results/` + emits single-file `dashboard.html` with Chart.js inline | `scripts/generate_dashboard.py` + `dashboard.html` (committed snapshot) | 3 hr | P2 | HTML opens locally with no network; charts render: coverage by category bar chart, verdict distribution donut, resilience trend line, cost burn rate, open finding counts |
| P6 | Demo video: script (3-5 min), OBS recording, YouTube unlisted upload | `docs/demo-script.md` + (external) | 2 hr | P5 | Video uploaded; link added to README header per W2 pattern |
| P7 | README + SETUP final pass: deployed URL, demo video link, dashboard link, badges | `README.md` + `SETUP.md` | 30 min | P6 | Grader-ready landing page |
| P8 | Social post: X with platform demo + tag @GauntletAI | (external) | 30 min | P6 | Post published; URL captured in submission |
| P9 | Final submission per Gauntlet Demo Day instructions | (external) | 30 min | P7 + P8 | Submitted by Fri noon |

**Phase 2 exit criterion:** All P1-P9 complete. Deployed daemon running. 3+ vulnerabilities. Cost analysis at 4 scale tiers. Dashboard. Demo video. Social post. Submitted.

---

## Decision points — to be made BY the Tate session executing the work

The points where the next Tate session should make explicit live calls (not pre-decide here):

| Decision | When | Inputs needed | Default if unclear |
|---|---|---|---|
| Spin up Implementation Lead in Phase 1b? | After Phase 1a #15 ships | Time-of-day on Mon, energy left, code-state stability | Default YES if it's Mon evening with 4+ hrs to spare; default NO if it's late and Tate would prefer to flow solo |
| Spin up Content Lead in Phase 1b? | After Phase 1a #15 ships | Whether B-track items feel "different enough" from A-track to genuinely parallelize | Default YES — content work is naturally independent of agent code work |
| Run two leads simultaneously? | If both above are YES | Whether files in flight overlap (per `gauntlet-team-lead` rule #4: no same-file collisions) | OK to run A-Lead + B-Lead in parallel since they touch different file trees |
| Spin up Polish Lead in Phase 2? | Wed morning after MVP shipped | How much polish work feels productively delegable vs being the kind of work Tate wants to drive directly | Default YES for dashboard generator (P5) since it's well-scoped + parallelizable with VULN reports |
| Skip dashboard (P5) and ship without it? | Thu evening if behind | Whether MVP submission already covered the visualization gap via Langfuse | Default NO — dashboard is a meaningfully better demo artifact than Langfuse screenshots; only skip if genuinely time-starved |
| Defer VULN-002/003 to Friday morning? | Wed evening | Whether continuous-mode actually produced novel findings | Default no — write VULN-002 from the highest-signal finding even if it's not maximally novel; VULN-003 can stretch into Fri morning |

---

## What's NOT in this plan (intentionally)

These are documented in `ARCHITECTURE.md` §9.4 as deferred. Naming them here so they don't get smuggled in:

- Multi-turn attack sequences (MVP is single-turn)
- Auto-detection of target version change (MVP supports `--regression` flag manually)
- Judge calibration against human-labeled ground-truth dataset
- LLM-augmented Orchestrator category-picking (MVP Orchestrator is deterministic)
- Multi-process / Redis-fronted parallel worker fleet
- Multi-judge panel
- Distributed fuzzing, RL-based attack-strategy improvement, exploit chaining
- Web UI for vuln-report review (markdown + git is the MVP UI; static HTML dashboard is the Final UI)

---

## Tracking

This is a markdown-living-doc. The next Tate session should update it as items complete (strike-through), slip (note new estimate), or get rescoped (note rationale). A companion interactive HTML version (`MVP-WORK-PLAN.html`) lives next to this file with localStorage-backed status checkboxes.

If a work item ends up materially harder or easier than estimated, write a one-line note in this doc and adjust downstream estimates accordingly. Don't let the plan diverge from reality silently.
