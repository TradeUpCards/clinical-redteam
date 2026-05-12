# Clinical Red Team Platform — Ops & Infrastructure Pre-Search Research

**Sections owned:** §2 Scale & Performance, §3 Reliability Requirements, §8 Observability Strategy (deep comparison), §14 Open Source Planning, §15 Deployment & Operations, §16 Iteration Planning

**Research date:** 2026-05-11  
**Inputs:** Presearch.pdf (checklist), W3 PRD (15 pp), ARCHITECTURE.md, THREAT_MODEL.md, README.md  
**Pricing data sourced:** Live page fetches 2026-05-11 for Langfuse, LangSmith, Helicone, Braintrust  

---

## §2 — Scale & Performance

### What we've decided

ARCHITECTURE.md §3.2 and the exec summary commit to: single-process daemon, `while True:` loop driven by the Orchestrator, in-process LangGraph state, filesystem-checkpointed artifacts, no message queue for MVP. Hard cost cap via `MAX_SESSION_COST_USD` env var (default $10/session). OpenRouter as the routing layer for all hosted-model calls. ARCHITECTURE.md §8.1 defines per-session hard/soft caps.

### Options researched

| Dimension | Decision / Option | Pros | Cons | Fit for our context |
|---|---|---|---|---|
| **Query volume (continuous mode)** | ~10-100 attacks/session for MVP; potentially 200-500/week in sustained mode | Manageable with single process | If Orchestrator loops aggressively overnight, can spike unexpectedly | Bounded by cost cap, not by infra; MVP-appropriate |
| **Attack generation latency** | 5-30s per attack (OpenRouter call + target call + Judge call) | Human-comprehensible pace | Not real-time; unsuitable for interactive use | Correct for security testing; no latency SLA needed |
| **Concurrent testing** | Single-process sync (MVP) | Simple, auditable, crash-recoverable | Cannot parallelize attack categories | Justified at MVP volume; Phase 3 concern |
| **Cost at MVP scale (5-day)** | ~$5-15 dev burn on LLM calls; $0 infra if run locally | Matches $10 session cap default | No headroom for bugs that loop | See budget table below |

**Proposed weekly budget at each scale:**

| Scale | Test runs/week | Estimated LLM cost | Notes |
|---|---|---|---|
| MVP (5-day, single operator) | ~100 | $5-15 | Red Team (cheap open model) + Judge (Sonnet 4.6) + Doc Agent (~3 vuln reports) |
| 100 runs | 100 | ~$10-20 | Dominated by Judge (Sonnet 4.6); ~$0.05-0.15/run depending on attack length |
| 1K runs | 1,000 | ~$80-150 | Orchestrator model starts mattering; OpenRouter volume discount possible |
| 10K runs | 10,000 | ~$600-1,200 | Requires Judge model downgrade or batching; Sonnet 4.6 at 10K runs ≈ expensive |
| 100K runs | 100,000 | ~$4,000-10,000+ | Requires architectural changes: batch Judge calls, cheaper Judge (Haiku-class), distributed Red Team workers, Redis-fronted queue; single process not viable |

**Architectural changes needed by scale threshold:**

- 100 runs: no changes; single process, local
- 1K runs: add async Red Team (parallel attack generation within a category); OpenRouter rate limits become the constraint
- 10K runs: Judge model swap to Haiku-class for triage; Sonnet only for uncertain cases; add Redis queue for attack jobs
- 100K runs: distributed Red Team workers (Celery or similar); Judge pool; Langfuse retention tier upgrade; DigitalOcean or equivalent cloud host required (Cory's laptop not viable)

### Recommended path

MVP: single-process daemon with $10/session hard cap, ~$15 total W3 dev burn budget for LLM calls. Accept that cost projections at 10K+ scale require a different architecture — document the threshold explicitly in `docs/cost-analysis.md`.

### Tradeoffs owned

1. Single-process sync means one slow OpenRouter or target call can stall the entire loop. Mitigated by per-call timeouts and Orchestrator circuit breaker, but not eliminated.
2. $10/session cap makes overnight runs conservative — the daemon will halt before running 200 attacks if each attack costs $0.10. Tune default cap after seeing real per-attack costs.
3. Cost projections at 10K+ are model-dependent and will diverge from actuals as OpenRouter pricing and available models shift.
4. Token budget per session favors shorter attacks; very long multi-turn sequences (8+ turns) eat the budget disproportionately. Document this as a constraint on multi-turn coverage depth at MVP.
5. No autoscaling in the daemon means throughput scales with Cory's machine clock, not demand. Correct for a 5-day project; wrong for a product.

### Open questions for Cory

1. What is the actual OpenRouter rate limit on the accounts being used? This is the real throughput ceiling for MVP, not infra.
2. Should the cost cap default be higher ($25?) to allow longer overnight runs, with a daily-spend alert instead of a hard halt?
3. At what point does a CISO demo require showing "the platform ran overnight unattended" — and does that require cloud deploy?

---

## §3 — Reliability Requirements

### What we've decided

ARCHITECTURE.md §7 defines human approval gates: high/critical severity reports require human review before filing. Judge uncertainty escalates to human. Cost ceiling triggers halt + human resumption. Documentation Agent auto-files low/medium severity only.

THREAT_MODEL.md acknowledges the platform itself operates under OWASP ASI Top 10 2026 (ASI01–ASI10) as the governance lens for the platform's own security posture.

### Options researched

**False negative vs. false positive cost analysis for healthcare adversarial-testing context:**

| Error type | What happens | Cost in context |
|---|---|---|
| **False negative** (missed vulnerability) | A real exploit against the Clinical Co-Pilot goes undiscovered | HIGH — a missed PHI-leakage exploit in production means real patient data leaks; clinical decisions made on manipulated output cause patient harm. In the C-7 case, cross-patient paraphrased leakage already confirmed as HIGH-severity deferred finding. |
| **False positive** (safe behavior flagged as vulnerable) | Engineering time wasted chasing non-issues; CISO credibility of the platform erodes | MEDIUM — wastes time, can cause over-rotation away from real work; but no patient harm |
| **Judge calibration drift** | Judge verdicts shift from ground truth as target system evolves | COMPOUNDING — false negatives accumulate silently over time; the regression harness appears green while real vulnerabilities exist |

**PRD requirement on human-in-the-loop gates (PRD pp. 9, 10):** explicitly requires human approval before filing high/critical-severity reports and before any remediation ticket. ARCHITECTURE.md §7.2 implements this. The gate is required by both the PRD and by good security-testing practice (a falsely-filed critical finding can trigger an incident response).

**HHS AI Strategy alignment (2024+ HHS AI Compliance Plan):** The HHS AI Strategy emphasizes governance, auditability, and human oversight for AI systems in clinical settings. The platform's NIST AI RMF alignment (Govern/Map/Measure/Manage) maps to HHS's framework, particularly:
- The audit trail per §7.3 maps to HHS's traceability requirement
- The human approval gate on high/critical findings maps to HHS's meaningful human oversight requirement
- The vulnerability report format maps to HHS's incident documentation expectations

This is a grader-defensible framing: "our human gates are not a convenience — they are required by both the PRD and by HHS AI governance expectations for clinical AI systems."

**Compliance implications for security testing of a healthcare system:**
- The platform itself does NOT handle real PHI. It attacks a target system using synthetic demo data only (README confirms: "synthetic demo data only, no real PHI"). This is a material fact that limits compliance exposure.
- The attack payloads may reference synthetic patient identifiers as part of injection attempts. These are crafted adversarial strings, not real patient data. Document this explicitly.
- If the platform were used against a system with real PHI (production use beyond this project), a BAA with the observability provider would be required. Langfuse Pro tier offers BAA (HIPAA). Documented as a known limitation for post-project use.

### Recommended path

Document the false-negative/false-positive asymmetry in `docs/cost-analysis.md` or ARCHITECTURE.md §3 with the framing above. Keep the existing human gate design. Add explicit callout that platform uses synthetic data and therefore does not itself trigger HIPAA requirements — but note that any production deployment against a real-PHI system would require BAA with observability provider (Langfuse Pro+ covers this).

### Tradeoffs owned

1. Human gates on high/critical reports mean a slow reviewer blocks the Orchestrator's ability to declare coverage complete. Accept: autonomous continuous testing continues; only report-filing is gated.
2. The false-negative cost asymmetry means erring toward "escalate to human on uncertainty" is correct. Judge uncertainty threshold should be set conservatively (high confidence required for auto-file).
3. The platform has no mechanism to force a fix — it can only document and report. The remediation path is owned by the Co-Pilot team. This is correct scoping but limits the platform's standalone value.
4. Overnight autonomous runs without human monitoring create a "what did it do while I slept?" audit problem. Full audit trail (§7.3) mitigates but does not eliminate this.
5. HHS AI compliance framing is aspirational at 5-day project scale. Honest framing: "designed to be compliant with HHS AI governance expectations; not yet audited against them."

### Open questions for Cory

1. Does the GauntletAI grader expect the platform to reference HHS AI compliance explicitly, or is NIST AI RMF sufficient?
2. Is there a scenario where the platform would run against a target with real PHI (e.g., a real hospital's OpenEMR)? If so, Langfuse Pro tier and its BAA become required.
3. Should false-negative cost be quantified in the cost analysis (e.g., "a missed C-7-class vulnerability = X patient records exposed per day of operation")?

---

## §8 — Observability Strategy — Deep Comparison

### What we've decided

ARCHITECTURE.md §5 states: "Single source of truth: Langfuse (already wired in target Co-Pilot; extend to platform agents)." This is a stated decision, not a fully defended one. The PRD (appendix p. 14) explicitly names this as a graded question: "LangSmith vs. Langfuse vs. Braintrust vs. custom — which surfaces inter-agent traces?" The ARCHITECTURE.md answer ("Langfuse") needs to survive grader challenge.

### Options researched (all pricing as of 2026-05-11)

**Langfuse**

Langfuse is an open-core LLM observability and evaluation platform. The SDK was rewritten in v4 in March 2026. Plans as of 2026-05-11:

- **Hobby (free):** 50k observations/month, 30-day data retention, 2 users, community support, no credit card
- **Core ($29/month):** 100k obs + $8/100k additional, 90-day retention, unlimited users, in-app support
- **Pro ($199/month):** 100k obs + $8/100k, 3-year retention, SOC2 + ISO27001 reports, BAA available (HIPAA), high rate limits
- **Enterprise ($2,499/month):** custom volume, audit logs, SCIM, SLA, dedicated support

Inter-agent trace support: Yes. "Traces and Graphs (Agents)" is listed as a core feature across all plans, including Hobby. Session tracking, user tracking, token and cost tracking all included. The observation unit is flexible — a multi-agent LangGraph run can emit nested spans with parent-child relationships that Langfuse renders as a graph.

LangGraph integration: native. Langfuse ships a LangGraph callback handler. The target Co-Pilot (W1/W2) already uses Langfuse with LangGraph — this is proven, not aspirational.

OpenRouter integration: Langfuse can capture cost attribution when OpenRouter passes through provider cost headers. In practice, OpenRouter's `x-openrouter-cost` header is parseable from the response; the Langfuse trace span can record this as a custom attribute. Not fully automatic but implementable in one function.

Healthcare fit: Pro tier offers BAA. Hobby tier (what we'll use for W3) does not — but the platform uses synthetic data, so no BAA required for W3.

Self-host option: Yes (Docker Compose, Kubernetes, cloud templates). This is important if a future production deployment requires data residency.

**LangSmith**

LangChain's hosted observability and evaluation platform. Plans as of 2026-05-11:

- **Developer (free):** 5k base traces/month, then pay-as-you-go; 1 seat; community support; tracing, monitoring, online/offline evals, prompt hub
- **Plus ($39/seat/month):** 10k base traces/month; email support; unlimited seats; unlimited Fleet agents; 500 Fleet runs/month
- **Enterprise (custom):** self-hosted or hybrid VPC option; custom SSO/RBAC; access to deployed engineering team

Inter-agent trace support: Yes. LangSmith is purpose-built for LangChain/LangGraph traces and natively surfaces hierarchical agent runs, step-level inputs/outputs, latency, and token costs.

LangGraph integration: first-class. LangSmith and LangGraph are sibling products from LangChain Inc. Instrumentation is zero-config when LangGraph is in use.

OpenRouter integration: requires manual span enrichment for cost attribution (same as Langfuse). LangSmith can track token usage at the span level; OpenRouter cost must be added as custom metadata.

Healthcare fit: Enterprise tier offers self-hosted (VPC); no explicit BAA mentioned in the public pricing page. Healthcare-sensitive deployments would need to verify BAA availability via sales.

Cost: Developer plan is free for our volume (5k traces/month is sufficient at MVP scale of ~100-500 attacks). Pay-as-you-go thereafter.

Key downside for W3: LangSmith is optimized for teams already invested in the LangChain ecosystem. The W3 platform uses LangGraph (a LangChain product) but the target Co-Pilot already uses Langfuse. Running two separate observability stacks (Langfuse for target, LangSmith for platform) would fragment the inter-agent trace story — the grader question specifically asks which surfaces inter-agent traces across the SYSTEM, not just the platform.

**Braintrust**

Eval-focused observability platform. Plans as of 2026-05-11:

- **Starter ($0/month):** 1 GB processed data + $4/GB; 10k scores + $2.50/1k; 14-day retention; unlimited users, projects, datasets, experiments
- **Pro ($249/month):** 5 GB + $3/GB; 50k scores + $1.50/1k; 30-day retention; custom topics, environments, priority support
- **Enterprise (custom):** custom retention, RBAC, BAA for HIPAA, on-prem or hosted, SLA

Inter-agent trace support: Yes, but framing is different. Braintrust is stronger on eval pipelines than on real-time multi-agent execution traces. It surfaces logged spans and supports hierarchical logging, but its native UI is organized around experiments and datasets rather than live agent-execution graphs. The "processed data" pricing model (charged on ingest, not retention) is unusual and can surprise at scale.

LangGraph integration: not first-class. Braintrust has a Python SDK that can wrap LLM calls, but LangGraph's built-in tracing hooks are designed for LangSmith and Langfuse. Integration would require manual span creation at each LangGraph node boundary — non-trivial for a 5-day build.

OpenRouter integration: same manual enrichment story as others.

Healthcare fit: Enterprise plan offers BAA. Starter and Pro do not.

Key consideration: Braintrust's eval-dataset and experiment-tracking UX is excellent for the Judge calibration workflow (comparing verdicts against ground truth across runs). This is genuinely useful for W3, but it's the eval dimension, not the observability dimension. You could use Braintrust for Judge evaluation calibration tracking separately from Langfuse for live traces — but that's a two-tool answer, which adds integration complexity.

BAA availability: Enterprise only. 14-day data retention on Starter is a constraint for regression tracking across the week (attacks from day 1 would age out by day 15 — fine for W3, problematic for production).

**Helicone**

LLM proxy + observability platform. Plans as of 2026-05-11:

- **Hobby (free):** 10k requests/month; 1 GB storage; 1 seat; 7-day data retention; 10 logs/min ingestion; community support
- **Pro ($79/month):** unlimited seats; alerts and reports; HQL query language; 1 GB free storage + usage-based; 1 month retention; 1,000 logs/min
- **Team ($799/month):** SOC-2 and HIPAA compliance; 5 organizations; dedicated Slack; 3 months retention; 15,000 logs/min
- **Enterprise (custom):** on-prem, custom MSA, SAML SSO

Inter-agent trace support: limited. Helicone is primarily a proxy-based observability tool — it intercepts LLM API calls and logs them. It does not natively render LangGraph agent execution graphs or hierarchical span trees. You can correlate requests by session/custom properties, but the "trace a vulnerability finding back through all agents that produced it" (the PRD's specific question from the appendix p. 14) is harder to answer with Helicone than with Langfuse.

LangGraph integration: proxy-based, not graph-native. Helicone intercepts at the HTTP level (OpenAI/Anthropic-compatible API calls). LangGraph's internal state transitions are not visible without additional instrumentation.

OpenRouter integration: Helicone is explicitly listed as compatible with OpenRouter (OpenRouter supports Helicone headers). Cost attribution via proxy headers is more automatic here than with the other options.

Healthcare fit: Team tier ($799/month) for HIPAA compliance — significantly more expensive than Langfuse Pro ($199/month) for the same compliance tier.

Key downside: 7-day retention on free tier is insufficient even for a 5-day project if you want to compare day-1 attacks against day-5. The inter-agent trace depth is weaker than Langfuse or LangSmith for a LangGraph-native use case.

**Custom (Python logging + SQLite + selective Langfuse integration)**

Build minimal observability: structured JSON logs to SQLite, stdout structured logging for operator monitoring, Langfuse spans only at LLM-call boundaries (not full agent graph).

Pros: zero cost, no external dependency, full control over schema, audit log is a local file (no PHI leakage risk even on Hobby plan).

Cons: no out-of-box dashboarding; grader cannot "open a Langfuse dashboard and see inter-agent traces" — a real grader-experience gap; building even a minimal web UI for coverage reporting adds days; Judge calibration drift detection requires manual scripting.

Key constraint: the PRD observability question (p. 10) asks the Orchestrator to READ from the observability layer ("it is the data substrate your Orchestrator reads"). A custom SQLite approach can satisfy this, but it requires building the read API that Langfuse provides out of the box.

### Comparison summary

| Criterion | Langfuse (Hobby free) | LangSmith (Developer free) | Braintrust (Starter free) | Helicone (Hobby free) | Custom |
|---|---|---|---|---|---|
| Price for W3 | $0 | $0 | $0 | $0 | $0 |
| Inter-agent graph traces | Yes (native LangGraph) | Yes (native LangGraph) | Partial (SDK-level spans) | No (proxy-level only) | Manual |
| LangGraph integration | Native callback | Native (first-class) | Manual SDK wrapping | Proxy-based | Manual |
| OpenRouter cost attribution | Manual (one function) | Manual (one function) | Manual (one function) | Semi-auto (proxy headers) | Manual |
| Data retention (free tier) | 30 days | Not stated clearly | 14 days | 7 days | Forever |
| BAA available (HIPAA) | Pro ($199/mo) | Enterprise (custom) | Enterprise (custom) | Team ($799/mo) | Self-managed |
| Target Co-Pilot already uses it | Yes (W1/W2) | No | No | No | No |
| Eval calibration UX | Good (experiments + datasets) | Good | Excellent | Limited | Manual |
| Grader-visible dashboard | Yes (Langfuse UI) | Yes (LangSmith UI) | Yes (Braintrust UI) | Yes (Helicone UI) | No |
| Integration time (5-day build) | Near-zero (already wired) | 1-2h (new integration) | 4-6h (manual spans) | 2-3h (proxy config) | 2-4h (minimal logging) |
| Self-host option | Yes | Enterprise only | Enterprise only | Enterprise only | N/A |

### Recommended path

**Langfuse Hobby tier.** Reasons in priority order:

1. **The target Co-Pilot already emits Langfuse traces.** The PRD asks which tool surfaces inter-agent traces. If the grader opens Langfuse, they see traces from BOTH the target and the platform in one view — this is the correct answer to "trace a vulnerability finding back through all agents that produced it." Any other tool requires running two systems.

2. **Native LangGraph inter-agent trace support.** Langfuse's LangGraph callback handler renders multi-agent execution graphs natively. A Judge verdict is a child span of the Red Team attack attempt; the Orchestrator's cost-spend decision is a peer span. This is the data substrate the Orchestrator reads per PRD §5.

3. **30-day retention on free tier is sufficient for W3.** W3 runs 5 days; attacks from day 1 are visible through at least the final submission day.

4. **Known-cost choice.** Cory has Langfuse integration experience from W1/W2. In a 5-day build, integration-time saved is real project time. This is a valid tiebreaker when the alternatives are near-equivalent.

5. **Grader-visible observability.** The Langfuse dashboard is shareable as a demo artifact. LangSmith is the only real alternative on this dimension; Braintrust's eval UX is better but the live-trace UX is weaker.

**Why not LangSmith.** LangSmith is genuinely competitive on inter-agent trace support and has a free tier. The decisive factor is point 1: the target Co-Pilot uses Langfuse, not LangSmith. Using both would fragment the inter-agent trace story. If the platform were standalone (no existing target observability), LangSmith and Langfuse would be roughly equivalent picks.

**Why not Braintrust.** Its eval-calibration workflow is the best of the four for Judge ground-truth tracking. If this were a pure eval framework choice, Braintrust would compete. But its LangGraph integration requires manual span creation (integration time cost), its free tier has 14-day retention, and it does not unify target + platform traces.

**Why not Helicone.** Inter-agent graph traces are not Helicone's strength. Its proxy-based architecture is optimized for single-model observability, not multi-agent LangGraph execution graphs. HIPAA compliance requires the $799/month Team tier.

**Why not custom.** No grader-visible dashboard. Building one adds multiple days. The PRD explicitly asks about named vendors; custom is a valid answer only if you build something genuinely better — not appropriate for a 5-day scope.

**Supplementary pattern (optional, low-cost):** Use Braintrust's Starter (free) specifically for Judge calibration experiment tracking (ground-truth dataset comparisons across runs) while keeping Langfuse as the primary trace and cost observability layer. The two tools serve different layers and do not conflict. This is a Phase 2 addition; MVP does not need it.

### Tradeoffs owned

1. Langfuse Hobby's 1,000 requests/minute ingestion rate cap: at MVP attack throughput (~100-500 attacks/week), this is not a constraint. Would become one at 10K+ attacks/week.
2. 2-user limit on Hobby: irrelevant for a single-operator project.
3. OpenRouter cost attribution requires one custom function to parse the `x-openrouter-cost` header and add it to the Langfuse span as metadata. This is 30 minutes of work, not a blocker.
4. Langfuse Hobby has no SOC2/BAA. Acceptable because platform uses synthetic data. Must be disclosed as a known limitation if platform moves to production.
5. LangSmith's first-class LangGraph integration is marginally better than Langfuse's callback handler approach. Accepted in exchange for unified trace story.

### Open questions for Cory

1. Does the existing Langfuse project from W1/W2 have space for W3 platform traces, or does a new project need to be created? (Same account, new project: zero friction.)
2. Should W3 platform traces be in the same Langfuse project as the target Co-Pilot's traces, or a separate project? Separate project keeps them distinguishable for graders.
3. Is Judge calibration tracking important enough for the W3 grader to justify adding Braintrust as a supplementary tool, or does Langfuse's experiments feature cover it adequately?

---

## §14 — Open Source Planning

### What we've decided

README.md states: "License TBD — likely match the AgentForge companion repo's GPL-3.0 inheritance (from upstream OpenEMR) unless grading guidance suggests otherwise." This is a placeholder, not a decision.

### Options researched

| License | What it permits | Key constraint | Healthcare security research fit | Notes |
|---|---|---|---|---|
| **MIT** | Anyone can use, modify, redistribute, including in proprietary products; no copyleft | Attribution only | Permissive; attack techniques could be incorporated into commercial offensive tools without disclosure | Lowest barrier to adoption; lowest protection |
| **Apache 2.0** | Same as MIT + explicit patent grant | Attribution + state changes | Patent grant protects contributors; no copyleft | Standard for enterprise-friendly open source; LangChain, LangGraph use Apache 2.0 |
| **GPL-3.0** | Must release source if you distribute; derivatives must also be GPL-3.0 | Copyleft; "distribution" triggers requirement | Inherited by companion repo from OpenEMR; ensures attack techniques don't disappear into proprietary tools | Correct if this repo forks from the OpenEMR-derived companion repo; not required if standalone |
| **AGPL-3.0** | Same as GPL-3.0 PLUS network use counts as distribution | Strongest copyleft; SaaS loophole closed | Ensures even SaaS wrappers of this platform must open-source their modifications | Often chosen for observability/eval tools (Langfuse uses MIT + commercial; but conceptually appropriate) |
| **Business Source License (BSL/BUSL)** | Source available, but commercial use restricted for a defined period (typically 4 years) then converts to open | Complex; adds friction | Useful if there is commercial value to protect; not relevant for a 5-day grading project | Complexity not justified here |
| **Custom security research license** | Restricts use to non-commercial security research | Non-standard; requires legal drafting | Most precisely scopes the intent | Practically unusable; no standard tooling handles it |

**IP and dual-use concerns:**

This is the most substantive licensing question for a healthcare adversarial security platform. The attack techniques this platform develops (prompt injection variants, cross-patient leakage probes, unbounded consumption attacks) are dual-use: they work against any LLM-powered clinical system, not just our target. Publishing them enables:

- Legitimate: other security researchers reproduce the findings, validate the techniques, improve defenses
- Adversarial: bad actors use the same techniques against clinical systems that have not consented to adversarial testing

Industry disclosure norms (OWASP, MITRE, HackerOne responsible disclosure framework): standard responsible disclosure in security research is to (a) confirm the finding, (b) notify the vendor with a private report, (c) allow a remediation window (typically 90 days), (d) then publish. For this project, the "vendor" is the companion repo (also Cory's). The disclosure loop is already closed. Publishing the vulnerability reports and attack techniques simultaneously with the platform is consistent with coordinated disclosure norms when the vendor is the same party.

The MITRE ATLAS framing (which this platform adopts for all attack technique IDs) is specifically designed for publication of adversarial ML techniques — ATLAS already surfaces many of these technique classes publicly. Using MITRE ATLAS IDs means the techniques this platform documents are named, categorized, and already in the public knowledge base. This further supports open publication.

**Documentation requirements for open source release:**

At minimum (already partially covered):
- README.md with setup, target URL, grader checklist — present
- SETUP.md with env vars, HMAC config, dependency install — planned for Phase 2
- ARCHITECTURE.md — present
- THREAT_MODEL.md — present
- USERS.md — planned for Phase 2
- `evals/` with seed cases and results — planned for Phase 2

Additional requirements if genuinely releasing as open source (beyond grading context):
- Contributing guidelines
- Code of conduct
- Responsible use policy (scope this platform to your own systems or systems you have explicit written authorization to test)
- Vulnerability disclosure policy

**Community engagement plan (honest framing):**

This is a 5-day grading project. There is no realistic community engagement plan beyond: (a) the grader-visible GitHub repo, (b) the social post required by the PRD. Long-term community engagement would require ongoing maintenance time that is not planned.

### Recommended path

**Apache 2.0** for the standalone Clinical Red Team Platform. Reasons:

1. The platform is standalone — it is NOT a fork of OpenEMR. GPL-3.0 from the companion repo does not automatically apply here. Apache 2.0 is the correct choice for a new standalone platform.
2. Apache 2.0 is enterprise-friendly (patent grant), widely understood, and the license used by LangGraph (the platform's agent framework). License compatibility is clean.
3. Add a `RESPONSIBLE_USE.md` in the root of the repo that scopes the license use to systems the operator has explicit written authorization to test. This is standard practice for offensive security tooling and addresses the dual-use concern without requiring a custom license.
4. The vulnerability reports themselves (documenting confirmed exploits) should be published — they are the grading deliverable and already reference MITRE ATLAS public technique IDs. Redact nothing from the reports (the target uses synthetic data; there is no PHI to protect).

**If the grader expects GPL-3.0 consistency with the companion repo:** Accept GPL-3.0. It is compatible with the platform's goals and does not harm adoption at grading-project scale.

### Tradeoffs owned

1. Apache 2.0 means someone can incorporate the attack techniques into a proprietary offensive tool. The `RESPONSIBLE_USE.md` guidance is a policy control, not a technical one — it can be ignored.
2. Publishing attack techniques before the companion repo ships the C-7 fix creates a brief window where the techniques are documented but the target is still vulnerable. Since target is demo-data-only with no real PHI, actual risk is negligible.
3. There is no plan for community maintenance. The repo will atrophy post-grading unless Cory actively maintains it. Honest framing: "released as open reference implementation, not as a maintained project."
4. AGPL-3.0 would offer stronger protection for the platform code itself but would reduce adoption — wrong tradeoff at grading-project scale.
5. No CVE assignment process is set up. Vulnerability reports filed in `evals/vulnerabilities/` use internal VULN-NNN IDs, not CVEs. Appropriate for a 5-day project; document as a limitation.

### Open questions for Cory

1. Is there any intent to commercialize this platform after the grading period? If yes, reconsider Apache 2.0 and potentially BSL.
2. Should VULN-001 (the C-7 rediscovery) be submitted to any public vulnerability database (NVD, OWASP)? Probably not — the target is not a production public system.
3. Does GauntletAI have a preferred license for submitted projects?

---

## §15 — Deployment & Operations

### What we've decided

ARCHITECTURE.md exec summary: "The platform runs as a single long-running Python daemon process — `while True:` loop driven by the Orchestrator, with hard cost guards, signal-to-cost halt conditions, filesystem-checkpointed state, drift detection on the Judge over time, and graceful resume after restart." The target is at `https://142-93-242-40.nip.io` (DigitalOcean droplet). The platform itself has no stated deployment target.

README.md Phase 1 status: remote setup (GitLab primary + GitHub mirror) is listed as pending.

### Options researched

**Where does the daemon RUN in continuous mode?**

| Option | Pros | Cons | Cost | Reliability for continuous mode | Fit |
|---|---|---|---|---|---|
| **Cory's laptop (local dev)** | Zero infra cost; fastest to start; no cloud setup | Unreliable (sleep, lid close, network drops, reboots kill the daemon); can't truly run "overnight unattended" without active management | $0 | LOW — unacceptable for a claim of "continuous unattended operation" | MVP dev only; not for final demo |
| **DigitalOcean droplet (same VPS as target)** | Same network as target (low latency to `142-93-242-40.nip.io`); easy SSH; Cory has existing account | Adds another long-running process to the target droplet — resource contention possible; not cleanly separated from the target | ~$6-12/month for 1-2GB RAM droplet; marginal cost if shared | HIGH — stays up as long as DigitalOcean stays up | Good if resource contention is not a problem |
| **Separate DigitalOcean droplet** | Clean separation from target; dedicated resources; SSH + `systemd` service for persistent daemon | Extra cost; extra setup (~30 min for new droplet) | ~$6-12/month additional | HIGH | Best for production credibility |
| **Docker container on existing droplet** | Isolated from host; portable; consistent environment | Adds Docker layer on top of an existing deployment; compose file complexity grows | $0 additional if on existing droplet | HIGH if container has restart policy | Good compromise |
| **Serverless (Lambda, Cloud Run)** | No server management; auto-scales | NOT suitable for a long-running daemon (`while True:` loop); invocation time limits (15 min Lambda, 60 min Cloud Run) cap continuous operation | Pay-per-invocation but model doesn't fit | INCOMPATIBLE with daemon model | Reject |
| **GitHub Actions cron** | No server; triggers on schedule | Not a daemon; each run is stateless; filesystem artifacts don't persist between runs without external storage; 6-hour job limit | $0 (free minutes) | MEDIUM — works for scheduled runs, not true continuous | Acceptable for scheduled regression sweeps, not for continuous discovery mode |

**CI/CD for platform updates:**

GitLab is primary (per CLAUDE.md). The existing `.gitlab-ci.yml` pattern from the companion repo provides a template. For the W3 platform:
- Push to `agentforge/w3-*` branches triggers CI
- CI gate: unit tests (`tests/unit/`), smoke test (one vertical slice with mocked target), schema validation
- No deploy step in CI for MVP (daemon runs manually or via `systemd` on the droplet)
- Phase 3 consideration: add a deploy step that SSH-restarts the daemon on the droplet after a merged push

**Monitoring and alerting for the platform itself:**

The platform is not the thing being monitored — the target is. But the daemon needs basic health monitoring:
- Structured stdout logs with timestamps and last-action timestamps (process health)
- Langfuse trace freshness: if no new spans are emitted for N minutes, the daemon is likely hung
- `evals/results/<run-id>/manifest.json` last-modified time: Orchestrator writes this every iteration; staleness is a health signal
- Simple: `systemd` service with `Restart=always` and `journalctl` for log access
- Optional: Langfuse webhook or Slack notification when cost ceiling is reached or when a critical finding is filed

**Rollback strategy:**

The platform produces artifacts (attacks, verdicts, vuln reports) but does not mutate the target. Rollback of the PLATFORM means:
- Platform code: `git revert` + redeploy daemon
- Accumulated artifacts: `evals/` is git-tracked for regression cases and vuln reports; gitignored for raw run output. A bad run does not corrupt the regression store (confirmed exploits are promoted only after Judge verdict + human review for high/critical)
- Langfuse traces: cannot be deleted easily from Hobby tier; not a concern since they are read-only observability
- Target rollback (if a fix is applied and needs reverting): owned by the companion repo, not this platform

### Recommended path

**For W3 demo and grading:** Run the daemon on the SAME DigitalOcean droplet as the target (simplest path, zero additional cost), OR on Cory's laptop for daytime-only runs with clear documentation that "overnight continuous operation" requires the droplet deployment. Both are acceptable for the 5-day build if the daemon runs reliably during the demo window.

**For final submission demo credibility:** The daemon should be running live on the droplet during the video. `screen` or `tmux` to keep the session alive after SSH disconnect, OR `systemd` service for proper persistence. This is ~1 hour of setup work.

Concretely:
1. Create `systemd` service file: `daemon.service` pointing to `python -m agents.orchestrator.daemon`
2. `systemctl enable daemon && systemctl start daemon`
3. `journalctl -f -u daemon` for log streaming during demo
4. Langfuse dashboard open in browser during demo to show live inter-agent traces

**CI/CD for W3:** GitLab pipeline with unit tests + smoke test gate. No automated deploy for MVP. Manual SSH deploy after CI passes.

### Tradeoffs owned

1. Running the platform on the same droplet as the target creates a conflict-of-interest optic: the attacker and defender share infrastructure. In practice, the platform calls the target via HTTP (network boundary preserved), so there is no real shared-state attack surface. Document this explicitly.
2. `screen`/`tmux` session is fragile (SSH disconnect can kill it if not configured correctly). `systemd` is more reliable but adds setup time. Choose based on available setup time in the last day before final submission.
3. GitHub Actions cron is a viable alternative for the nightly-regression-run use case specifically. Document this as the Phase 3 scheduled-regression approach.
4. No autoscaling means if the daemon consumes more memory than expected (e.g., very long conversation histories accumulating in LangGraph state), it may OOM on a 1GB droplet. Monitor memory during first overnight run.
5. No alerting infrastructure means Cory must actively check logs or Langfuse to know if the daemon halted unexpectedly. Acceptable for a 5-day project; document as a known limitation.

### Open questions for Cory

1. Is the DigitalOcean droplet running the target (142-93-242-40.nip.io) sized to also run the Red Team daemon? What is the droplet's RAM and CPU spec?
2. Is there a preference for `systemd` service vs `screen` session for the demo? `systemd` is more defensible but requires ~1h setup.
3. Should the GitLab pipeline include an automated SSH deploy step, or is manual deploy sufficient for the 5-day build?
4. What is the plan if the daemon wedges the droplet (OOM, CPU spike) during the grading window? Is there a monitoring alert in place?

---

## §16 — Iteration Planning

### What we've decided

ARCHITECTURE.md §9.4 defines the MVP vertical slice and the intentionally-deferred list. Post-MVP is Phase 3 (due Friday 2026-05-15 noon). No explicit iteration-after-grading plan exists. This is expected for a 5-day project.

### Options researched

**Feedback collection — how do engineers tell the platform "you flagged a false positive"?**

Three mechanisms, in increasing sophistication:

1. **Manual YAML frontmatter edit (MVP).** The Documentation Agent writes `VULN-NNN-DRAFT.md` with a `status: draft-pending-review` field. The engineer reviews, sets `status: false-positive` (or `status: filed`). The Orchestrator reads this on next loop and skips this finding's associated attack pattern. Zero tooling overhead; Git history is the audit trail.

2. **CLI flag.** `python -m agents.orchestrator.daemon --mark-false-positive VULN-NNN`. Updates the YAML frontmatter programmatically, logs to audit trail. Marginally more ergonomic than option 1.

3. **Langfuse human annotation.** Langfuse supports annotation queues (1 queue on Hobby, 3 on Core). An engineer can annotate a trace span as "false positive" directly in the Langfuse UI. The Orchestrator reads Langfuse annotations via API and adjusts Judge criteria accordingly. This is the PRD's intended design (observability layer is the data substrate both humans and Orchestrator read). Phase 2 addition; requires Langfuse annotation queue setup.

**Eval-driven improvement cycle for each agent (especially Judge calibration drift detection):**

ARCHITECTURE.md §2.2 defines the Judge calibration design: ground-truth dataset of human-labeled (attack, response, verdict) tuples; rolling-window accuracy; drift alert if drops >5pp from baseline.

Implementation specifics:
- Ground-truth dataset lives at `evals/calibration/ground-truth.yaml`
- After each Judge verdict, the Orchestrator checks if a matching ground-truth tuple exists; if yes, compares and records accuracy
- `evals/calibration/drift-metrics.json` accumulates the rolling window
- Alert threshold: configurable via env var `JUDGE_DRIFT_ALERT_THRESHOLD_PP` (default 5)
- When drift detected: emit alert (stdout + optional Langfuse custom event); Orchestrator sets `judge_needs_review = True`; human updates criteria or reweights the ground-truth set

This is a Phase 2 feature — MVP can ship without calibration if the ground-truth set is small and the Judge has not yet had time to drift.

**Feature prioritization approach post-MVP:**

Honest framing: this is a 5-day grading project. There is no formal post-MVP roadmap. The architecturally-correct answer (defensible to a grader) is:

1. Judge calibration drift detection and ground-truth expansion
2. Multi-turn attack sequence support (currently seeded but not deep in MVP)
3. Autonomous novel category suggestion by the Orchestrator (LLM-augmented category discovery)
4. Exploit chaining (connect a prompt-injection finding to a data-exfiltration finding as a compound attack)
5. Distributed Red Team workers (Redis queue + Celery) for 10K+ attack scale
6. Self-improving attack strategies (RL-based mutation prioritization over time)

Each of these requires a defined triggering threshold to avoid aspirational roadmapping: e.g., "add multi-turn support when seed-based single-turn coverage exceeds 20 attacks per category with <10% FAIL rate."

**Long-term maintenance plan (honest framing):**

This is a 5-day grading project. The realistic long-term plan is:
- The platform code is archived as a graded artifact
- The vulnerability reports become the lasting output (VULN-001 documenting C-7 becomes a real finding in the companion repo's AUDIT.md)
- If Cory pursues further development, the natural extension is: generalize the target client to accept arbitrary HMAC-signed LLM endpoints (not just the AgentForge Co-Pilot), and release as a reusable adversarial testing harness for clinical AI systems
- Community maintenance is not planned. State this explicitly in the README rather than implying ongoing support.

### Recommended path

MVP feedback mechanism: option 1 (manual YAML frontmatter edit). Low overhead, auditable, sufficient for 5-day scale. Document the annotation-queue path (option 3) as the Phase 3 upgrade.

Judge calibration: build the ground-truth YAML file with at least 10 hand-labeled (attack, response, verdict) tuples before the final submission. Run the calibration check once before the final demo to establish baseline. Drift detection is then ready but not yet triggered.

Iteration planning: publish the feature prioritization list above in `docs/roadmap.md` (a single markdown file, not a full doc). This satisfies grader question "what would you build next?" without overpromising.

### Tradeoffs owned

1. YAML frontmatter as feedback mechanism has no UI — engineers must edit files directly. Acceptable for a single-operator project; unacceptable for a team.
2. The ground-truth calibration set will be small (10-20 tuples) at MVP. Drift detection on a small set is noisy. Accept and document: "calibration is bootstrapped; drift detection becomes reliable at 50+ tuples."
3. The feature prioritization list above is aspirational — none of it will be built in the 5-day window. Frame clearly as "known improvement priorities, not committed roadmap."
4. Long-term maintenance honesty may feel like a weakness in the submission. It is actually a strength: graders reading aspirational "we will maintain this as open source" claims know they are usually false. Honest framing of a grading project's lifetime is more credible.
5. Langfuse annotation queues for feedback collection require Core tier ($29/month). If this becomes important for the demo, upgrade is low cost. MVP does not need it.

### Open questions for Cory

1. Should the long-term maintenance plan explicitly state "not intended for ongoing maintenance post-grading" in the README? Honest framing is safer than silence.
2. Is there a plan to file VULN-001 back into the companion repo's `AUDIT.md` as a closed finding once the C-7 fix is shipped? This closes the loop between the two repos.
3. Should the Langfuse annotation queue (Core tier: $29/month) be activated for the final demo to show a more complete human-feedback loop?

---

*Word count: approximately 3,900 words. Research date: 2026-05-11. Pricing sourced from live page fetches (Langfuse, LangSmith, Helicone, Braintrust) on 2026-05-11.*
