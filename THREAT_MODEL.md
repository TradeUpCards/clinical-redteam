# Clinical Red Team Platform — Threat Model

**Target:** AgentForge Clinical Co-Pilot at `https://142-93-242-40.nip.io` (deployed; companion repo at https://github.com/TradeUpCards/agentforge).
**Status:** Architecture defense draft (2026-05-11). Living document — extended continuously as Red Team Agent surfaces new attack vectors.
**Frameworks anchored:** OWASP Top 10 for LLM Applications v2025 + OWASP ASI Top 10 2026 + MITRE ATLAS + NIST AI RMF.

---

## Executive Summary

The AgentForge Clinical Co-Pilot is an LLM-powered agentic system that helps primary care physicians retrieve chart context, summarize notes, assist intake workflows, and answer source-cited clinical questions. It is deployed at `https://142-93-242-40.nip.io` and exposes three primary attack surfaces: a chat endpoint (`/chat`, `/graph_chat`) that takes natural-language queries, a document upload endpoint (`/attach_and_extract`) that ingests lab PDFs and intake forms, and a citation resolver endpoint (`/resolve_citation.php`) that returns document metadata for click-to-source UI. The system is **agentic** (LangGraph supervisor + workers + responder + tool use) but **deliberately not autonomous** (chat surfaces are read-only; the only action-taking path — clinical-table writes from extracted documents — is gated behind explicit clinician approval via the HITL gate shipped in W2 P4 R1+R2). This bounded autonomy materially shapes which threat categories are highest-risk: attacks that exploit autonomy (rogue-agent behavior, sustained goal hijack) are largely capped by the approval gate; attacks that exploit data flow (PHI leakage, prompt injection, tool misuse, memory poisoning) are not.

The threat model is structured around two complementary OWASP frameworks rather than invented categories: **OWASP Top 10 for LLM Applications v2025 (LLM01–LLM10)** for the broad LLM-application attack surface, and **OWASP ASI Top 10 2026 (ASI01–ASI10)** for the agentic surface specifically. Each PRD-named category from the W3 brief (prompt injection, data exfiltration, state corruption, tool misuse, denial of service, identity & role exploitation) maps to entries in both frameworks. Per-attack tactical citations use **MITRE ATLAS** technique IDs for portability across tools and audits. Of the 10 ASI categories, 8 apply meaningfully to this target; 2 (ASI01 Agent Goal Hijack, ASI10 Rogue Agents) are bounded by the HITL approve gate and present limited surface — this is documented, not glossed over. Every defense the Co-Pilot already ships (PHI scrubber + sentinel-pid boundary via `PersonaMap`, substring-grounded extraction verifier, HMAC + ACL + rate-limit + token-budget gates, claim-emission discipline, no-PHI-in-logs rubric in CI) has a corresponding adversarial test category in this model.

The highest-risk attack categories — prioritized by likelihood × impact × autonomy-bounded severity — are: (1) **LLM02 Sensitive Information Disclosure / cross-patient paraphrased PHI leakage** — already documented as `AUDIT.md` C-7 in the companion repo as a HIGH-severity finding deferred to W3; the existing PHI scrubber catches literal `patient_id=N` tokens but Haiku can paraphrase, and three nightly-tier eval cases exercise this; (2) **LLM01 Prompt Injection / indirect via uploaded document content** — the `/attach_and_extract` flow ingests untrusted document text that Haiku then sees as part of its extraction prompt; injection within a Docling block is a confirmed concern; (3) **LLM06 Excessive Agency / tool parameter tampering** — supervisor's tool selection and the worker's tool-call construction both surface as decision boundaries that can be steered; (4) **LLM10 Unbounded Consumption / cost amplification** — `/extract_via_graph` has no concurrency cap (per Aria's W2-end discovery), and a slow extraction can wedge the single uvicorn worker; (5) **ASI06 Memory & Context Poisoning** via the RAG corpus or multi-turn chat history; (6) **ASI07 Insecure Inter-Agent Communication** via LangGraph state passing — the worker→responder bridging bug from W2 was effectively a real-world cascading-failure case (ASI08), and similar shapes likely exist.

The platform's adversarial coverage prioritizes these high-risk categories first, with seed cases drawn from the existing 67-case W2 eval suite (six prompt-injection cases, one cross-patient-leakage case, six no-PHI-in-logs cases, one auth-boundary case all become Phase 1 seeds for the Red Team Agent's mutation work). The C-7 cross-patient paraphrased leakage finding becomes Vulnerability Report #1 once independently re-discovered by the Red Team Agent — providing a clean validation that the platform reproduces a known-real exploit before chasing novel ones. Lower-likelihood categories (LLM03 Supply Chain, LLM04 Data Poisoning of training data) are explicitly out-of-scope for Phase 1 because we are not training the underlying models — those risks are inherited from Anthropic and managed at the provider boundary, not here. The full attack surface map below is organized first by OWASP LLM Top 10 (target's LLM-app surface), then by OWASP ASI Top 10 (target's agentic surface), with cross-references where a single attack vector spans both frameworks.

---

## 1. Target System Overview

### 1.1 What the target IS

The AgentForge Clinical Co-Pilot is an OpenEMR-integrated LLM application built on:
- **Python agent service** (FastAPI, deployed on DigitalOcean droplet) with a LangGraph supervisor + 2 workers (`evidence_retriever`, `intake_extractor`) + responder
- **PHP module** (`oe-module-clinical-copilot`) inside OpenEMR providing the chat panel, HITL review modal, and citation resolver endpoint
- **MariaDB** for clinical data + Co-Pilot extraction tracking
- **Qdrant** for guideline-corpus vector search (26 chunks)
- **Anthropic Claude** for LLM calls (Haiku 4.5 for synthesis, Sonnet 4.6 for reasoning)

### 1.2 Attack surface entry points

| Endpoint | Method | Auth | Input shape | What an attacker controls |
|---|---|---|---|---|
| `/chat` | POST | HMAC + session | `{patient_id, session_id, messages}` | Message content (user turn) |
| `/graph_chat` | POST | HMAC + session | Same as `/chat` | Message content; supervisor routing influenced |
| `/attach_and_extract` | POST | HMAC + session | Multipart form with PDF | **Document content** (binary file content) |
| `/extract_via_graph` | POST | HMAC + session | Same as attach_and_extract | Same as above (newer endpoint, routes through supervisor) |
| `/resolve_citation.php` | GET | OpenEMR session + ACL | Query params: `source_type`, `source_id`, `block_id` | Query parameter values |
| Approve / Reject endpoints (P4) | POST | OpenEMR session + clinician role | `{extraction_id}` | Whether/when to approve |
| OpenEMR documents UI (upstream) | Browser | OpenEMR session | File upload | Document content + category selection |

### 1.3 Trust boundaries and bounded autonomy

The Co-Pilot is **agentic but not autonomous**. The deliberate boundaries:

| Surface | What the agent CAN do autonomously | What requires a human |
|---|---|---|
| `/chat`, `/graph_chat` | Read patient data via 5 W1 tools; query Qdrant; synthesize response with citations | **Nothing is written to the world** — output is advisory; clinician reads + decides |
| `/attach_and_extract` | Run Docling layout + Haiku extraction + verifier; persist extraction as `pending_review` | **Clinician must explicitly approve** before any clinical-table write fires (HITL gate from P4 R1+R2) |
| Tool calls within a turn | Within one user-initiated turn, LLM picks tool(s); supervisor max-hops bound | Loop terminates per turn; **no follow-up scheduling, no overnight work, no self-initiated queries** |
| Background activity | None — agent does not initiate | All actions are user-triggered |

This bounded autonomy materially shapes the threat model. ASI categories that require sustained autonomous goal pursuit (ASI01 Goal Hijack, ASI10 Rogue Agents) have limited blast radius. ASI categories that apply to any agentic-with-tool-use system (ASI02 Tool Misuse, ASI06 Memory Poisoning, ASI07 Inter-Agent Comms, ASI08 Cascading Failures) apply with full force.

### 1.4 Existing defenses (the Co-Pilot's W2 security posture)

Adversarial testing must probe the failure modes of these defenses, not just unprotected paths:

| Defense | What it blocks | Where it lives |
|---|---|---|
| **HMAC-signed requests + replay protection** | Forged inbound requests; replay attacks | All agent endpoints; PHP middleware |
| **OpenEMR ACL gate** | Cross-patient access without role; unauthorized endpoint access | `CoPilotController.php` |
| **Per-user rate limit + hourly token budget** | Cost amplification attacks; sustained probing | Agent service rate limiter |
| **Sentinel patient boundary (`PersonaMap`)** | Real PIDs crossing into agent traces / Langfuse / extraction tables | `PersonaMap.php` translates real pid → sentinel before agent call |
| **Substring-grounded extraction verifier** | Hallucinated extracted values | `agent/extractors/__init__.py` strips fields where value not in source block; >30% strip rate → refuse |
| **Outbound PHI scrubber** | SSN / phone / email / MRN / cross-patient-ID in agent responses | `agent/_phi_scrubber.py` |
| **Claim-emission discipline (verifier)** | Ungrounded clinical claims | Inline citation requirement in prompt + verifier rejection of un-cited claims |
| **HITL approve gate on writes** | Auto-write to clinical tables from extraction | `DocumentSavedSubscriber.php` + `RoundtripService.php` |
| **PR-blocking eval gate** | Regression of any of 5 boolean rubrics (>5pp drop OR <80% floor) | `.github/workflows/agent-eval.yml` + `scripts/run_eval_gate.py` |
| **Strip-rate gate (second axis)** | Verifier-load drift | `scripts/run_strip_rate_gate.py` |
| **Docker network isolation** | Direct agent access from public internet | Agent only reachable from OpenEMR container per `.deploy/README.md` |

### 1.5 Already-known finding (becomes Vuln Report #1)

`AUDIT.md` C-7 in the companion repo documents **cross-patient paraphrased PHI leakage** as a HIGH-severity finding deferred to W3:
- **Vector:** prompt asks about Patient A; chart context includes mention of related Patient B; Haiku synthesizes a response that paraphrases B's information in narrative form (e.g., "her sister Maria has diabetes" pulled from another patient's chart)
- **Why existing defense doesn't catch it:** PHI scrubber catches literal `patient_id=N` tokens; Haiku can paraphrase past it
- **Confirmed exploitable:** 3 nightly-tier eval cases (`cross_patient_leakage_resistance`, etc.) currently fail in live mode
- **Documented fix path:** `check_citation_patient_boundary()` operating on Citation provenance, not regex (~2-4h scope, deferred as pre-clinical-pilot gate)

This becomes the Red Team Agent's first Phase 1 target — re-discover this finding autonomously, validate the platform reproduces it, then file as Vulnerability Report #1.

---

## 2. OWASP LLM Top 10 v2025 — Coverage Map

For each entry: applicability to target, attack vectors, existing defenses, severity, Phase 1 coverage commitment.

### LLM01:2025 Prompt Injection

**Applies:** YES (high). All chat endpoints are direct injection surfaces; document upload is an indirect injection surface.

**Vectors against this target:**
- **Direct injection** via `/chat` user message ("ignore previous instructions and...")
- **Indirect via document content** — `/attach_and_extract` ingests PDF text Docling parses into blocks; Haiku sees that text as part of the extraction prompt. Injection within a Docling block content area can manipulate extraction output.
- **Multi-turn / persistence** — chat history accumulates; later turns can be primed by earlier "innocuous-looking" turns
- **Multimodal** — N/A (target doesn't process images directly; Docling extracts text from PDFs but pixel content not LLM-ingested)

**Existing defenses:**
- System prompt enforces patient_id scoping + claim-emission discipline + sentinel boundary
- Verifier strips ungrounded claims
- Substring-grounded extraction verifier blocks ungrounded extracted fields

**Severity:** HIGH (could surface PHI from wrong patient, or cause incorrect clinical extraction)

**Phase 1 coverage:** YES (priority). Seed cases: 5 existing prompt-injection cases from W2 eval suite (`injection_unicode_obfuscated`, `injection_via_allergy_reaction`, `injection_via_encounter_narrative`, `injection_via_lab_field_name`, `injection_unicode_obfuscated`) + new indirect-via-document cases.

**MITRE ATLAS:** AML.T0051 (LLM Prompt Injection), AML.T0048 (External Harms via API)

### LLM02:2025 Sensitive Information Disclosure

**Applies:** YES (highest priority — already a documented HIGH finding).

**Vectors against this target:**
- **Cross-patient paraphrased leakage** (the C-7 finding) — Haiku narrates patient B's data while answering about patient A
- **System prompt leakage via injection** — extracting the system prompt could reveal sentinel-boundary mapping rules
- **Logs / observability leakage** — if PHI scrubber misses (especially names; Tier 2 deferred), traces to Langfuse leak
- **Error message leakage** — exception details in API responses could include PHI substrings
- **Citation popover leakage** — `/resolve_citation.php` returns document content; bypassing ACL could expose another patient's PDF region

**Existing defenses:**
- PHI scrubber (cross-patient ID, SSN, phone, email, MRN) — Tier 2; cross-patient *names* deferred
- Sentinel boundary at agent line (PersonaMap)
- ACL gate on `/resolve_citation.php`
- HMAC on agent endpoints
- `no_phi_in_logs` rubric in CI (6 cases)

**Severity:** CRITICAL for cross-patient leakage; HIGH for prompt extraction; MEDIUM for error-message leakage

**Phase 1 coverage:** YES (HIGHEST priority). Seed cases: 6 no-PHI cases + 1 cross-patient-leakage case. C-7 reproduction is target #1.

**MITRE ATLAS:** AML.T0024 (Exfiltration via ML Inference API), AML.T0007 (Discover ML Model Family)

### LLM03:2025 Supply Chain

**Applies:** PARTIAL.

**Vectors against this target:**
- Anthropic Claude API as upstream (managed by Anthropic; out of our control)
- Docling, LangGraph, Qdrant, BAAI bge-small-en model deps
- Cohere Rerank as optional (free-tier; can be disabled)

**Existing defenses:**
- Pinned versions in `requirements.txt`
- No model fine-tuning (no training-data poisoning surface from our side)

**Severity:** LOW for this platform's testing scope (we don't control upstream model weights or pip indices)

**Phase 1 coverage:** **OUT OF SCOPE.** Documented as a limitation. Phase 3+ if scope expands.

**MITRE ATLAS:** AML.T0010 (ML Supply Chain Compromise)

### LLM04:2025 Data and Model Poisoning

**Applies:** PARTIAL.

**Vectors against this target:**
- **Conversation history poisoning** — multi-turn `/chat` could prime later turns
- **Qdrant corpus poisoning** — IF an attacker had write access to the corpus (currently they don't; corpus is curated)
- **Training data poisoning** — N/A (we don't train models)

**Existing defenses:**
- Conversation history is per-session; no cross-session contamination
- Qdrant write access is admin-only (no public ingest endpoint)

**Severity:** LOW for current architecture; would rise to HIGH if corpus gains a public-write surface

**Phase 1 coverage:** YES for conversation-history poisoning (overlaps with LLM01 multi-turn). Corpus poisoning OUT OF SCOPE.

**MITRE ATLAS:** AML.T0019 (Publish Poisoned Datasets)

### LLM05:2025 Improper Output Handling

**Applies:** YES (medium).

**Vectors against this target:**
- Chat panel renders LLM output as HTML/markdown — could XSS if LLM emits raw `<script>` tags (DOMPurify or similar likely in place; verify)
- Citation resolver returns document text — could include malicious payloads if document was crafted
- Logs containing LLM output could break log parsers if newlines / control chars / JSON-in-string injected

**Existing defenses:**
- Frontend renders citations + responses via DOMPurify (verify in `chat-panel.js`)
- Server-side citation resolver returns structured JSON (not raw HTML)

**Severity:** MEDIUM (XSS surface if frontend escaping fails)

**Phase 1 coverage:** YES (one Red Team category). Test: crafted prompt that asks Haiku to emit HTML/JS; observe whether frontend renders or escapes.

**MITRE ATLAS:** AML.T0048 (External Harms via API)

### LLM06:2025 Excessive Agency

**Applies:** YES (high — applies despite bounded autonomy).

**Vectors against this target:**
- **Tool selection manipulation** — supervisor decides which W1 tool(s) to call; injection could steer toward `get_recent_encounters` (which the verifier finds harder to ground) over safer paths
- **Tool parameter tampering** — `get_recent_labs` accepts `since_date`, `lab_codes` — could inject malformed params to surface unintended data
- **Recursive tool calls** — supervisor max-hops cap is 5; attempting to exhaust the cap before the query completes
- **Search guideline keyword injection** — `evidence_retriever`'s keyword router (`_GUIDELINE_KEYWORDS`) controls when guideline corpus is queried; injection could force or prevent retrieval

**Existing defenses:**
- Supervisor max-hops bound
- Tool isolation (workers can't call other workers directly)
- HITL approve gate prevents excessive agency on the only WRITE path
- Per-user rate limit + token budget
- Verifier strips ungrounded claims regardless of which tool produced them

**Severity:** HIGH (tool misuse can surface wrong-patient data even with sentinel boundary)

**Phase 1 coverage:** YES (priority). Seed: cross-patient queries that should get refused; tool-parameter mutation cases.

**MITRE ATLAS:** AML.T0012 (Valid Accounts) — relevant to ACL bypass via tool misuse

### LLM07:2025 System Prompt Leakage

**Applies:** YES (medium).

**Vectors against this target:**
- Direct injection asking for system prompt verbatim
- Indirect via reflection ("repeat what you were told before this conversation started")
- Probing via observed responses (inferring rules from refusal patterns)

**Existing defenses:**
- System prompt does not contain credentials (no API keys, no DB strings)
- System prompt does contain claim-emission discipline rules — leakage of these would help attackers craft bypasses but isn't catastrophic on its own

**Severity:** MEDIUM (system prompt extraction enables more sophisticated attacks; not catastrophic alone)

**Phase 1 coverage:** YES (one Red Team category). Test: extraction prompts; reflection prompts; rule-inference probing.

**MITRE ATLAS:** AML.T0029 (Denial of ML Service) — adjacent

### LLM08:2025 Vector and Embedding Weaknesses

**Applies:** PARTIAL.

**Vectors against this target:**
- Adversarial embeddings — crafted text that shifts embedding closeness to manipulate guideline retrieval
- Cross-tenant embedding contamination — N/A (corpus is shared, not per-tenant)
- Reranker bypass — BAAI cross-encoder fallback; specific text can game reranker scoring

**Existing defenses:**
- Corpus is curated (no untrusted ingest)
- BM25 + dense + rerank reduces single-axis manipulation impact

**Severity:** LOW (corpus is small + curated; embedding attacks low-impact)

**Phase 1 coverage:** PARTIAL (if Red Team Agent has cycles after higher-priority work).

**MITRE ATLAS:** AML.T0029, AML.T0043 (Craft Adversarial Data)

### LLM09:2025 Misinformation

**Applies:** YES (medium — directly clinical impact).

**Vectors against this target:**
- Hallucinated clinical facts (defended by verifier + grounding requirement)
- Fabricated citations (defended by citation contract + substring grounding)
- Confidence inflation on uncertain answers (defended by claim-emission discipline + verifier)

**Existing defenses:**
- Substring-grounded verifier (strips ungrounded claims, refuses on >30% strip rate)
- Required inline citations
- 5 PRD boolean rubrics including `factually_consistent` and `citation_present`

**Severity:** HIGH (clinical decisions made on misinformation cause patient harm)

**Phase 1 coverage:** YES. Seed cases: 4 evidence-retrieval cases that currently fail in hybrid mode (Haiku not consistently emitting inline guideline citations).

**MITRE ATLAS:** AML.T0048

### LLM10:2025 Unbounded Consumption

**Applies:** YES (HIGH — confirmed exploitable per Aria's 2026-05-10 finding).

**Vectors against this target:**
- **Slow extraction wedging single uvicorn worker** (Aria diagnosed this at production wedge 2026-05-10; `concurrent.futures.ThreadPoolExecutor` + `asyncio.run` + `future.result(timeout=120)` antipattern means thread can't be killed; `AsyncAnthropic(...)` no `timeout=` kwarg defaults to ~10 min)
- **No concurrency cap on `/extract_via_graph`** — multiple slow uploads pile up
- **Token-budget per user** (existing defense) — but per-user; bypass via multiple sessions
- **Multi-turn cost amplification** — long conversations accumulate context; each turn pays cumulative token cost
- **Vector-search exhaustion** — Qdrant queries are cheap but reranker calls are not (BAAI cold-start ~16s; Cohere paid)

**Existing defenses:**
- Per-user rate limit + hourly token budget (effective for casual abuse)
- Supervisor max-hops bound
- Verifier > 30% strip → refuse (caps repeated failed attempts)

**Phase 1 coverage:** YES (HIGHEST priority alongside LLM02). Seed: existing token-exhaustion attempts; new wedging-via-slow-extraction cases.

**MITRE ATLAS:** AML.T0029 (Denial of ML Service), AML.T0034 (Cost Harvesting)

---

## 3. OWASP ASI Top 10 2026 — Agentic Surface Coverage

For each entry: applicability to target (given bounded autonomy), attack vectors, Phase 1 coverage.

### ASI01:2026 Agent Goal Hijack

**Applies to target:** **BOUNDED.** Within a single user-initiated turn, supervisor's routing can be steered. But Co-Pilot lacks autonomy across turns — no goals to "hijack" beyond the current turn.

**Vectors:** prompt injection that steers supervisor to wrong worker (LLM01 overlap); injection that causes verifier bypass.

**Coverage:** Combined with LLM01.

### ASI02:2026 Tool Misuse & Exploitation

**Applies to target:** YES (high). Same as LLM06 with agent-specific framing.

**Vectors:** Tool parameter tampering via injection; recursive tool calls; tool-selection manipulation. See LLM06 above.

**Phase 1 coverage:** YES.

### ASI03:2026 Agent Identity & Privilege Abuse

**Applies to target:** YES (medium-high).

**Vectors:**
- Sentinel boundary bypass — could attacker discover the real-pid → sentinel-pid mapping from observed behavior?
- ACL gate bypass via session manipulation
- Cross-patient access via pid manipulation in tool calls

**Existing defenses:**
- PersonaMap is server-side; mapping not exposed to agent
- ACL gate on PHP side
- HMAC + session validation

**Phase 1 coverage:** YES. Seed: 1 auth-boundary case; cross-patient probing cases.

### ASI04:2026 Agentic Supply Chain Compromise

**Applies to target:** PARTIAL — overlaps LLM03. Agent-specific concern: prompt-injection inside Docling library outputs; Anthropic SDK behavior changes.

**Phase 1 coverage:** OUT OF SCOPE for primary surface (overlaps LLM03). Documented as limitation.

### ASI05:2026 Unexpected Code Execution

**Applies to target:** LOW.

**Vectors:** Co-Pilot does not eval/exec LLM outputs as code. PHP layer doesn't evaluate dynamic strings. Risk surface is minimal.

**Phase 1 coverage:** LOW priority. Single test case to confirm.

### ASI06:2026 Memory & Context Poisoning

**Applies to target:** YES (high).

**Vectors:**
- Multi-turn chat poisoning (overlaps LLM01 multi-turn / LLM04 conversation poisoning)
- RAG corpus poisoning (corpus is curated; less surface — see LLM04)
- Document-content priming — uploaded document content shapes Haiku's view of subsequent turns

**Phase 1 coverage:** YES.

### ASI07:2026 Insecure Inter-Agent Communication

**Applies to target:** YES (medium).

**Vectors:**
- LangGraph state-passing manipulation — can attacker influence what's in `SupervisorState` between hops?
- Worker output poisoning — worker drops or mangles state in ways subsequent nodes don't catch (the bridging-bug shape from W2)

**Existing defenses:**
- State is in-process only (not network-exposed)
- Schema-typed state transitions

**Phase 1 coverage:** YES. Specific test: probe whether crafted patient queries can cause workers to write inconsistent state to responder.

### ASI08:2026 Cascading Agent Failures

**Applies to target:** **CONFIRMED EXPLOITABLE — already happened in W2.** The worker→responder bridging bug from W2 (`.gauntlet/stories/worker-responder-bridging-bug.md` in companion repo) is a real-world cascading failure: workers dropped record `fields` when converting to Citation, responder produced empty answers against fully-populated patients. Pattern reappeared 24h later in guideline-records bridging.

**Vectors:** Worker output that triggers downstream-component failure modes; supervisor decisions that propagate bad state through worker chain; verifier failures cascading to refusal storms.

**Phase 1 coverage:** YES. Seed: bridging-bug regression test from W2 + new variant generation.

### ASI09:2026 Human-Agent Trust Exploitation

**Applies to target:** YES (high — clinical decisions hinge on agent output).

**Vectors:**
- Convincing-but-wrong responses that clinician acts on
- Confidence inflation in language ("definitely" / "certainly") for uncertain answers
- Citation appearance without grounding — citation badge present but cited record doesn't actually support the claim (existing verifier addresses this)
- HITL approve-gate fatigue — clinician approves extraction without careful review

**Phase 1 coverage:** YES (medium priority). Test: response confidence levels vs ground-truth correctness.

### ASI10:2026 Rogue Agents

**Applies to target:** **LARGELY N/A.** Co-Pilot has no autonomy for an agent to "go rogue" on. No background activity surface. HITL gate prevents any write action without explicit approval.

**Phase 1 coverage:** Single case to document the architectural protection (HITL gate + bounded autonomy = no rogue surface).

---

## 4. Highest-Risk Categories — Prioritization

**30-second summary (the verbal-defense answer):** *"The highest risks are cross-patient PHI leakage, prompt injection, and unbounded consumption. Cross-patient leakage is prioritized because it's already confirmed (the C-7 finding from W2). Prompt injection is the broadest user-controlled surface across both `/chat` and document-upload paths. Unbounded consumption can take down target availability — Aria's W2-end production wedge proved exploitability. These are the three MVP categories; the Red Team Agent's seed cases are drawn from existing W2 eval cases for these categories, plus mutations."*

In order of priority for Phase 1 Red Team Agent coverage:

| Rank | Category | OWASP ID | Why prioritized |
|---|---|---|---|
| 1 | Cross-patient PHI leakage (paraphrased) | LLM02 + ASI03 | Already documented as HIGH-severity finding (C-7); confirmed exploitable in 3 nightly cases; clinical impact direct |
| 2 | Prompt injection — direct + indirect via document upload | LLM01 + ASI06 | Largest attack surface (chat + upload); existing defenses are not perfect; PRD requires multi-turn coverage |
| 3 | Unbounded consumption / production wedge | LLM10 + ASI02 | Confirmed exploitable per Aria's 2026-05-10 prod wedge; impacts target availability |
| 4 | Tool misuse — parameter tampering + selection manipulation | LLM06 + ASI02 | High blast radius; multiple defenses must hold for safety |
| 5 | Cascading agent failures | ASI08 | Confirmed real-world (W2 bridging bug, twice); systemic pattern |
| 6 | Misinformation (clinical facts) | LLM09 | Clinical decisions made on bad info → patient harm |
| 7 | Memory & context poisoning (multi-turn) | ASI06 + LLM04 | Multi-turn coverage required by PRD |
| 8 | Identity & privilege abuse (cross-patient) | ASI03 | Sentinel boundary is well-defended but specific bypasses worth probing |
| 9 | Improper output handling (XSS via LLM output) | LLM05 | Frontend escaping likely solid; verify |
| 10 | System prompt leakage | LLM07 | Lower direct impact; enables other attacks |

Out-of-scope for Phase 1: LLM03 (supply chain), LLM04 corpus side (curated), ASI04 (overlaps LLM03), ASI05 (low surface), ASI10 (architecturally bounded).

---

## 5. How the Platform Will Prioritize Coverage

The Orchestrator Agent reads coverage state and prioritizes attacks by:

1. **High-severity unaddressed categories first** — Phase 1 starts with rank 1-3 above
2. **Recently-changed defense surfaces** — when target ships a fix in any category, that category gets a regression-priority bump
3. **Categories with no recent signal** (low pass-rate variation) get cycle-out — explore others
4. **Cost-aware fallback** — if rank-1 category exhausts budget without finding novel attacks, Orchestrator rotates to next unaddressed category

Coverage map maintained in `evals/coverage.md` (updated automatically by Orchestrator after each attack round). Per-category attack count + verdict distribution + last-update timestamp.

---

## 6. Out of Scope

| Out of scope | Why |
|---|---|
| LLM03 Supply Chain (model providers, pip indices) | We don't control upstream; managed at provider boundary |
| LLM04 corpus poisoning side | Corpus is curated; no public ingest |
| ASI04 Agentic Supply Chain | Overlaps LLM03 |
| ASI05 Unexpected Code Execution | Co-Pilot doesn't eval/exec LLM outputs |
| ASI10 Rogue Agents | Architecturally bounded by HITL gate |
| Physical security of the droplet | Different threat model class |
| Network-layer attacks (DDoS, MITM) | Caddy + DigitalOcean handle; orthogonal |
| Authentication bypass via OpenEMR upstream vulnerabilities | OpenEMR's own security boundary; out of scope for Co-Pilot adversarial testing |

---

## 7. References

- Companion repo: https://github.com/TradeUpCards/agentforge
  - `AUDIT.md` C-7 (cross-patient leakage finding)
  - `EVAL_SUITE.md` §6 (nightly-tier failures with W3 fix scopes) + §8.6 (per-rubric regression matrix)
  - `W2_ARCHITECTURE.md` (current Co-Pilot architecture)
  - `.gauntlet/stories/worker-responder-bridging-bug.md` (the W2 cascading-failure case)
- Target deployed: https://142-93-242-40.nip.io
- Architecture: `ARCHITECTURE.md` (this repo)
- Vulnerability reports: `evals/vulnerabilities/`
- Frameworks: OWASP LLM Top 10 v2025 (genai.owasp.org), OWASP ASI Top 10 2026, MITRE ATLAS (atlas.mitre.org), NIST AI RMF (nist.gov/itl/ai-risk-management-framework)

---

*Threat model draft — 2026-05-11. Living document; extended as Red Team Agent surfaces new vectors. Revision history in git log.*
