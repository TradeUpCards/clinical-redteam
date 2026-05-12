# Clinical Red Team Platform -- Architecture Pre-Search Research
# Sections 5, 6, 7, 9, 10, 11, 12, 13

**Author:** Tate (Architecture Lead)
**Date:** 2026-05-11
**Status:** Pre-search input for docs/presearch.md synthesis. Read in conjunction with ARCHITECTURE.md, THREAT_MODEL.md, and security-frameworks-research.md.

---

## Section 5 -- Agent Framework Selection

### What we have decided

LangGraph. Documented in ARCHITECTURE.md Section 3.1. Rationale: inspectable graph structure, Langfuse instrumentation already wired, Anthropic-friendly multi-provider support, and known-cost from prior project work (Cory built and debugged LangGraph state machines in a week-long build; that first-hand experience has a compressible learning curve for this build).

### Alternatives considered

LangGraph -- Selected. Fits a security-platform need for deterministic DAG routing over a conversation-pattern abstraction. Pros: explicit graph; deterministic edge routing; Langfuse-native; TypedDict state typing; pause-resume via checkpointing; multi-provider LLM support. Cons: graph abstraction adds boilerplate vs raw Python for simple pipelines; async mental model differs from sync.

CrewAI -- Rejected. The Red Team/Judge isolation requirement (ARCHITECTURE.md Section 3.3) is incompatible with CrewAI default inter-agent context sharing. Shared context equals conflict of interest by design (PRD p. 4). Pros: role-based agent definition is readable; lower-code for structured multi-agent teams. Cons: the Crew abstraction encourages shared context across agents -- conflicts with the hard requirement to keep Red Team hypothesis invisible to Judge.

AutoGen (Microsoft) -- Rejected. AutoGen conversation graph makes it natural for agents to share reasoning chains -- the opposite of what the Judge isolation requirement demands. Pros: strong community; conversation-pattern agents; good at multi-turn agent dialogue. Cons: no first-class graph; harder to enforce hypothesis-stripping at schema boundary.

Custom Python (no framework) -- Rejected for MVP. Valid Phase 3 option if LangGraph proves insufficient at scale. Pros: total control; no abstraction overhead; simpler to audit. Cons: reinvents graph primitives, state management, checkpoint/resume; 5-day build cannot afford this overhead.

Semantic Kernel (Microsoft) -- Not considered seriously. Wrong ecosystem for this stack. Heavy Java/C# lineage in Python port; less established in Python multi-agent patterns; no Langfuse-native instrumentation.

Swarm (OpenAI, experimental) -- Rejected. Experimental status is a risk that cannot be carried on a 5-day build. No first-class graph or checkpoint/resume; handoffs are ephemeral with no state persistence.

### Tradeoffs we own

1. LangGraph graph abstraction adds boilerplate for simple use cases. The four-agent DAG is explicit enough that the graph pays for itself, but any developer unfamiliar with LangGraph will hit a learning curve. Mitigation: code comments explicitly explain edge decisions; ARCHITECTURE.md Section 3.2 flow is the canonical reference.
2. LangGraph version pinning risk. LangGraph had a significant API surface change between 0.1 and 0.2. Pinning the version in requirements and documenting it in SETUP.md is the mitigation.
3. Graph sync vs async. MVP chooses sync execution (ARCHITECTURE.md Section 3.2). Sync is simpler to audit and reason about for security work; async buys throughput not needed at MVP volume. Phase 2 multi-category parallelism can use LangGraph async path but introduces coroutine reasoning overhead.
4. Why LangGraph is a harder question when the interviewer knows AutoGen. The defensible answer: Red Team/Judge isolation is the first-order requirement; CrewAI and AutoGen both encourage shared context; LangGraph explicit edge typing is the only framework-level mechanism that enforces the hypothesis-stripping contract at the schema boundary.
5. PRD explicitly asks which framework manages coordination (PRD p. 8). LangGraph gives a named, demonstrable answer. A custom solution gives a correct but harder-to-demonstrate one.

### Open questions for Cory

None blocking. One open decision: whether to use LangGraph built-in checkpointing (adds a StateGraph checkpointer dependency, approximately 1h setup) or the filesystem-checkpoint approach in ARCHITECTURE.md Section 3.2. The filesystem approach is simpler and avoids an extra dependency; the LangGraph checkpointer is more rigorous. Recommend filesystem for MVP and revisit if resume-after-restart proves flaky.

### Risks specific to our choice

1. LangGraph graph topology couples agent boundaries. Adding a fifth agent later requires restructuring the graph. Design with extensibility: each node has a defined input TypedDict and output TypedDict with no implicit cross-contamination.
2. Langfuse LangGraph integration has quirks. Not every LangGraph edge fires a Langfuse span automatically; some require explicit langfuse.trace() calls inside node functions. The integration pattern in ARCHITECTURE.md Section 5 documents the expected span structure.
3. LangGraph default state serialization is pickle-based. If LangGraph built-in persistence is used, any unpicklable object in state fails silently. The filesystem-checkpoint approach sidesteps this by serializing to JSON explicitly.
4. Community support for security-domain LangGraph patterns is thin. Most LangGraph examples are retrieval, code generation, or customer service. There is no prior art for adversarial red team graph with hypothesis stripping. The first version of this pattern will hit undocumented edge cases.
5. LangGraph does not natively enforce type safety at edges. TypedDict provides IDE hints but not runtime enforcement. Pydantic v2 or jsonschema validation is needed at every inter-agent boundary to enforce the contracts in ARCHITECTURE.md Section 12.

---


## Section 6 -- LLM Selection



### What we have decided



Per ARCHITECTURE.md Section 8.2: criteria-first selection, not model-name-first. Models read from environment variables.

Phase 1 starting recommendations:

- Red Team: open-weight model via OpenRouter (permissive safety posture)

- Judge: Anthropic Claude Sonnet-class via OpenRouter (frontier accuracy; cross-provider independence from Red Team)

- Documentation: Anthropic Claude Sonnet-class via OpenRouter (report quality bounded by FAIL verdict count)

- Orchestrator: pure Python rules, no LLM for MVP

### Alternatives considered



WhiteRabbit-Neo (Kindo, Llama fine-tune) for Red Team: Purpose-built for offensive security, will not refuse security workflows. Very low cost. Context 8K-32K. Most defensible pick if available on OpenRouter. Availability must be verified at build-start.



Dolphin-Mistral / Dolphin-Mixtral for Red Team: Community-tuned to reduce refusals; will execute security tasks. Low cost. Context 32K. Broadly available on OpenRouter; well-characterized community behavior. Reliable fallback if WhiteRabbit-Neo unavailable.



Qwen 2.5 72B / Qwen 3 for Red Team: Less restrictive than Llama 3.3 on many security tasks. Very low cost. Context 128K. Best cost-to-quality ratio of open models on OpenRouter.



DeepSeek V3 / R1 for Red Team: Strong general reasoning; less characterized for offensive security. Lowest cost of strong options. Context 64K+. Worth testing for mutation reasoning tasks. Data residency concern (Chinese provider) manageable for research context with no real PHI.



Llama 3.3 70B Instruct for Red Team (last resort): Meta recent versions added significant safety training; refuses some offensive prompts. Mid cost. Context 128K. Last-resort for Red Team: safety training counterproductive for adversarial generation.



Anthropic Claude Sonnet-class for Judge and Documentation (selected): Follows instructions including security evaluation. Mid-high cost. Context 200K. Cross-provider independence from Llama-family Red Team. Strong on nuanced partial-success evaluation. Consistent structured output.



Anthropic Claude Haiku-class for Documentation fallback: Same posture as Sonnet. Low cost. Context 200K. Acceptable with stricter template constraints.



OpenAI GPT-4o-class for Judge fallback: Handles evaluation tasks well. High cost. Context 128K. Best cross-provider fallback from Anthropic for Judge.



Google Gemini Flash / Pro for Phase 2 panel member only: Similar evaluation posture to Claude. Low-mid cost. Context 1M (Flash). Useful for multi-judge panel in Phase 2. Not needed for MVP.



Local / self-hosted (Ollama, llama.cpp): Fully permissive; near-zero cost. Infrastructure setup cost prohibitive for 5-day build. Phase 3 option if cost at 10K+ runs becomes the constraint.



Frontier commercial models for Red Team -- Explicitly rejected. Both OpenAI and Anthropic are trained to refuse jailbreak-generation requests. Safety training is a feature for clinical synthesis; it is an obstacle for adversarial generation. PRD p. 9 notes this directly.



Key tension: PRD pp. 5 and 9 explicitly note that frontier commercial LLMs are intentionally trained to avoid offensive security workflows. The Red Team job is precisely to generate adversarial inputs. Solution: open-weight model for Red Team; frontier model for Judge; OpenRouter as the routing layer providing both.



Multi-turn context window implications: Multi-turn attack sequences (Phase 2) accumulate conversation history. At 5-turn attacks, models use approximately 2-4K tokens of context. At 20-turn attacks (Phase 3), any model with less than 16K context is a risk. The Judge also sees full attack sequence plus target response. Frontier models 100K+ context windows handle this without architectural changes.



### Tradeoffs we own



1. Open-weight models produce lower-quality attacks than frontier models. Accepted in exchange for avoiding frontier refusal. Mutation loops compensate by generating N variants; quality is measured by Judge verdict distribution, not model name.

2. OpenRouter sees all platform prompts. Attack payloads pass through OpenRouter infrastructure. Acceptable for security research -- the target sentinel-pid boundary strips real PHI before any agent call. Attack payloads themselves are synthetic.

3. Model deprecation risk. OpenRouter periodically deprecates older model IDs. Pin specific versions in config; document in SETUP.md. Fallback chain absorbs short-term outages.

4. Judge using same provider as Documentation creates a shared-failure-mode. Both use Claude Sonnet via OpenRouter. If Anthropic has an outage or model behavior shift, both agents are affected simultaneously. Mitigation: GPT-class fallback for Judge; Documentation can queue on outage.

5. Selection criteria are defensible; specific model IDs will be questioned. The criteria survive model deprecation; specific IDs do not. ARCHITECTURE.md Section 8.2.5 addresses this directly.



### Open questions for Cory



First open question: WhiteRabbit-Neo availability on OpenRouter must be verified at build-start. If available, it is the most defensible Red Team model pick. If not, fall back to Dolphin-Mixtral. This is a 5-minute check; no code changes required; env var swap.



Second open question: DeepSeek R1 as Red Team reasoning model for mutation tasks. Worth testing in Phase 1 against Dolphin-Mixtral to see which produces higher Judge FAIL rate on distinct attacks. Data residency concern manageable for research context with no real PHI.



### Risks specific to our choice



1. Open-weight model quality is uncertain for novel attack categories. If FAIL rate is near zero after adequate attempts, Red Team model quality is the suspect.

2. OpenRouter availability and pricing are third-party dependencies. A pricing change or model removal mid-session disrupts the attack run. Mitigation: fallback chain; hard cost caps absorb price volatility.

3. Cross-provider Judge independence is partial. Both Judge and Documentation use Anthropic Claude. Full cross-provider independence would require GPT-class as primary Judge, which increases cost.

4. The selection criteria framework requires active maintenance. If a new dominant open-weight model appears, the criteria must be re-applied. Criteria are not self-maintaining.

5. Structured output reliability varies across model providers. Claude Sonnet is very reliable with JSON mode; open-weight models via OpenRouter have variable structured output support. Testing per-model in Phase 1 is required.



---

## Section 7 -- Tool Design



### What we have decided



ARCHITECTURE.md Sections 2 and 3.2 define the tool set. Each agent call to the outside world is mediated by a named tool:

- TargetClient: HMAC-signed HTTP to the Co-Pilot (Red Team only external call)

- RegressionStore: read/write of confirmed exploit YAML files under evals/regression/

- CoverageStateReader: reads evals/coverage.md and evals/results/run-id/manifest.json (Orchestrator input)

- ObservabilityWriter: emits Langfuse spans at every LLM call boundary

- SeedLoader: reads evals/seed/category/*.yaml (Red Team input)

- CriteriaLoader: reads evals/criteria/category.yaml (Judge input)

- VulnerabilityReporter: writes evals/vulnerabilities/VULN-NNN-DRAFT.md (Documentation Agent output)



### Alternatives considered



Target client authentication: HMAC-signed HTTP (chosen) vs mock target. Must use real target per PRD hard gate (p. 7). HMAC credentials stored in env, never in code.



Regression store format: YAML files in evals/regression/ git-tracked (chosen) vs SQLite database. YAML plus git provides version history, diff-readable change tracking, and no dependency on a database process. SQL adds complexity for no Phase 1 gain (ARCHITECTURE.md Section 9.1).



Coverage state: filesystem (chosen) vs Redis or in-memory dict. Filesystem survives process crashes; Redis adds an infrastructure dependency; in-memory dict is lost on crash.



Observability tool: Langfuse already wired in target Co-Pilot stack (chosen) vs LangSmith / Braintrust / custom. Langfuse is already operational. Reusing it costs zero new auth setup; provides per-agent cost attribution out of the box.



PHI scrubber on attack output: reuse existing scrubber pattern (chosen) vs write from scratch. The scrubber pattern from the target Co-Pilot is known-tested against the PHI exposure surface.



Mock vs real data during local development: The live target at https://142-93-242-40.nip.io is always-on. For local dev iteration on agent logic, a --dry-run flag can mock the target client by returning a canned response from a fixture file. All eval results used in deliverables come from live target calls.



Error handling per tool:

- TargetClient 5xx / network error: exponential backoff (3 retries); circuit breaker after 5 consecutive failures; Orchestrator pauses session on sustained unavailability

- TargetClient 429 rate-limited: respect Retry-After header; Orchestrator reduces attack frequency for remainder of session

- TargetClient HMAC signature rejected (401): hard fail and alert; requires credential rotation

- RegressionStore file not found or corrupt YAML: log and skip corrupt case; alert; do not halt daemon

- CoverageStateReader missing manifest.json on first run: initialize empty coverage state

- ObservabilityWriter Langfuse network unavailable: degrade gracefully; log spans to stdout as structured JSON; do not halt daemon

- VulnerabilityReporter filesystem write fails: alert and log to stdout; do not halt daemon (losing a draft report is recoverable; halting the daemon is not)



### Tradeoffs we own



1. HMAC credential management is manual. Credentials must be set in environment variables and never committed to git. The .env.example template documents required vars; pre-commit hook must check for HMAC secret patterns.

2. Filesystem-based tools are single-process. If Phase 3 parallelizes Red Team workers, file locking becomes necessary. For MVP single-process operation this is not a concern.

3. Langfuse requires network access. If the development machine is air-gapped, observability degrades to stdout-only. Acceptable for the research context.

4. YAML regression store is human-editable. This is a feature (humans can manually adjust exploit status) and a risk (manual edits can corrupt the store). CI runs a YAML schema validation step against every regression file.

5. The target client mock mode can drift from real target behavior. Engineers must re-verify against live target before filing results.



### Open questions for Cory



Decision needed: What is the HMAC key rotation policy? The platform uses the same HMAC key as the target Co-Pilot OpenEMR integration. If the target rotates its key (scheduled or in response to a security event), the platform needs a corresponding update. This should be documented in the runbook, not left as tribal knowledge.



---

## Section 9 -- Eval Approach



### What we have decided



ARCHITECTURE.md Sections 3.5 and 11 define three eval contexts:

- Context A: adversarial eval suite (the platform product) -- continuous attacks against the live target, verdict-classified by Judge Agent

- Context B: platform meta-tests -- unit tests, calibration tests, smoke tests, schema tests in tests/

- Context C: grader-facing artifacts -- filed vulnerability reports, regression cases, coverage report



The Judge Agent renders pass / fail / partial / uncertain verdicts using per-category criteria loaded from evals/criteria/category.yaml. Ground-truth calibration dataset (human-labeled attack/response/verdict tuples) is a Phase 2 addition; MVP relies on rubric-based criteria.



### Alternatives considered



LLM-as-Judge (rubric-prompted, frontier model) -- Selected. PRD requires evaluation of whether an attack succeeded, which is inherently a natural-language judgment task. Deterministic heuristics alone miss the tail. Signal quality: high -- nuanced; catches partial successes; handles natural language evaluation. Cost: mid (one frontier call per attack). Consistency: moderate -- model can drift; structured output helps. Calibration: requires ground-truth calibration dataset for drift detection.



Deterministic-only (keyword matching, regex patterns on target response) -- Insufficient for this domain. Cross-patient leakage (PHI via paraphrase) is precisely the case that breaks regex. Signal quality: low -- misses paraphrased leakage; misses context-sensitive partial success. Cost: very low. Consistency: very high.



Hybrid (deterministic fast-path plus LLM fallback) -- Valid architecture, adds complexity for MVP. Deterministic pre-filter catches obvious cases (target returned exact PHI string); LLM evaluates ambiguous responses only. Phase 2 consideration.



Multi-judge panel -- Highest signal quality: disagreement between judges surfaces ambiguity. Phase 2-3 feature. Single-judge sufficient for MVP given ground-truth calibration guard. ARCHITECTURE.md Section 9.1 explicitly defers this.



Human evaluation only -- Very high quality but very high cost; unsustainable at any continuous volume. Only appropriate for building ground-truth calibration dataset (Phase 2), not for runtime evaluation at continuous scale.



Proprietary LLM eval frameworks (Braintrust, Weights and Biases Weave) -- Equivalent to LLM-as-Judge. For a security research platform where all data is sensitive, keeping eval data in our infrastructure (Langfuse) is preferable to a platform dependency.



Ground truth data sources for Judge calibration (Phase 2):

1. W2 eval suite (67 cases) with human-reviewed verdicts. These are the seed cases; many already have a known-expected verdict. Promote these to Judge calibration tuples.

2. Manually verified confirmed exploits. When an engineer reviews and promotes a DRAFT vulnerability report, that (attack, response, verdict=fail) triple becomes a ground-truth anchor.

3. Known-safe synthetic cases. Craft attacks that are clearly benign (direct clinical question with no injection attempt); these should always produce PASS verdicts. Meta-test fixtures that should always fail their rubric are the inverse.



CI integration: Platform meta-tests (Context B) run on every commit via CI. Adversarial eval (Context A) is NOT run in CI per commit -- it calls a live target and costs money. The CI gate is whether the platform agent logic works, not whether the platform found a new vulnerability in the target. Manual or scheduled daemon runs produce the Context A artifacts.



### Tradeoffs we own



1. LLM-as-Judge is non-deterministic. The same attack replayed against the same target response can theoretically produce different verdicts across runs. Mitigation: pin Judge model version; compute agreement rate across repeated verdicts on calibration set.

2. MVP lacks human-labeled ground truth. Phase 1 Judge calibration is rubric-based only. There is no quantitative accuracy number to cite at the architecture defense. Mitigation: explicitly document this as Phase 2 work; the rubric criteria themselves are the interim quality control.

3. Rubric drift is the Judge primary failure mode. If the Judge criteria YAML gets stale as the target evolves, Judge verdict quality degrades silently. Mitigation: versioned criteria files; criteria updates require PR review.

4. Partial verdict handling is underspecified for regression. A PARTIAL verdict means a defense partially held. Whether this becomes a regression test depends on Orchestrator mutation strategy. Current ARCHITECTURE.md: PARTIAL triggers mutation, not a filed regression case. This is a design choice some teams would implement differently.

5. Calibration dataset is small at Phase 2 start. A calibration set of 30-50 tuples is sufficient to detect gross drift but insufficient for fine-grained accuracy measurement. Acceptable for research; insufficient for production-grade security claims.



### Open questions for Cory



None blocking for MVP. Phase 2 question: Should PARTIAL verdicts auto-file a regression test at lower severity than FAIL? Current architecture only files regression tests on FAIL. If a defense partially holds consistently, that is signal worth tracking. The counterargument: partial success does not establish a reproducible exploit, so regression test validity is uncertain. Decision can be deferred to Phase 2 based on empirical observation of PARTIAL verdict frequency.



### Risks specific to our choice



1. Judge rubric calibration is underspecified at Phase 1 start. The rubric must be precise enough that the Judge can distinguish pass/fail/partial reliably. Writing good rubrics is spec-writing, not code-writing, and it is easy to deprioritize.

2. Verdict non-determinism reduces regression reliability. If the Judge renders different verdicts on the same input across runs, confirmed exploits may not reproduce consistently. Mitigation: temperature=0; structured output enforcement; consistency checks against calibration set.

3. The adversarial eval artifacts (Context A) are not in CI. If an engineer makes a change that breaks the Red Team mutation logic, no CI check catches it until a manual eval run is triggered. Mitigation: smoke tests (Context B) cover the core loop path with mocked targets.

4. The eval and testing namespaces must stay distinct. evals/ is the product (adversarial findings). tests/ is the platform meta-testing. Conflating them makes it unclear which artifacts are deliverables and which are internal quality checks.

5. Context A continuous-mode output grows unboundedly. evals/results/ accumulates per-run directories indefinitely. Engineers must rotate or archive old results to avoid disk exhaustion on long-running deployments.



---
## Section 10 -- Verification Design

### What we have decided

ARCHITECTURE.md Section 4 covers the regression harness. Three layers of verification:
1. Judge evaluates attack success -- primary signal
2. Regression harness verifies fixed vs behavior-changed -- ARCHITECTURE.md Section 4.3
3. Human gate on high/critical reports before filing -- ARCHITECTURE.md Section 7.2

The PRD calls verification (p. 4) a hard problem: determining whether a fix actually improves the system or simply changes its behavior temporarily.

### Alternatives considered

For the claim Did the attack succeed:
- LLM Judge with rubric (chosen): handles semantic / paraphrased success; catches partial wins. Non-deterministic; requires calibration.
- String matching on response: deterministic. Misses paraphrase; brittle to target response format changes.
- Binary HTTP response code check: zero ambiguity. Only works for hard failures; not useful for semantic attacks.

For the claim Was the fix genuine or behavioral (the hard problem per PRD p. 4):

Pair verdict with fixed/changed classifier (chosen): Judge produces verdict; if attack passes on fixed target, require evidence that expected-safe behavior is present, not just different behavior. Can distinguish target refuses correctly from target saying something different that happens not to include PHI. Requires specific expected-safe criteria per category.

Replay identical attack N times, check verdict stability: Run same attack 3 times; if all 3 pass, call it fixed. Increases confidence in stochastic verdict. 3x cost; temporal non-stationarity means consecutive passes are not independent.

Adversarial variant generation post-fix: After fix, generate 5 variants; if all 5 pass, call category fixed. Stronger than single replay. High cost; Phase 2 feature.

Mechanistic fix verification (human-in-loop): Engineer identifies what changed in target code; confirms change addresses root cause. Highest confidence. Requires human; not scalable to continuous operation.

Confidence thresholds:
- Judge confidence >= 0.85: verdict accepted
- Judge confidence 0.70 to 0.85: verdict accepted but flagged for sampling review
- Judge confidence < 0.70: verdict = uncertain, escalates to human

Escalation triggers:
- verdict = uncertain: human review queue
- High/critical severity: human review queue regardless of confidence
- Judge uncertain rate > 25% in a session: alert (calibration may have drifted)
- Regression test PASS to FAIL transition: alert and open-findings bump

### Tradeoffs we own

1. Expected-safe behavior specs are the most important and most underspecified artifact. The criteria YAML files for each category must be precise enough that the Judge can distinguish target improved from target behaved differently. This is documentation work, not code work, and it is easy to deprioritize.
2. Mechanistic verification is out of scope for continuous automation. The platform can only verify behavioral outcomes, not root causes. A fix that produces correct behavior via the wrong mechanism will verify as fixed until the variant is tested.
3. Confidence thresholds are chosen by judgment, not calibration. The 0.85 / 0.70 thresholds have no empirical basis at Phase 1. They will need adjustment once the calibration dataset is built.
4. Different-behavior classification is a judgment call. The Judge must produce uncertain when the target response is neither clearly-vulnerable nor clearly-safe. Prompting the Judge to make this three-way distinction is harder than binary verdict prompting.
5. Regression test validity degrades as target evolves. An exploit valid against target version v1 may no longer be technically valid against target version v3. Stale regression cases produce false alerts. Mitigation: status field on every regression case; human review when active cases have not fired in 30+ days.

### Open questions for Cory

Decision needed: What is the minimum-repro requirement for a regression case? Define minimal repro as the smallest attack sequence that reliably produces the FAIL verdict, with no extraneous turns or tokens. This can be automated via binary search on attack sequence length.

### Risks specific to our choice

1. The fixed vs behavior-changed distinction requires category-specific criteria. Generic criteria are not sufficient. Category-specific criteria take time to write and must be maintained as the target evolves.
2. The uncertain verdict creates a human review backlog. If the Judge frequently marks verdicts as uncertain, engineers spend more time reviewing than the platform saves. Calibration is the long-run fix.
3. Regression tests can be simultaneously valid and misleading. A test that passes because the target model received a provider-side update (not because the code was patched) looks like a successful fix. Target version SHA tracks code version but not underlying LLM provider version. ARCHITECTURE.md Section 10.2 notes this as a continuous-mode-specific failure mode.
4. The platform cannot verify its own fix recommendations. The Documentation Agent recommends remediation, but has no mechanism to verify the recommended fix actually addresses the root cause. Human engineering review is the only backstop.
5. False positive vulnerability reports have a real cost. If the Documentation Agent files a high-severity report based on a flaky Judge verdict, engineers spend time reproducing a non-issue. The minimum-repro requirement and human gate on high/critical reports are the mitigations.

---
## Section 11 -- Failure Mode Analysis

### What we have decided

ARCHITECTURE.md Section 10 covers this in depth. Section 10.1 maps per-agent failure modes. Section 10.2 covers continuous-mode-specific failure modes. Section 10.3 addresses the recursion question (who tests the tester).

### Alternatives considered

The presearch format asks us to map to the checklist shape and surface anything missed. Cross-checking ARCHITECTURE.md Section 10 against the PRD appendix (pp. 14-15) and the Presearch checklist (p. 3):

PRD checklist items not fully addressed in ARCHITECTURE.md Section 10:

1. What happens when the Red Team Agent generates content that is itself harmful -- Addressed in ARCHITECTURE.md Section 2.1 (content-class filter plus refuse-and-log) but the hard category list (what content triggers the filter) is not specified. This is a gap. Recommendation: define hard categories explicitly: CSAM content triggers; real patient PHI inclusion in attack triggers; credentials or secrets in attack triggers.

2. What is the fallback when the Orchestrator has no clear next priority -- ARCHITECTURE.md Section 3.6.1 step 5 (round-robin by stale-since timestamp) is the fallback. But if ALL categories have stale-since less than 24h AND no open findings AND cost cap not hit? The Orchestrator should HALT with reason coverage-floor-met and notify the engineer to add new categories. This is implied but not stated explicitly.

3. How do you handle cascading failures across agents in a single test run -- ARCHITECTURE.md Section 3.4 lists per-agent timeout handling but does not address cascading. If Red Team generates 10 attacks, Judge times out on attack number 3, the remaining 7 attacks have no verdict, and the Orchestrator has partial coverage-state. Current handling: mark all uncertain; note in manifest that run was partial; continue (do not replay all 10). This needs to be made explicit.

Mapping checklist items to ARCHITECTURE.md:

Tool fails -- ARCHITECTURE.md Sections 3.4 and 10 -- coverage is comprehensive
Ambiguous queries -- Judge uncertain verdict plus Section 10.1 evaluator-collapse row -- covered
Rate limiting -- Section 3.4 target unavailable plus Section 3.2 OpenRouter fallback -- covered
Graceful degradation -- Section 8.1 soft/hard cost caps plus Orchestrator scope reduction -- covered
Red Team harmful content -- Section 2.1 content filter (hard categories not listed) -- gap: specify hard categories
Judge agreeing with everything -- Section 10.1 judge-collapse row plus meta-test fixtures -- covered
No clear Orchestrator next priority -- Section 3.6.1 fallback to round-robin plus halt-on-coverage-floor -- covered but needs explicit halt-reason documentation
Cascading failures across agents -- Section 3.4 handles individual agent failure; cascade not explicit -- partial gap

The hardest failure mode not mentioned anywhere: The Red Team mutation engine can produce attacks that look semantically similar to the seed case but are considered novel by the Red Team own evaluation -- while the Judge correctly identifies them as equivalent. This leads to mutation-diversity collapse (ARCHITECTURE.md Section 10.2 covers this) without the Red Team detecting it. The platform needs a diversity signal (e.g., attack embedding cosine similarity to prior attacks in the same category) to detect this early.

### Tradeoffs we own

1. Hard category filter for Red Team content is underspecified. A filter that is too aggressive will cause the Red Team to halt on legitimate security test generation. A filter that is too permissive risks the platform generating genuinely harmful content. The categories need to be specified before Phase 1 ships.
2. The platform has no mechanism to detect mutation convergence. If the Red Team mutation engine converges on a local maxima (all variants cluster around the same attack shape), the Orchestrator signal-to-cost halt will eventually fire -- but not until budget is wasted. An early-exit signal based on attack embedding diversity would save money.
3. Cascading failure handling is underspecified for partial run recovery. When Judge times out mid-batch, the manifest marks the run as partial. On daemon restart, does the partial run replay from where it left off, or does it start a new run? Current spec: start new run (simpler). This means partial runs waste some budget.
4. The suspicion threshold for platform-self-attack detection is unbounded. ARCHITECTURE.md Section 2.1 says Red Team output is treated as untrusted input by every downstream component. But the mechanism for detecting an attack targeting the platform itself is not specified beyond input sandbox.
5. Observability fatigue in continuous mode is real. A daemon running for 48 hours will produce thousands of PASS verdicts. Engineers will stop checking the dashboard. Mitigation is tiered notification (ARCHITECTURE.md Section 10.2) but the digest tooling (daily/weekly emails or webhook alerts) is not built into MVP scope.

### Open questions for Cory

Decision needed: What are the explicit hard-category content classifications for the Red Team filter? Propose: (1) any content involving minors in non-clinical contexts, (2) inclusion of real-appearing SSN/MRN/PHI in attack payloads (synthetic IDs are fine; real-format tokens that could be real PHI are not), (3) attack payloads targeting non-Co-Pilot endpoints or systems not in the approved scope list. Cory to confirm or revise this list.

---
## Section 12 -- Security Considerations

### Alternatives considered

Prompt injection into the platform own LLM calls: The Judge evaluates target responses. A malicious target response could attempt to inject instructions into the Judge evaluation prompt.

Structured output enforcement (chosen): Judge renders verdict as JSON object. If response cannot be parsed into JudgeVerdict schema, it is rejected. Free-text instructions in the target response cannot change the schema. Strength: high. Cost: low.

Response sanitization layer before Judge: strips known injection patterns. Pattern matching is brittle; advanced injections evade simple patterns. Not sufficient alone.

Fixed rubric in system prompt only: Good foundation but does not prevent the target response from containing injection attempts. Structured output is the defense at the boundary.

Sandboxed Judge context: Target response is a user-role message, not a system-prompt injection. Already implemented by virtue of how the Judge prompt is constructed.

Data leakage risks:

Real PHI in target responses stored in evals/results/: Target Co-Pilot uses sentinel-pid boundary (PersonaMap). If an exploit bypasses the sentinel boundary, the response WILL contain real PHI. Mitigation: PHI scrubber runs on all stored target responses before persisting to disk.

Attack payloads containing real PHI: Platform should use only synthetic patient data. evals/seed/ files must not contain real patient names, IDs, or PHI. CI checks seed files for PHI patterns before accepting commits.

OpenRouter sees attack payload content: Use only clearly-synthetic data in attack payloads. Document data classification in SETUP.md.

Vulnerability reports may summarize exploited PHI: PHI scrubber runs on Documentation Agent output before writing DRAFT.md. Classify evals/vulnerabilities/ as sensitive; restrict repo access accordingly.

API key management:
- HMAC key: Environment variable (COPILOT_HMAC_KEY); never in code or config files. Rotate when Co-Pilot rotates its key.
- OpenRouter API key: Environment variable (OPENROUTER_API_KEY). Rotate quarterly.
- Langfuse API key: Environment variable (LANGFUSE_SECRET_KEY). Rotate quarterly.
- Session credentials: Environment variable; scoped to a test-only OpenEMR account with no access to real patient records.

Pre-commit hook: detect-secrets or trufflehog scan on every commit to catch accidental secret commits.

Audit logging: Every autonomous action logged with agent name, version, inputs (full), outputs (full), human-approval status, timestamp. Logged to structured JSON files under logs/. Langfuse provides secondary audit trail at the LLM call level.

Access controls: Only engineers on the security team can trigger autonomous runs. Vulnerability reports are filed to a private directory. Coverage dashboards can be read-only public; findings cannot.

### Tradeoffs we own (Section 12)

1. The platform is not air-gapped. It calls OpenRouter (third-party LLM routing), Langfuse (third-party observability), and the target API. Mitigation: no real PHI in any of these flows; sentinel-pid boundary on target side; synthetic data in attack payloads.
2. PHI scrubber on target responses adds latency. At W2 levels, this is less than 50ms overhead. At high-volume Phase 3 operation, it could become a bottleneck.
3. The platform own LLM calls are subject to injection from crafted target responses. Structured output enforcement is strong but not perfect -- a target response that happens to be valid JSON matching the JudgeVerdict schema but with manipulated field values is a theoretical attack.
4. Access controls for the platform admin functions are policy-only at Phase 1. Scope enforcement is in the code (approved-target list) but enforcement of who can run this code is OS-level.
5. The recursion concern is open by design. The platform cannot fully test its own security at the same rigor level it tests the target. The stopping point is human review at trust gates, deterministic unit tests, and ground-truth calibration for the Judge.

### Open questions for Cory (Section 12)

Decision needed: What OpenEMR test account credentials are used for attack replay? The platform needs to authenticate to the OpenEMR session layer in addition to HMAC to make valid /chat calls. This should be a dedicated test account with no access to real patient records. Confirm the test account exists and is scoped appropriately before Phase 1 begins.

### Risks specific to our choice (Section 12)

1. The platform is not air-gapped and passes data through third-party services. The attack payloads and target responses flow through OpenRouter and Langfuse respectively. The mitigations (synthetic data, sentinel-pid boundary, PHI scrubber) reduce but do not eliminate this risk.
2. The PHI scrubber is a pattern-based filter. Paraphrased PHI (the exact vulnerability the platform is designed to detect in the target) could also appear in responses logged by the platform, and may evade the scrubber. This is acknowledged as an accepted residual risk.
3. Audit log completeness is not verified. The platform logs what it intends to log; there is no independent verification that all autonomous actions are captured. This is a standard limitation of self-reporting audit systems.
4. The human gate on critical findings creates a workflow dependency. If the security engineer reviewer is unavailable, critical findings accumulate as drafts. No mechanism currently triggers escalation if a high/critical draft goes unreviewed for more than 24h.
5. Prompt injection into the platform via the target response is a real threat that requires ongoing vigilance. As the target evolves and its response patterns change, the structured output defense must continue to hold.

---

## Section 13 -- Testing Strategy

### What we have decided

ARCHITECTURE.md Section 3.5 Context B defines platform meta-tests. Four test classes: unit tests (tests/unit/), Judge calibration tests (tests/calibration/), smoke tests (tests/smoke/), schema tests (tests/schemas/).

### Alternatives considered

Unit tests for platform tools and agents:

Pytest with mocked LLM responses (chosen): Fast; deterministic; covers agent logic without LLM API calls; can run in CI without cost. Mock openrouter.chat.completions.create() to return canned responses; test state transitions, schema validation, filesystem writes.

Full integration with live LLM: Tests actual model behavior. Expensive; non-deterministic; cannot run in every CI commit.

VCR.py cassette recording: Records real LLM calls, replays in tests. Cassettes go stale when model behavior changes; adds maintenance burden.

Unit test coverage targets:
- TargetClient: HMAC signature generation; retry logic; circuit breaker state machine; mock target responses. Key failures to cover: wrong HMAC leads to 401; 5xx leads to retry; 5 consecutive failures leads to circuit open.
- RegressionStore: write confirmed exploit; read by ID; status transitions; corrupt YAML handling.
- CoverageStateReader: parse manifest.json; initialize empty state on first run; compute per-category metrics.
- Judge rubric evaluation: per-criterion trigger logic; confidence threshold behavior; structured output parsing.
- Orchestrator selection rules: all 5 priority rules in ARCHITECTURE.md Section 3.6.1; halt conditions.
- Schema validation: all inter-agent JSON schemas per ARCHITECTURE.md Section 12.

Integration tests for agent flows:

Vertical slice smoke test: One full attack cycle -- Red Team seed, TargetClient (mocked), Judge (mocked canned verdict), Documentation (mocked), filesystem persistence.

Orchestrator loop smoke test: Three iterations of the main daemon loop with mocked agents. Tests loop termination conditions.

Crash recovery test: Write a partial manifest.json; restart daemon; verify it resumes from checkpoint. Target and LLM mocked.

Schema contract test: Generate an AttackCandidate; pass to Judge schema validator; generate JudgeVerdict; pass to Documentation schema validator. All schemas validated without LLM calls.

Adversarial testing of the platform itself (testing the tester per PRD pp. 14-15):

- Judge accuracy against ground truth: Calibration test suite of human-labeled (attack, response, verdict) tuples. Run weekly in Phase 2 when ground truth dataset exists.
- Red Team novelty -- is it generating distinct attacks or repeating? Attack embedding cosine similarity: compute embedding for each new attack; reject if similarity > 0.95 to any attack in same-category corpus.
- Judge uniform-verdict collapse: Meta-test fixtures -- cases that MUST produce PASS (clearly safe query) and cases that MUST produce FAIL (directly exploitable target behavior from confirmed finding). Run on every regression run.
- Documentation Agent report quality: Rubric against PRD required fields (vuln ID, severity, repro, expected/observed, remediation, OWASP, MITRE). Block DRAFT to FILED promotion if fields missing.
- Orchestrator halt condition correctness: Unit test -- inject cost-cap-exceeded state; inject all-categories-at-floor state; verify halt fires with correct reason.

Regression testing setup for platform code:

CI pipeline structure:
- Pre-commit: schema tests and unit tests (fast; less than 30s; no LLM calls)
- CI on every push: all unit tests, smoke tests, schema tests (less than 5 minutes)
- Weekly scheduled CI: Judge calibration tests against ground-truth dataset
- Manual trigger: full integration test with mocked target (pre-release check)

NOT in CI per commit: live target calls, real LLM calls (cost), adversarial eval runs (Context A). These are triggered manually or on a schedule.

### Tradeoffs we own (Section 13)

1. Mocked LLM responses in unit tests do not capture model drift. If the Judge model changes behavior in a new version, unit tests with canned responses will not catch it. Mitigation: weekly calibration tests against ground-truth; pin model versions.
2. Novel attack metric requires embedding computation on every attack. This adds latency and cost per attack. At MVP throughput (tens of attacks per session), the overhead is negligible. At Phase 3 throughput (thousands), it becomes a consideration.
3. The smoke test uses a mocked target -- divergence from real target behavior is possible. Smoke tests validate platform logic, not attack quality. Engineers must validate on live target before shipping findings.
4. Ground-truth calibration dataset does not exist at Phase 1 start. This is the largest testing gap. Interim mitigation: meta-test fixtures (known-pass and known-fail cases), weekly calibration run against those fixtures.
5. Testing the tester recursion has a practical stopping point but it is not automated. Human review of calibration cases is the final backstop. This is by design (ARCHITECTURE.md Section 10.3) but worth making explicit in the test strategy.

### Open questions for Cory (Section 13)

One decision needed: What CI system runs the platform meta-tests? The W3 platform is a standalone Python application, not an OpenEMR PHP module. It can use GitHub Actions, GitLab CI (if a new project is created), or a local pre-commit plus manual run model. Given the W3 timeline (5 days), a simple GitHub Actions workflow running pytest on every push is the right scope. Confirm: is the platform code in the same repo as OpenEMR (a new directory), or a separate repo? This changes which CI system is authoritative.

### Risks specific to our choice (Section 13)

1. Unit tests with mocked LLM responses can give false confidence. If the Judge prompt changes but the canned response fixtures are not updated, tests still pass while the actual Judge behavior degrades. Mitigation: fixture review is part of the PR checklist for any Judge prompt change.
2. The adversarial eval suite (Context A) is outside CI. A regression in Red Team mutation logic will not be caught until a manual eval run is triggered. Mitigation: smoke tests cover the core loop path; regression in mutation quality shows up in Judge verdict distribution trends.
3. The calibration test suite depends on the ground-truth dataset being correctly labeled. If the human-labeled tuples contain errors, the calibration tests will validate against incorrect ground truth. Mitigation: calibration dataset changes require two-engineer review.
4. Schema tests may lag behind schema changes. Any schema change must update both the code and the test simultaneously.
5. The recursion stopping point (human review of calibration cases) is a manual process. If the calibration dataset grows large, human review of all cases is impractical. Mitigation: sample-based review plus automated consistency checks.

---

---

## Findings Summary

Approximate word count: approximately 4800 words across 8 sections.

## The Three Most Surprising Alternatives Surfaced

1. Dolphin-class fine-tunes (and WhiteRabbit-Neo) as the most defensible Red Team model choices -- not any frontier model. The community-tuned uncensored LLM variants are frequently dismissed without recognizing that for adversarial security research platforms -- where the failure mode is the LLM refusing to do its job -- they are architecturally correct. WhiteRabbit-Neo (if available) is even more defensible: explicitly purpose-built for offensive security workflows. A grader who probes why Dolphin-Mistral gets a category answer: permissive safety posture is the first selection criterion, and Dolphin variants are the best-characterized permissive models on OpenRouter.

2. The Judge primary attack surface is crafted target responses, not external prompt injection. The platform attacks the Co-Pilot, but the Co-Pilot can respond with injection-containing outputs aimed at the Judge. This is a second-order attack vector (the platform creates conditions for the target to attack the platform) that was not surfaced in ARCHITECTURE.md. Structured output enforcement is the right mitigation, but the threat needs to be named explicitly in the security section.

3. Fixed vs behavior-changed is harder than pass vs fail. The regression harness requires distinguishing genuine fixes from behavioral changes that happen to pass the current test. The four-way verdict (pass / fail / partial / uncertain) with the uncertain case specifically handling neither vulnerable nor clearly safe is a non-obvious architectural decision. Most red-team platforms use binary pass/fail and miss the suspicious pass problem entirely. This is a significant product differentiation if explained well in the architecture defense.

## Sections With Genuine Open Questions for Cory

Section 7 (Tool Design): HMAC key rotation policy -- is there a documented rotation cadence for the Co-Pilot HMAC key, and does the platform team need to be notified when it rotates?

Section 11 (Failure Modes): Hard-category content classification list for the Red Team content filter -- Cory needs to approve the specific categories before Phase 1 ships. Proposed: (1) any content involving minors in non-clinical contexts, (2) inclusion of real-appearing SSN/MRN/PHI in attack payloads, (3) attack payloads targeting non-Co-Pilot endpoints or systems not in the approved scope list.

Section 12 (Security): Test account credentials for OpenEMR session authentication -- confirm a dedicated test account exists and is scoped correctly before any live attacks fire.

Section 13 (Testing): CI system for the standalone platform -- is this a separate GitHub/GitLab repo or a directory in the existing OpenEMR fork? This determines which CI configuration applies.

The question in Section 6 (WhiteRabbit-Neo availability) is a 5-minute check at build-start, not a design decision.

---

Prepared by Tate (Architecture Lead) as pre-search input for docs/presearch.md.