# Clinical Red Team Platform — Users

**Project:** Clinical Red Team Platform — autonomous multi-agent adversarial AI security platform.
**Source-of-truth note:** Every agent capability built in `ARCHITECTURE.md` and the implementation must trace back to one of the use cases defined here. If a capability does not serve a use case below, it is out of scope for W3.

---

## Important framing — who this serves

The user of THIS platform is **not the physician** the target Co-Pilot serves. The Co-Pilot's user (the primary care physician — see [companion repo `USERS.md`](https://github.com/TradeUpCards/agentforge/blob/master/USERS.md)) is the END-USER whose safety this platform protects, but the platform itself is operated by **security and platform-engineering roles** inside a healthcare organization that runs an LLM-powered clinical product.

This distinction matters: the platform's UX is a CLI + a vulnerability-report viewer + a coverage dashboard, not a chat panel inside an EMR. It runs continuously in the background. Its "interface" is the artifacts it produces.

---

## Target Users (4 personas)

### U1 — Security Engineer (primary daily operator)

**Who:** application-security or AI-security engineer at a healthcare organization that has deployed a clinical LLM product. Holds responsibility for finding and triaging vulnerabilities before clinical impact.

**Workflow:** runs the Clinical Red Team Platform against the deployed Co-Pilot continuously (nightly batch + on-demand on every Co-Pilot deploy). Reads vulnerability reports as they're filed. Validates HIGH/CRITICAL severity reports before they're promoted from `DRAFT` status. Tunes attack-category prioritization when coverage gaps emerge.

**What they need from the platform:**
- A `run` command that targets the deployed system without needing per-attack scripting
- Vulnerability reports they can validate and promote/reject in <5 minutes per report
- Coverage dashboards showing which attack categories have been exercised vs gap
- Cost telemetry showing burn per session + per agent
- A regression harness that auto-runs when the target version changes

**Why an autonomous agent system, not a static scanner.** Static scanners run a fixed test suite. Adversarial AI requires *adaptation* — the Red Team Agent must mutate partially-successful attacks, learn from defenses, and prioritize based on coverage gaps. A human can't write enough static tests fast enough to keep up with a Co-Pilot whose underlying LLM updates monthly. The platform's value to U1 is **continuous adaptive coverage** that a static suite can't provide.

### U2 — Clinical AI Platform Owner (Co-Pilot dev team — receives findings)

**Who:** lead engineer (or PM) for the Clinical Co-Pilot product. Receives vulnerability reports from U1 and decides remediation priority + assigns to engineers.

**Workflow:** reads filed vulnerability reports. Reviews HIGH/CRITICAL drafts before U1 promotes them. Tracks open findings → fix → regression-validation cycle. Decides scope of fixes (vs deferred-with-rationale per `AUDIT.md` C-7 pattern from W2). Pushes fixes that get auto-regression-tested by the platform on the next deploy.

**What they need from the platform:**
- Vulnerability reports formatted for engineering action: minimal repro, observed vs expected, recommended remediation
- Regression confirmation when their fix lands ("the fix held; here's the regression test that now passes")
- Cross-category regression detection (PRD: *"flag when fixing one attack introduces a regression in another category"*)
- A traceable history of who-fixed-what-when

**Why an autonomous agent system.** The dev team can't run continuous adversarial testing themselves — it's not their core job. The platform delegates the "find vulnerabilities" responsibility entirely so the dev team can focus on building + fixing. The Documentation Agent's report quality bar (PRD: *"a senior security engineer could reproduce, validate, and fix the vulnerability based solely on what the agent writes"*) is the load-bearing UX requirement here.

### U3 — Hospital CISO (governance + trust signoff)

**Who:** Chief Information Security Officer at the hospital deploying the Co-Pilot. Decides whether to trust the platform with continuous security testing of systems their physicians depend on. Must sign off on each major Co-Pilot version going to clinical use.

**Workflow:** reads platform-level summaries monthly (or on Co-Pilot version change). Reviews policy-level questions: is the threat model comprehensive? Are framework anchors current (OWASP / NIST / HHS)? What's the platform's own posture against rogue-agent risk? Is human approval gating critical-severity reports correctly?

**What they need from the platform:**
- A coverage map by attack category × target version + trend (is the system getting more or less resilient?)
- Open-finding inventory by severity with expected remediation timelines
- Cost burn rate + projection at scale
- Documented governance — which decisions are autonomous vs which require human gate
- Audit trail — every autonomous action recorded with inputs/outputs/timestamp
- Framework-recognized threat-model categorization (OWASP IDs, MITRE ATLAS technique IDs) — speaks the language CISOs already know

**Why this matters.** The PRD's "Final Note" sets exactly this bar: *"the deliverable that matters is not the one that finds the most impressive jailbreak in a demo. It's the one you could defend in front of a hospital CISO who is deciding whether to trust this platform with continuous security testing of systems their physicians depend on."* U3's needs ARE the design constraint.

### U4 — Compliance Officer (audit + healthcare regulatory)

**Who:** healthcare compliance officer (or external auditor) reviewing the AI deployment posture against HHS AI Strategy + 2025 HHS AI Compliance Plan + NIST AI RMF.

**Workflow:** quarterly review. Reads governance documentation; samples a vulnerability report from each severity tier; verifies audit trail completeness; checks that human-gate enforcement is technical (not just documented).

**What they need from the platform:**
- NIST AI RMF function mapping (Govern / Map / Measure / Manage) showing which platform component fulfills each function
- HHS AI Strategy alignment — which controls map to which platform behaviors
- Audit log of every human-gate action: who approved what, when, with what evidence
- Reports formatted in a way that survives external audit review (severity scoring is reproducible; remediation status is tracked)

**Why an autonomous agent system, with these specific controls.** Healthcare AI deployments increasingly require demonstrable continuous testing, not point-in-time audits. An autonomous platform with strong audit trails + human gates at safety-critical decisions delivers both — continuous coverage WITH compliance-grade traceability.

---

## What this platform does NOT serve (out of scope)

These are real adjacent needs that other tools handle better — listed explicitly so they're not perceived as gaps in our scope.

- **Penetration-testing the underlying infrastructure** (Caddy, OpenEMR PHP, MariaDB, network layer). Different tooling class — handled by traditional pentest firms.
- **Static code analysis of the Co-Pilot codebase** (SAST). Different methodology; static analyzers are deterministic, our platform is probabilistic + adaptive.
- **Production fraud detection or anomaly monitoring** of clinical Co-Pilot usage. Different user population (clinical operations team, not security); different signal class.
- **Replacing the Co-Pilot's own internal test suite** (the W2 67-case eval gate). The platform's eval suite ATTACKS the Co-Pilot from outside; the W2 test suite VALIDATES it from inside. Both needed; different jobs.
- **Authoring fixes to discovered vulnerabilities.** Documentation Agent recommends remediation but does not auto-patch the target. Fixes are U2's responsibility.
- **Generating clinical content of any kind.** This is a security tool, not a clinical AI product. It does not advise on patient care.

---

## Source-of-truth commitments

Per the W3 PRD: every agent capability built in `ARCHITECTURE.md` traces to one of these four use cases.

| Use case | Triggers the build of | Evidence in this repo |
|---|---|---|
| U1 — Security Engineer | Red Team Agent, Judge Agent, run CLI, coverage dashboard, cost telemetry, regression harness | `agents/red_team/`, `agents/judge/`, observability layer |
| U2 — Clinical AI Platform Owner | Documentation Agent (vuln report quality), regression-validation flow, cross-category regression detection | `agents/documentation/`, `evals/regression/` |
| U3 — Hospital CISO | Framework-anchored threat model, governance documentation, autonomous-vs-gated decision audit, trend metrics | `THREAT_MODEL.md`, `ARCHITECTURE.md` §7, `docs/governance.md` (Phase 2) |
| U4 — Compliance Officer | NIST AI RMF function mapping, HHS AI Strategy alignment, full audit trail, structured vuln reports | `ARCHITECTURE.md` §7.4, `docs/governance.md` (Phase 2), `evals/vulnerabilities/` (with status field) |

If any agent or capability in the implementation cannot be traced to U1-U4 above, it should be deferred or cut.
