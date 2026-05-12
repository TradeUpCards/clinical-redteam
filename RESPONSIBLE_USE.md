# Responsible Use

The Clinical Red Team Platform is an autonomous multi-agent adversarial AI security platform built to test the AgentForge Clinical Co-Pilot. This document defines the platform's intended use, the responsibilities of anyone running it, and the dual-use posture the project commits to.

---

## What this platform IS for

- **Adversarial security testing** of LLM-powered clinical applications you own or have explicit, documented authorization to test
- **Continuous regression-defense** validation that fixes to vulnerabilities actually hold over time + across model and code changes
- **Vulnerability discovery + documentation** in a structured, reproducible form usable by engineering teams
- **Security research** in clinical / healthcare AI contexts, conducted under appropriate ethical frameworks

## What this platform IS NOT for

- **Attacking systems you don't own or aren't authorized to test.** This includes any third-party LLM application, any production clinical system without express written consent of its operator, any system whose owner has not signed off on the testing scope and the disclosure protocol that follows discovery
- **Generating attack content for actual deployment** against real systems by malicious actors
- **Fraud, harassment, intimidation, or any unauthorized intrusion** against any computer system, organization, or individual
- **Producing content involving minors** in clinical, sexual, or violent contexts (the Red Team Agent is configured to refuse generation of these categories — see `ARCHITECTURE.md` §2.1 "Hard content categories")
- **Producing or weaponizing real-world malware** (working CVE exploits, ransomware code, or similar). The Red Team Agent refuses to generate these
- **Generating attacks containing real Protected Health Information (PHI).** All testing uses synthetic data; the platform's PHI scrubber and the target's sentinel-patient boundary depend on this discipline being upheld

---

## On dual-use — the honest framing

This platform demonstrates adversarial AI techniques against a healthcare LLM application. Adversarial techniques are inherently dual-use: the same methods that find vulnerabilities can, in principle, be used to exploit them.

We choose to publish this work openly anyway, for these reasons:

1. **The techniques are not novel to this platform.** Every attack category the Red Team Agent generates maps to a publicly-documented OWASP LLM Top 10 entry, OWASP ASI Top 10 category, or MITRE ATLAS technique ID. We are not creating new attack capabilities; we are automating execution of well-known categories.

2. **The contribution is the harness, not the attacks.** The scientifically and operationally interesting artifact is the multi-agent system that hunts, evaluates, documents, and regression-tests adversarial findings *continuously* — with separated incentives between attack generation and evaluation. That harness has defensive value (more thorough testing of clinical AI systems) that exceeds its offensive value (the attacks it generates are derivative of public taxonomies).

3. **Healthcare LLM systems will be tested adversarially regardless.** They are being deployed at scale. Whether teams use a structured platform like this one or improvise piecemeal, adversarial testing is happening. A documented, framework-anchored, reproducible approach is preferable to ad-hoc red-teaming.

4. **The platform's defense-in-depth design assumes responsible operation.** Hard human gates on high/critical-severity findings, refused-content categories, scope-locked target list, audit logging of every autonomous action — these are architectural choices that constrain malicious use while preserving defensive utility.

We do not claim this dual-use posture is uncontested. Reasonable people can disagree about whether this work should be published. We made the call. If you fundamentally disagree, do not use the platform.

---

## Your responsibilities as an operator

By using this platform, you accept the following responsibilities:

### Authorization
- **Test only systems you own or have explicit written authorization to test.** "It's just a test" is not authorization. Bug-bounty program participation requires reading the program's scope and complying with it. Contracted penetration testing requires a signed statement of work. Internal corporate testing requires sign-off from the system's owner and your organization's security leadership. Document the authorization. Make it producible if asked.
- **Configure the platform's target scope explicitly.** The hard content categories in `ARCHITECTURE.md` §2.1 enforce that the Red Team Agent refuses to attack any URL other than the one configured in `RED_TEAM_TARGET_URL`. Do not bypass this guardrail.
- **Comply with all applicable laws.** This includes the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), the General Data Protection Regulation (EU), HIPAA (for healthcare contexts), and any other jurisdiction-specific computer-crime, privacy, or healthcare regulations that apply to you and the system you're testing.

### Disclosure
- **Disclose discovered vulnerabilities responsibly.** If the system you tested has a published vulnerability disclosure policy, follow it. If not, default to Coordinated Vulnerability Disclosure norms: report privately to the system owner, give them reasonable time to remediate before public disclosure (typically 90 days for severe issues), avoid disclosing exploit details before a fix is available.
- **Do not leverage discovered vulnerabilities for any purpose other than reporting.** Do not access data you are not entitled to; do not pivot into other systems; do not exfiltrate; do not persist access. If you discover a vulnerability that exposes data, stop, document the minimum necessary to report it, and report.
- **For healthcare contexts specifically:** if a vulnerability could expose PHI, treat your testing logs as PHI-exposing artifacts. Apply your organization's PHI handling controls. Do not commit logs containing real patient data to public repositories. Consult your organization's HIPAA Privacy Officer.

### Synthetic data
- **All adversarial testing should use synthetic data.** The platform is designed around the target's existing sentinel-patient boundary (real OpenEMR pids 1-4 are mapped to sentinel pids 999101-999104 before any agent call). Do not bypass this boundary.
- **If you fork this platform to test a different target, you must implement an equivalent PHI sanitization boundary** before generating any attack against a system that processes real patient data.

### Safe operation
- **Configure cost guards.** The platform's `MAX_SESSION_COST_USD` env var prevents runaway LLM spend; do not disable it.
- **Configure concurrency caps.** The platform's per-target rate limit prevents accidental denial-of-service against the target during testing; do not disable it.
- **Review high/critical-severity findings before action.** The Documentation Agent drafts but does not auto-file high/critical reports for a reason — false positives in this severity class waste engineering time and erode trust in the platform. Review each one.
- **Audit your runs.** The platform produces a complete audit trail at `evals/results/<run-id>/manifest.json`. Retain these for as long as your organization's audit retention policy requires.

---

## What we (the project authors) have done to constrain misuse

- **Hard content categories** — Red Team Agent refuses to generate content involving minors, real PHI, weaponized real-world malware, or attacks against systems other than the configured target. Documented in `ARCHITECTURE.md` §2.1; implemented as a pre-flight check on every `AttackCandidate`.
- **Target scope lock** — single configured target URL via env var; refused-and-logged when Red Team output appears to target anything else.
- **Severity gating** — Documentation Agent drafts all reports; high/critical-severity reports require human approval before promotion to filed status. No auto-filing of severe findings; no auto-creation of remediation tickets without human review.
- **Audit trail** — every autonomous action recorded with inputs, outputs, timestamp, and gate status.
- **Sentinel-patient boundary inheritance** — the target's existing PHI sanitization remains in effect; the platform tests against synthetic patient data only.
- **Framework anchoring** — every attack category maps to a publicly-documented OWASP / MITRE ATLAS taxonomy entry. Nothing novel to discover here that's not already public.
- **No exploit-pivot capability** — the platform is designed to discover and document vulnerabilities, not to chain them into broader system compromise. The Red Team Agent is bounded by single-attack-per-iteration scope; it does not maintain persistent access to discovered footholds.

---

## On healthcare-specific considerations

Healthcare AI systems carry elevated stakes because:

- Errors can directly harm patients (wrong recommendation acted upon, missed alert, fabricated information presented as fact)
- Real patient data is regulated under HIPAA (US) and equivalent frameworks elsewhere
- Vulnerabilities often have real-world clinical impact, not just data-exposure impact

This means:

- **Coordinate with your organization's clinical safety officer** before running adversarial testing against any system used in clinical workflows, even non-production environments, even with synthetic data
- **Coordinate with your organization's HIPAA Privacy Officer** if testing logs could plausibly expose PHI patterns (even synthetic) that resemble real patients
- **Consider clinical impact in your severity ratings.** A "low-severity" data exposure in another domain might be "critical" in healthcare if it could lead to a wrong-patient clinical decision
- **Do not test in production without explicit written authorization from clinical leadership.** Even read-only adversarial probes can perturb models in production via context contamination, log poisoning, or rate-limiting cascades

---

## If something goes wrong

If you believe the platform has caused unintended harm — to a system you tested, to a third party, to data, to operations — stop the platform immediately, preserve the audit trail at `evals/results/<run-id>/`, and report to your organization's security leadership. Do not attempt to remediate by continuing to use the platform.

If you believe the platform itself has a vulnerability that could be exploited (the Red Team Agent could be weaponized, the Documentation Agent could be tricked into filing fraudulent reports, the audit trail could be tampered with), report responsibly via the same coordinated-disclosure norms you would for any security tool.

---

## Closing note

Adversarial security testing makes systems safer. It also creates risk if conducted carelessly or maliciously. This platform exists because the authors believe the defensive benefit of structured, automated, framework-anchored adversarial testing of clinical AI systems exceeds the marginal offensive risk added by its publication. We rely on operators to share that judgment in how they use it.

If you have questions about whether your intended use is responsible, the right answer is to ask before running, not after.
