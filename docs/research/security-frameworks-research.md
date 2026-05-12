# W3 security frameworks research — drop notes here

**Purpose:** Capture current state of LLM/AI security frameworks as of 2026-05-11 so the W3 architecture defense + THREAT_MODEL.md cite ACTUALLY-CURRENT sources, not stale 2024 recall. Tate reads this file to update the threat model + architecture drafts.

**Format:** paste URL + bracketed data points under each section. Loose pasting is fine — Tate parses. No need for prose; bullets/lists/raw paste OK.

**Time budget:** ~15 min total. Tier 1 is essential; Tier 2 is bonus.

---

## TIER 1 — must-verify

### 1. OWASP LLM Top 10

**Search:** `OWASP Top 10 for LLM Applications 2026` OR `OWASP LLM Top 10 latest version`
**Try:** https://owasp.org/www-project-top-10-for-large-language-model-applications/

**Bring back:**

URL of canonical doc:

Current version (was v2.0 in Nov 2024 — what's it now?):

Date of last update:

Was it renamed / merged into something larger (e.g., OWASP GenAI Security Project)?

List of all 10 entries with their IDs (paste names is fine):
1.
2.
3.
4.
5.
6.
7.
8.
9.
10.

Anything new since 2024 worth flagging (e.g., new entry on agentic AI, multi-agent risks, supply chain)?

Not a URL. doc is here: C:\Dev\GauntletAI\AgentForge\.gauntlet\week3\research\LLMAll_en-US_FINAL.pdf
---

### 2. MITRE ATLAS

**Search:** `MITRE ATLAS adversarial AI`
**Try:** https://atlas.mitre.org/

**Bring back:**

URL of matrix page:https://atlas.mitre.org/matrices/ATLAS

Last-updated date (look for it in header or footer):

Current count of tactics + techniques (was ~14 tactics, ~80 techniques in 2024):
- Tactics:
- Techniques:

Tactic names (just copy the column headers from the matrix):

Any specific tactic or technique relevant to AGENTIC / MULTI-AGENT systems? (This is new territory; may or may not exist):

Technique IDs that look relevant to these PRD categories — if you can spot any:
- Prompt injection:
- Data exfiltration / PHI leakage:
- Tool misuse / agent action:
- Denial of service / cost amplification:

---

### 3. NIST AI Risk Management Framework

**Search:** `NIST AI RMF 600-1 generative AI profile` OR `NIST AI Risk Management Framework current`
**Try:** https://www.nist.gov/itl/ai-risk-management-framework

**Bring back:**

URL of canonical RMF page: https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf

Current version (AI RMF 1.0 was Jan 2023; is there a 2.0?):

Beyond AI 600-1 (Gen AI profile, July 2024), are there NEW profiles published? Specifically look for:
- Agentic AI profile?
- Multi-agent profile?
- Healthcare-specific profile?

Anything published in last 12 months (mid-2025 → now):
https://www.nist.gov/itl/ai-risk-management-framework

C:\Dev\GauntletAI\AgentForge\.gauntlet\week3\research\NIST.AI.100-1.pdf
---

## TIER 1.5 — REQUIRED (added per W3 multi-agent scope)

### 3.5. OWASP for Agentic Applications / Agentic Security Initiative (ASI)

**Search:** `OWASP Agentic AI security` OR `OWASP Agentic Applications top 10` OR `OWASP ASI agentic threats`
**Try:** https://genai.owasp.org/ (OWASP GenAI Security Project — likely umbrella)

**Why we want this:** the W3 PRD requires a MULTI-AGENT system. The LLM Top 10 covers attack surfaces of LLM apps (target), but our own attacker PLATFORM is agentic — needs agentic-specific framing (inter-agent trust, autonomous decisions, tool chaining at scale, agent collusion). Citing both = orthogonal coverage; defense story is stronger.

**Bring back:**

URL of canonical Agentic doc:https://www.trydeepteam.com/docs/frameworks-owasp-top-10-for-agentic-applications

What's it actually called (Agentic Applications Top 10? Agentic Security Initiative? something else)?

Maturity stage (alpha / beta / v1.0 / draft):

Last update date:

List of categories / threats it names (paste names):

Anything specifically about MULTI-AGENT systems (not just single-agent)?

Does it map to OWASP LLM Top 10 (e.g., "Agentic risk X extends LLM02")? Or is it stand-alone?

The OWASP ASI Top 10 2026 Risks List
Agent Goal Hijack (ASI01:2026)
Tool Misuse & Exploitation (ASI02:2026)
Agent Identity & Privilege Abuse (ASI03:2026)
Agentic Supply Chain Compromise (ASI04:2026)
Unexpected Code Execution (ASI05:2026)
Memory & Context Poisoning (ASI06:2026)
Insecure Inter-Agent Communication (ASI07:2026)
Cascading Agent Failures (ASI08:2026)
Human-Agent Trust Exploitation (ASI09:2026)
Rogue Agents (ASI10:2026)
---

## TIER 2 — nice-to-have

### 4. OWASP AI Exchange (the broader umbrella)

**Try:** https://owaspai.org/

One-liner: is this the broader umbrella for ALL OWASP AI work, where LLM Top 10 + Agentic both live? Or is it a separate methodology doc?
https://owaspai.org/docs/ai_security_overview/#how-to-use-this-document
---

### 5. Recent agentic-AI red-team research (last 6 months)

**Search:** `multi-agent red teaming LLM 2026` OR `agentic AI security framework 2026` OR `autonomous red team AI agent`

Any 1-2 publications from Anthropic / OpenAI / DeepMind / academic that we can cite for the multi-agent attacker methodology. Even just paper titles + date is fine.
https://www.microsoft.com/en-us/research/blog/red-teaming-a-network-of-agents-understanding-what-breaks-when-ai-agents-interact-at-scale/

https://ui.adsabs.harvard.edu/abs/2026arXiv260423338C/abstract
https://learn.microsoft.com/en-us/azure/foundry/concepts/ai-red-teaming-agent
---

### 6. Healthcare-specific AI security guidance

**Search:** `HHS AI security healthcare` OR `HITRUST AI controls` OR `FDA AI/ML SaMD security` OR `ONC HTI AI provisions`

Any one source naming healthcare AI security controls — would massively strengthen the "hospital CISO defense" angle (PRD p. 12).
https://www.hhs.gov/sites/default/files/hhs-artificial-intelligence-strategy.pdf
https://www.hhs.gov/programs/topic-sites/ai/index.html
C:\Dev\GauntletAI\AgentForge\.gauntlet\week3\research\HHS_use_cases

C:\Dev\GauntletAI\AgentForge\.gauntlet\week3\research\2025-hhs-ai-compliance-plan.pdf

C:\Dev\GauntletAI\AgentForge\.gauntlet\week3\research\hhs-artificial-intelligence-strategy.pdf
---

## NOTES — anything else worth flagging

(free-form: anything you noticed during research that doesn't fit above but matters)



---

## STATUS

- [ ] Tier 1 done — Tate can begin draft
- [ ] Tier 2 done — Tate has bonus material for stronger defense
- [ ] No internet / blocked / partial — Tate works with what's here

When done, drop a chat message with "research dropped" and Tate reads this file + drafts THREAT_MODEL.md + ARCHITECTURE.md anchored to the actually-current frameworks you found.
