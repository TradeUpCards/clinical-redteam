# Research material

Source canon for the ARCHITECTURE.md + THREAT_MODEL.md framework anchoring. Verified current as of 2026-05-11.

## W3 case study (project north star)

- [`prd/Week 3 - AgentForge - Adversarial AI Security Platform PRD.pdf`](./prd/) — the W3 case study from GauntletAI Austin Admission Track

## Framework anchors (Tier 1 — must-cite)

| File | What it is | Use in this project | Canonical URL |
|---|---|---|---|
| [`frameworks/OWASP-LLM-Top10-v2025.pdf`](./frameworks/OWASP-LLM-Top10-v2025.pdf) | OWASP Top 10 for LLM Applications, v2.0 (released Nov 2024) | Attack-surface taxonomy for the **target** Co-Pilot — see `THREAT_MODEL.md` §2 | https://genai.owasp.org/llm-top-10/ |
| OWASP ASI Top 10 2026 *(notes only — see `security-frameworks-research.md`)* | OWASP Agentic Security Initiative Top 10 2026 — agent-specific threats | Security posture for **this platform** (autonomous multi-agent) — see `THREAT_MODEL.md` §3 + `ARCHITECTURE.md` §2 (per-agent ASI risk mapping) | https://genai.owasp.org/initiatives/agentic-security/ (companion to LLM Top 10 under same OWASP GenAI Security Project umbrella) |
| MITRE ATLAS *(referenced by URL — atlas.mitre.org)* | Adversarial Threat Landscape for AI Systems — MITRE ATT&CK-style tactics + technique catalog for ML/AI | Per-attack tactical citation (e.g., `AML.T0051 LLM Prompt Injection`) — used by Judge Agent + Documentation Agent for stable IDs | https://atlas.mitre.org/ |
| [`frameworks/NIST.AI.100-1.pdf`](./frameworks/NIST.AI.100-1.pdf) | NIST AI Risk Management Framework 1.0 (Jan 2023) | Governance lens — Govern / Map / Measure / Manage functions structure platform's policy + audit posture; see `ARCHITECTURE.md` §7 | https://www.nist.gov/itl/ai-risk-management-framework |

## Healthcare-specific guidance

| File | What it is | Use in this project |
|---|---|---|
| [`healthcare/hhs-artificial-intelligence-strategy.pdf`](./healthcare/hhs-artificial-intelligence-strategy.pdf) | HHS Artificial Intelligence Strategy | Healthcare governance + clinical-AI risk framing for the "hospital CISO defense" angle (PRD p. 12) |
| [`healthcare/2025-hhs-ai-compliance-plan.pdf`](./healthcare/2025-hhs-ai-compliance-plan.pdf) | 2025 HHS AI Compliance Plan | Compliance lens for healthcare AI — informs USERS.md persona work (CISO + clinical safety officer) |
| [`healthcare/HHS_use_cases/`](./healthcare/HHS_use_cases) | HHS AI use-case catalog | Reference for clinical-AI patterns we may probe |

## Research notes (working file)

- [`security-frameworks-research.md`](./security-frameworks-research.md) — original research dump from 2026-05-11, capturing what was current at architecture-defense time. Includes URLs, version numbers, and cross-references that informed the framework anchoring choice.

## How this material is used

The architecture defense was built on top of this material. Specifically:

- **OWASP LLM Top 10 v2025** entries map 1:1 to the W3 PRD's 6 named attack categories (prompt injection / data exfiltration / state corruption / tool misuse / DoS / identity & role exploitation). See `THREAT_MODEL.md` §2 for the full per-entry coverage map.
- **OWASP ASI Top 10 2026** covers what the LLM Top 10 doesn't — agent-specific risks (inter-agent communication, cascading failures, rogue agents, agent goal hijack). See `THREAT_MODEL.md` §3 + `ARCHITECTURE.md` §2 (per-agent ASI risk callouts).
- **MITRE ATLAS technique IDs** give the Documentation Agent a stable, machine-greppable taxonomy that maps to existing security tooling.
- **NIST AI RMF** provides the governance scaffolding for trust boundaries — see `ARCHITECTURE.md` §7.4 for the function mapping.
- **HHS AI Strategy** anchors the "would a hospital CISO trust this platform?" defense (PRD p. 12).

## Why these and not others

The W3 brief explicitly says: *"The goal with this research is to lean into what is already known so you don't reinvent the wheel."* These are the established frameworks a hospital CISO already recognizes. Citing them gives the platform credibility faster than inventing taxonomy.

Out of scope for tier-1 anchoring (may add in Phase 2/3): Google SAIF (light overlap with OWASP), HITRUST AI controls (subscription required), Anthropic Responsible Scaling Policy (provider-specific).
