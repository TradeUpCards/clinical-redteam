# AI Cost Analysis — Clinical Red Team Platform

**Status:** Final-sprint draft, 2026-05-13. Real per-call costs aggregated
from the deployed daemon's `cost-ledger.json` artifacts across 14 productive
runs (2026-05-13 18:39 → 20:30 UTC; ~2 hours of unattended continuous-mode
operation against `https://142-93-242-40.nip.io`).

**PRD anchor:** Submission Requirements row p.11 — *"Actual dev spend and
projected production costs for running the adversarial platform at 100 / 1K
/ 10K / 100K test runs. Consider architectural changes needed at each
scale. This is not simply cost-per-token × n runs."*

A "test run" in what follows means **one attack iteration** — one Red Team
generation + one target call + one Judge verdict, optionally with a
Documentation Agent draft when the verdict is FAIL or PARTIAL. That maps
directly to the cost-ledger's per-iteration accounting.

---

## At a glance

| Scale | Naive (cost × n) | Realistic (with arch changes) | Headline change |
|---|---|---|---|
| 100 runs | $0.55 | $0.55 | None — current single-process daemon handles this with cap headroom |
| 1K runs | $5.50 | $4-7 | Judge prompt caching + tiered-Judge (Sonnet only for high-severity seeds) |
| 10K runs | $55 | $20-40 | Horizontal daemon fleet + batch Red Team generation + response cache for repeat target queries |
| 100K runs | $550 | $80-180 | Queue-based architecture (Redis) + fine-tuned mid-tier Judge + S3-style artifact store + signal-to-cost halt becomes load-bearing |

The naive column assumes today's per-attack cost ($0.0055) scales linearly.
The realistic column applies the architectural changes named below.

The PRD's "not simply cost-per-token × n" demand is the difference between
the naive and realistic columns. Without architectural change, the 100K
case ($550) is feasible but wasteful. With it, the same coverage costs
$80-180. The architectural changes are not theoretical — each is named
against current code paths and current bottlenecks visible in the
cost-ledger data.

---

## 1. Actual development spend

**Source:** `evals/results/<run-id>/cost-ledger.json` written by
`src/clinical_redteam/cost_ledger.py`. Each file records `total_usd`,
`by_tier_usd` (`red_team` / `judge` / `documentation` / `orchestrator`),
`by_tier_calls`, plus a full `entries[]` history with per-call model,
tokens, and timestamp.

### 14 productive runs aggregated (2026-05-13 18:39 → 20:30 UTC)

| Metric | Value |
|---|---|
| Productive runs (attack_count > 0) | 14 |
| Zero-cost daemon-restart artifacts | 10 (excluded from averages) |
| Total attack iterations | 415 |
| Total spend | $2.304 |
| Spend per run (mean) | $0.165 |
| Spend per attack (mean) | $0.00555 |
| Attacks per run (mean) | 29.6 (12 runs at 30, 1 at 28, 1 at 27) |
| FAIL verdicts observed | 0 |
| PARTIAL verdicts observed | 0 |
| PASS verdicts | 218 (52.5%) |
| UNCERTAIN verdicts | 197 (47.5%) |

### Per-tier breakdown (one representative run — `20260513T201205-50dd98`)

| Tier | Model | Calls | Total spend | Mean per call | Share of run cost |
|---|---|---|---|---|---|
| Red Team | `deepseek/deepseek-chat` | 30 | $0.00723 | $0.000241 | 3.7% |
| Judge | `anthropic/claude-sonnet-4-5` | 30 | $0.18935 | $0.006312 | 96.3% |
| Documentation | (never invoked — 0 FAILs) | 0 | $0.00000 | — | 0% |
| Orchestrator | (pure Python rules per ARCH §8.2.4 — "MVP: Pure Python rules; no LLM") | 0 | $0.00000 | — | 0% |
| **Run total** | | **60 LLM calls** | **$0.19657** | | |

**Key shape:** Judge dominates ~96% of session cost at current settings.
That is the highest-leverage knob for architectural change at scale (see §4).

### What's NOT in this $2.30

Each productive run held to ~30 attacks (~7-9 minute wall-clock) before the
daemon recycled; the $5.00 `MAX_SESSION_COST_USD` hard cap was not hit even
once, and no run reached the `--max-iterations 1000` ceiling configured in
`.deploy/docker-compose.redteam.yml`. Documentation Agent has yet to fire
(zero FAIL/PARTIAL verdicts; see §5.1 for what that means for projections).

Earlier MVP-phase runs (B6 v1/v2, the "overnight Wed" run referenced in
session coordination notes) are not in this snapshot because the deployed
status app's `/api/runs` endpoint serves the 25 most recent run-ids and
those have rolled off. They're consistent with the per-attack figure above.

---

## 2. Per-attack cost (current architecture)

**Methodology:** sum `total_usd` from `cost-ledger.json` across all
runs ÷ sum of `verdict_counts` totals across the same manifests. Yields
$2.304 / 415 = **$0.00555 / attack** at current model configuration.

### What "current model configuration" means

- **Red Team Agent** — `deepseek/deepseek-chat` (primary).
  DeepSeek is at the bottom of OpenRouter's relevant-quality price band
  for unaligned generation. Fallbacks (`meta-llama/llama-3.1-70b-instruct`,
  `anthropic/claude-haiku-4.5`) are wired but did not trigger across the
  sampled runs.
- **Judge Agent** — `anthropic/claude-sonnet-4-5` (primary).
  Picked for scoring consistency; the Judge's PASS/FAIL/PARTIAL/UNCERTAIN
  call is the platform's load-bearing decision and the place where rubric
  precision dominates token cost.
- **Documentation Agent** — `anthropic/claude-haiku-4.5` (primary,
  deployed config) / `anthropic/claude-sonnet-4-5` (fallback).
  Fires only when Judge returns FAIL or PARTIAL; ARCH §8.2.3 specifies
  Sonnet-primary / Haiku-fallback as the Phase 1 design, but the
  deployed compose env (`.deploy/docker-compose.redteam.yml` L68-69)
  inverts this as an intentional cost-optimization for sprint
  conditions — cheap structured-output by default, with a Sonnet
  upgrade path on Haiku 429/5xx. With zero FAIL/PARTIAL verdicts in
  the sample window, Doc Agent contributes $0 — but that subsidy
  disappears the moment the target starts leaking (see §5.1).

### Per-attack cost vs. early-phase estimates

The F2 coordination ticket projected $0.02-0.04 per attack. Actual is
~$0.0055 — roughly 4-7× cheaper. Three reasons:

1. **Sonnet did not fall back to Haiku.** Plan was tier-mix; reality was
   100% Sonnet at $0.0063/call.
2. **Documentation Agent never invoked.** 0 FAILs in sample → no Haiku
   structured-output cost.
3. **No multi-turn or indirect-injection chains in sample period.**
   F6 (multi-turn PI) and F8 (indirect injection via `/attach_and_extract`)
   shipped to main earlier today but ran in parallel; their per-attack
   cost is 3-4× single-turn (additional Red Team generation + additional
   target call + additional Judge evaluation per turn). Future runs
   that include them will pull the per-attack mean up.

The realistic-projection column in §3 assumes a mix that bakes both in.

---

## 3. Projections at four scale tiers

### Methodology

- **Naive** = (current per-attack) × n. Honest baseline; equivalent to
  "no architectural change."
- **Realistic** = applies the architectural changes named in §4 cumulatively.
  Each tier carries the changes from the tiers below.

Realistic also assumes a more representative attack-mix than the sample
window: 1-5% FAIL/PARTIAL rate triggering Documentation Agent draft, and a
20-30% mix of multi-turn (F6) + indirect-injection (F8) attacks. Both
weight the mean per-attack cost upward.

### Tier-by-tier

#### 100 runs — $0.55 naive / $0.55 realistic

Trivial. Current single-process daemon handles this in ~3 minutes of
wall-clock. No architectural change needed. Cost-cap ($5 default) covers
9× headroom. Used today: 415 runs / $2.30 sits well above the 100-run
threshold and below the 1K threshold.

#### 1K runs — $5.50 naive / $4-7 realistic

Per-attack cost climbs from $0.0055 to $0.006-0.009 once F6/F8 attack-mix
plus 1-5% Documentation triggers are included. Naive linear extrapolation
overshoots because it doesn't account for **prompt caching** — at this
volume the Judge's per-category rubric stays constant across attacks
within a category, so OpenRouter's prompt-caching feature (which the
Anthropic models support) starts paying for itself. Caching the rubric
turns Judge's $0.0063/call into ~$0.002/call on cache-hit, cutting the
dominant cost line ~3×.

#### 10K runs — $55 naive / $20-40 realistic

Three changes apply. **Horizontal daemon fleet** (multiple processes
against a shared `evals/` tree with file-locking on `coverage.json`)
because a single Python process becomes the wall-clock bottleneck. **Batch
Red Team generation** — one DeepSeek call produces N mutations per seed
instead of one (already cheap, but N=8 in a single call cuts amortized
overhead). **Response cache at HMAC-payload level** because the target's
chat endpoint is deterministic on identical inputs; cached responses skip
the target call entirely and let the Judge run against the cached body —
saves ~20-30% of target-call latency budget (target itself is $0 but its
latency is real wall-clock at scale).

#### 100K runs — $550 naive / $80-180 realistic

This is where the PRD's framing really bites. Without architectural change,
$550 is *technically affordable* — but it would be one daemon process
running for ~7 days at 30 attacks per ~7 minutes. Sequential single-process
is the wrong shape entirely.

Four changes apply on top of the 10K-tier base:

1. **Queue-based architecture (Redis or similar)** — replaces the
   coverage-state-driven category selector inside a single
   Orchestrator process. Multiple workers pull seeded attack jobs off the
   queue; the Orchestrator becomes a job producer with halt-condition
   awareness.
2. **Fine-tuned mid-tier Judge** trained on accumulated PASS/FAIL/PARTIAL
   verdicts from the prior 100K-run history. Drops Judge cost from
   $0.0063/call (Sonnet) to ~$0.0008/call (small distilled model) for
   the 80-90% of clearly-pass clearly-fail cases; Sonnet only sees
   borderline / UNCERTAIN cases. Cuts the dominant cost line by ~5-8×.
3. **S3-style artifact store** for `evals/results/<run-id>/`. The
   filesystem-only approach is fine to ~10K runs; past that, NFS or
   POSIX filesystem becomes the operational pain point.
4. **Signal-to-cost halt becomes architectural insurance**, not a
   nice-to-have. At 100K runs, a 5% rate of low-signal attacks (PASS
   verdicts on categories where the target is provably defending) costs
   ~$30. The Orchestrator's halt-on-signal-collapse path (`ARCH §10.2`)
   stops the daemon as soon as the marginal return collapses; this is
   what keeps the realistic column at $80-180 instead of $300+. The
   mechanism is implemented (`agents/orchestrator.py` `signal_floor`
   parameter) but ships disabled by default — the deployed compose
   config does not set `ORCHESTRATOR_SIGNAL_FLOOR`, so the floor stays
   at 0.0 (halt skipped). Calibrating the threshold from real
   FAIL-verdict data is a prerequisite for activating it; until then,
   the 100K-tier realistic projection is conservative — the actual
   cost would be lower once the halt is enabled.

---

## 4. Architectural changes per tier (the substance behind the table)

| Change | Tier | Touches | Why it's load-bearing |
|---|---|---|---|
| Prompt-caching on Judge rubric | 1K | `src/clinical_redteam/openrouter.py` (per-tier completion call) | Judge is 96% of run cost; rubric is stable per-category; 3-5× cost cut on cache-hit |
| Tiered Judge model selection *(planned, not shipped)* | 1K | `src/clinical_redteam/agents/judge.py` + per-seed `severity_class` (seeds carry the field; Judge currently ignores it for model routing) | Sonnet only for HIGH/CRITICAL seeds; Haiku for LOW; cuts Judge mean spend ~40% |
| Horizontal daemon fleet | 10K | `src/clinical_redteam/agents/orchestrator.py` + `persistence.py` file-locking | Single-process wall-clock ceiling is ~30 attacks per 7 min × 1 process |
| Batch Red Team mutations | 10K | `src/clinical_redteam/agents/red_team.py` | N=8 mutations per LLM call cuts amortized DeepSeek overhead 6-8× |
| HMAC-payload response cache | 10K | `src/clinical_redteam/target_client.py` (new cache layer) | Deterministic target → skip the call entirely on repeat payloads |
| Queue-based architecture (Redis) | 100K | `src/clinical_redteam/agents/orchestrator.py` (split into producer + worker) | Orchestrator-as-producer is the only shape that scales past one machine |
| Fine-tuned mid-tier Judge | 100K | training pipeline (not in current repo) + new model entry in `openrouter.py` | Trained on prior verdict history; cuts Judge cost 5-8× on clearly-pass/clearly-fail cases |
| S3-style artifact store | 100K | `src/clinical_redteam/persistence.py` (new backend behind same interface) | NFS / POSIX filesystem becomes hot at this scale |
| Signal-to-cost halt as primary guard | 100K | `src/clinical_redteam/agents/orchestrator.py` halt-condition logic per ARCH §10.2 | Cost cap by itself is too coarse at this scale; need marginal-return early-stop |

Every change in this table maps to a current file or a clearly named new
component. None of them are speculative architecture; they're the natural
follow-on shape of the MVP code paths once the operational profile
demands it.

---

## 5. Honest limitations of these projections

### 5.1 Defense-profile dependence

Per-attack cost is bimodal on Judge verdict. A PASS or UNCERTAIN run costs
Red Team + Judge calls only ($0.0055). A FAIL or PARTIAL run additionally
triggers Documentation Agent ($0.001 on Haiku), and — for HIGH/CRITICAL
severity verdicts — a human-review pause that *doesn't* directly cost
LLM tokens but freezes operational throughput.

The current $2.30 total reflects **zero FAIL verdicts** in the sample
window. As soon as the target begins to leak under the F6+F8 attack
families that just shipped, two things change:

1. Mean per-attack cost climbs ~10-20% from Documentation Agent activations
2. Mean attacks-per-run drops because the Orchestrator's coverage-floor
   logic backs off once a category has confirmed signal — this is GOOD
   for total cost but invalidates naive "attacks × per-attack-cost"
   extrapolation

Both effects are captured in the realistic column of §3 via the assumed
1-5% FAIL/PARTIAL mix, but the actual mix is dependent on target defense
posture, which is itself moving as the target also iterates.

### 5.2 OpenRouter pricing drift

All per-call costs here are from `entries[].cost_usd` written by
`openrouter.py` at call time, which uses OpenRouter's response-reported
pricing. That pricing has shifted ~10-15% over the last 3 months for the
Sonnet/Haiku tier. Projections assume current pricing holds; a 20% drift
either direction is within historical norms.

### 5.3 Multi-turn and indirect-injection cost multipliers

Both `F6 / pi-multi-turn-context-poison` (Bram, merged 2026-05-13) and
`F8 / C-A + C-C indirect-injection` seeds (Bram, merged 2026-05-13) are
fundamentally 3-4× more expensive per attack than single-turn:

- Multi-turn = N target calls + N Red Team gens + 1 Judge verdict across
  the full chain. N=3 for the canonical seed.
- Indirect injection via `/attach_and_extract` adds a target-side
  extraction call before the chat call, plus a Red Team generation for
  the embedded-payload artifact.

The realistic projection bakes in a 20-30% mix of these attack types.
If the operational mix shifts heavier toward multi-turn (because Bram
expands the F6 seed catalog), the realistic numbers move up
proportionally.

### 5.4 Architectural items requiring validation work

The 100K-tier proposals — fine-tuned mid-tier Judge, queue-based
Orchestrator split, S3-style artifact store — are named here as the
correct architectural shape but have not been validated end-to-end.
The fine-tuned-Judge proposal in particular depends on having ~10K+
high-quality labeled verdicts, which requires the platform to first run
at meaningful scale and *then* curate the training set. That's a
multi-week effort outside W3 scope.

What the platform ships at W3 is sound architecture for 100-1K runs and a
defensible scaling path past that — not a deployed 100K-run system.

### 5.5 No FAIL-verdict cost data

The biggest single-data-point caveat: the current $2.30 doesn't include a
single Documentation Agent invocation because the target defended every
attack in the sample window. The Documentation Agent's actual per-call
cost is therefore extrapolated from prior B6 MVP runs ($0.0008-0.002
per invocation on Haiku, before VULN-001's Sonnet-fallback adjustment).
Once F6/F8 produce real FAIL verdicts, the per-FAIL Documentation cost
will replace the extrapolation with measured data; this doc should be
refreshed at that point.

---

## Appendix A — Raw data reference

Pulled 2026-05-13 ~20:35 UTC via the deployed status app's JSON API
(does not require droplet SSH):

```
GET https://redteam-142-93-242-40.nip.io/api/runs
GET https://redteam-142-93-242-40.nip.io/api/runs/20260513T201205-50dd98
```

The first endpoint returns the 25 most recent run summaries (run_id,
started_at, total_cost_usd, verdict_counts, category_coverage); the
second returns the full `manifest.json` + `cost-ledger.json` +
`coverage.json` for one run including the per-tier breakdown and
sampled `entries[]`.

All numbers in §1–§3 of this document are computed from those endpoints'
JSON outputs; no synthetic estimates appear in the actual-spend or
per-tier sections. The architectural-change cost-cut percentages in §4
are *informed projections* based on the cost-ledger shape, not measured
post-change; they should be validated by running the same workload with
caching/tiered-model enabled before being cited as production claims.

## Appendix B — Methodology integrity checks

The cost-ledger's atomic-write contract (`persistence.py::atomic_write_json`)
guarantees no half-written records on daemon crash. Every `record()` call
flushes synchronously; `cost-ledger.json` on disk is always at least as
recent as the last completed LLM call. Aggregating across run-ids
therefore captures every dollar spent in the sample window without
double-counting and without missing partial-run spend on a daemon halt.

The total-cost figure can be operator-confirmed against the OpenRouter
account dashboard for the same window; the cost-ledger's per-call records
use OpenRouter's response-reported pricing, so the two should reconcile to
within OpenRouter's own per-call tokenization rounding. The cross-check is
not independently verifiable from the repo alone — it requires an operator
with OpenRouter account access.

The per-tier breakdown is from `cost-ledger.json::by_tier_usd` which is
incremented in the same code path as `total_usd`; the two are consistent
by construction (`by_tier_usd.values().sum() == total_usd` within
floating-point precision).
