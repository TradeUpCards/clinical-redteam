# SETUP — Clinical Red Team Platform

How to install and operate the platform end-to-end against the deployed target.

> **Time to first attack:** ~10 minutes from a clean machine if the deployed target is already running. The target deployment itself is W2 scope and lives in the [companion repo](https://github.com/TradeUpCards/agentforge).

---

## 1. Prerequisites

| Requirement | Why | Verify |
|---|---|---|
| **Python 3.12+** | Pydantic v2 + modern type syntax | `python --version` |
| **git** | Clone + branch + push | `git --version` |
| **OpenRouter API key** | LLM routing for Red Team / Judge / Doc Agents | https://openrouter.ai/keys |
| **Network access to the deployed target** | Live attacks (PRD hard gate) | See §4 |
| **HMAC secret from the deployed target** | Sign requests so the target accepts them | Pull from companion-repo `.env` or DO droplet env |
| **(Optional) Langfuse keys** | Inter-agent trace inspection | https://cloud.langfuse.com — no-op without keys |
| **(Optional) SSH access to droplet** | If agent endpoint isn't publicly exposed | `ssh root@142-93-242-40.nip.io` |

---

## 2. Clone + install

```bash
git clone https://github.com/TradeUpCards/clinical-redteam.git
cd clinical-redteam

# Windows PowerShell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

# macOS / Linux
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Smoke-verify the install:

```bash
python -m clinical_redteam.run --version
python -m clinical_redteam.run --list-categories
pytest -q
```

Expect: version string, 3 categories listed with seed inventory, all tests passing (~256 at MVP cutoff).

---

## 3. Configure `.env`

Copy the template and fill in real values:

```bash
cp .env.example .env
```

Required variables:

| Variable | Purpose | Example |
|---|---|---|
| `OPENROUTER_API_KEY` | Auth for OpenRouter — Red Team + Judge + Doc Agent all route through it | `sk-or-v1-...` |
| `RED_TEAM_TARGET_URL` | Where attacks go. Tunnel path OR direct deployed URL — see §4 | `http://localhost:8000` |
| `RED_TEAM_TARGET_HMAC_SECRET` | Must match the deployed Co-Pilot's `OPENEMR_HMAC_SECRET` exactly | `(32+ char hex)` |
| `RED_TEAM_TARGET_USER_ID` | User context for HMAC payload. W2 admin parity | `1` |
| `RED_TEAM_TARGET_SENTINEL_PATIENT_IDS` | Sentinel-only patient IDs allowed in attacks. Comma-separated, must be 999100–999999 | `999100,999114,999050` |

Optional (with sane defaults):

| Variable | Default | Override when |
|---|---|---|
| `MAX_SESSION_COST_USD` | `10` | You want stricter cost cap per session |
| `RED_TEAM_TIER1_MODEL` / `TIER2_MODEL` / `TIER3_MODEL` | (set in .env.example) | Testing a different routing chain |
| `LANGFUSE_PUBLIC_KEY` + `LANGFUSE_SECRET_KEY` + `LANGFUSE_HOST` | unset (no-op) | You want inter-agent traces in Langfuse UI |
| `HMAC_MAX_AGE_SECONDS` | `30` | Target's tolerance is wider |
| `LOG_LEVEL` | `INFO` | Debugging — set to `DEBUG` |
| `EVALS_DIR` | `./evals` | Pointing at a different eval-suite checkout |
| `RESULTS_DIR` | `./evals/results` | Writing run artifacts elsewhere |

**Hard rule:** patient IDs in attack payloads MUST be in the sentinel range 999100–999999. The target client refuses anything else (`target_client.py:76-83`). This is a project-wide guardrail to keep attacks from accidentally touching real-or-could-be-real PHI even though the deployed target only has synthetic data.

---

## 4. Connect to the target

The platform attacks the **deployed Co-Pilot** at `https://142-93-242-40.nip.io`. Two paths, depending on whether the agent endpoint is publicly exposed:

### Path A — Direct (if agent is public on the droplet)

```bash
# In .env:
RED_TEAM_TARGET_URL=https://142-93-242-40.nip.io
```

Confirm by running a smoke attack (§5). If you get HTTP 200 with valid response → direct path works, no tunnel needed.

### Path B — SSH tunnel (if agent is Docker-internal only)

```bash
# In .env:
RED_TEAM_TARGET_URL=http://localhost:8000

# Then in a separate terminal, KEEP THIS RUNNING:
ssh -L 8000:127.0.0.1:8000 -o ServerAliveInterval=30 -o ServerAliveCountMax=3 root@142-93-242-40.nip.io
```

The `ServerAliveInterval` flags keep the tunnel from dying on idle connections. If the tunnel drops, attacks will fail with `connection refused` until you reopen it.

Verify either path:

```bash
curl http://localhost:8000/health         # tunnel path
# OR
curl https://142-93-242-40.nip.io/health  # direct path
```

Expect: `{"status":"ok","llm_mode":"live"}` or similar 200 response.

---

## 5. First attack (single-shot)

```bash
python -m clinical_redteam.run \
  --category sensitive_information_disclosure \
  --max-attacks 1 \
  --no-mutate
```

What happens:
1. Loads the canonical SID seed (`evals/seed/sensitive_information_disclosure/c7-paraphrased-leakage.yaml`)
2. Red Team Agent constructs the attack prompt
3. Content filter pre-flight (refuses out-of-scope categories before the target sees them)
4. HMAC-signed POST to the target's `/chat` endpoint
5. Judge Agent evaluates the response against `evals/criteria/sensitive_information_disclosure.yaml`
6. Verdict (pass / partial / fail) written to a new run dir under `evals/results/<timestamp>-<hash>/`
7. If verdict = FAIL → Documentation Agent drafts a vuln report

You should see ~1 attack output to stdout + a new `evals/results/<run-id>/` directory.

---

## 6. Continuous mode (the "platform running live tests" PRD hard gate)

Run the Orchestrator daemon. Halts on cost cap, signal collapse, coverage floor, max-iterations, or SIGINT (Ctrl-C):

```bash
python -m clinical_redteam.run \
  --continuous \
  --max-budget 1.00 \
  --max-iterations 50 \
  --halt-on-empty-categories
```

The Orchestrator picks categories itself based on coverage state — you don't pass `--category` in continuous mode.

One JSON-line per iteration goes to stdout (suitable for `tee` into a log). Final `HaltReport` printed on exit explains why the daemon stopped.

For a longer run:

```bash
python -m clinical_redteam.run \
  --continuous \
  --max-budget 5.00 \
  --max-iterations 500 \
  2>&1 | tee evals/results/run-$(date +%Y%m%dT%H%M%S).log
```

### Resume after interrupt

The persistence layer writes manifest checkpoints atomically. If the process dies mid-run:

```bash
python -m clinical_redteam.run --resume <run-id>
```

(The run-id is the directory name under `evals/results/`.) The daemon picks up from the last checkpointed iteration with cost ledger + coverage state intact.

---

## 7. Reading results

Each run produces a directory like `evals/results/20260512T134033-f7bfca/`:

| File | What it tells you |
|---|---|
| `manifest.json` | Run-level summary: start/end timestamps, halt reason, verdict counts, total cost |
| `coverage-state.json` | Per-category attack count, per-attack verdicts. What the Orchestrator reads to decide what to attack next. |
| `cost-ledger.json` | Per-call cost, per-tier breakdown, model name + tokens for every LLM invocation |
| `attacks/<n>-<seed_id>.json` | Per-attack: prompt, response, Judge verdict + rubric trigger, mutation lineage |

For vulnerabilities (only created when a FAIL verdict fires):

| File | What it tells you |
|---|---|
| `evals/vulnerabilities/VULN-<NNN>-<slug>.md` | Documentation Agent's structured report. CISO-readable: severity, repro, observed-vs-expected, remediation. |

If `LANGFUSE_*` keys are set, the same activity is in the Langfuse UI as inter-agent spans with cost attribution per agent role.

---

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `OutOfScopeTargetError` | `RED_TEAM_TARGET_URL` hostname not on allowlist | Allowlist is in `target_client.py:55-67` — must be `localhost`, `127.0.0.1`, `142-93-242-40.nip.io`, or `agent`. Anything else is a hard refusal. |
| `SentinelPatientIdError` | Attack payload references a non-sentinel patient ID | Patient IDs in seeds + mutations must be 999100–999999. Real PIDs (1–200) are forbidden even though the deployed target is synthetic-only. |
| HTTP 401 from target | HMAC signature mismatch | `RED_TEAM_TARGET_HMAC_SECRET` doesn't match what the deployed target expects. Re-pull from companion-repo `.env` or the droplet. |
| HTTP 404 from OpenRouter | A tier model was delisted | Check `RED_TEAM_TIER*_MODEL` values against current https://openrouter.ai/models. Tier fallback (429/5xx/connect/404) will auto-degrade through tiers but if ALL tiers fail there's a config issue. |
| Connection refused on `localhost:8000` | SSH tunnel dropped | Restart the tunnel (§4 Path B). Use `-o ServerAliveInterval=30` to keep it alive. |
| Cost cap fires too early | `MAX_SESSION_COST_USD` too low or you're running expensive models | Either raise the cap or switch tier models to cheaper alternatives. Inspect `cost-ledger.json` to see where the spend went. |
| Tests fail after `pip install -e ".[dev]"` | Wrong Python version | Check `python --version`. Must be 3.12+ for Pydantic v2 + match types. |

---

## 9. What "production" deployment would look like

The MVP runs **from your local box** (or any box with the install above) against the deployed target. That satisfies the PRD hard gate "platform must be running live tests against a live system."

For continuous 24/7 operation as a deployed service — not required by MVP — the additional pieces are:

| Concern | MVP state | Production add |
|---|---|---|
| Compute host | Local laptop / dev box | Long-lived host (droplet, VPS, k8s job) |
| Process supervision | Manual `python -m ...` | systemd unit / Docker restart-policy |
| Secret management | `.env` file on disk | Vault / SSM / cloud KV store |
| Trigger source | Manual invocation | cron (time-based) + webhook (git-push regression) |
| Artifact storage | Local filesystem under `evals/results/` | S3 / blob store with retention policy |
| Failure alerting | stderr / exit code | Slack / PagerDuty hook on non-zero exit |
| Cost guardrails | Per-run `MAX_SESSION_COST_USD` | Cloud budget alarms + per-day rollups |
| Observability | Langfuse UI (if keys set) | Same + Grafana dashboards + per-run cost trends |

These are out of MVP scope and documented in `ARCHITECTURE.md` §8 (cost + scale) as Phase 2/3 work. The cost analysis at Final (`docs/cost-analysis.md`) makes the architectural-changes-per-scale call for 100 / 1K / 10K / 100K test runs.

---

## 10. References

- `README.md` — what this is + grader-facing artifact map
- `ARCHITECTURE.md` — multi-agent design + agent definitions + framework anchoring
- `THREAT_MODEL.md` — attack surface map + OWASP/ASI/ATLAS coverage
- `RESPONSIBLE_USE.md` — sentinel-only-patient hard rule + scope boundary
- `evals/` — seeds, criteria, run artifacts, vulnerability reports
- `.env.example` — every env var with inline comments
