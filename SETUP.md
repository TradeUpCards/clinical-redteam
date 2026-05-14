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
git clone https://labs.gauntletai.com/coryvandenberg/clinical-redteam.git
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
| `MAX_SESSION_COST_USD` | `10` | You want stricter cost cap per individual run |
| `MAX_DAILY_COST_USD` | `50` | You want stricter rolling-24h aggregate cap across all runs (F19; daemon refuses to start a new run with exit code 8 when exceeded). Pairs with `restart: on-failure:3` in deployment so the daemon doesn't restart-loop into the cap. Measures OpenRouter-side spend only — Anthropic-direct calls (if any) are opaque to this gate. |
| `RED_TEAM_MODEL` / `RED_TEAM_FALLBACK_MODELS` | `deepseek/deepseek-chat` / `meta-llama/llama-3.1-70b-instruct,anthropic/claude-haiku-4.5` | Testing a different Red Team primary + fallback chain |
| `JUDGE_MODEL` / `JUDGE_FALLBACK_MODEL` | `anthropic/claude-sonnet-4-5` / `anthropic/claude-haiku-4.5` | Testing a different Judge primary + single fallback |
| `DOCUMENTATION_MODEL` / `DOCUMENTATION_FALLBACK_MODEL` | `anthropic/claude-haiku-4.5` / `anthropic/claude-sonnet-4-5` | Testing a different Doc Agent primary + single fallback |
| `LANGFUSE_PUBLIC_KEY` + `LANGFUSE_SECRET_KEY` + `LANGFUSE_HOST` | unset (no-op) | You want inter-agent traces in Langfuse UI |
| `HMAC_MAX_AGE_SECONDS` | `30` | Target's tolerance is wider |
| `LOG_LEVEL` | `INFO` | Debugging — set to `DEBUG` |
| `EVALS_DIR` | `./evals` | Pointing at a different eval-suite checkout |
| `RESULTS_DIR` | `./evals/results` | Writing run artifacts elsewhere |
| `ORCHESTRATOR_SIGNAL_FLOOR` | `0.0` (disabled) | You want the daemon to halt when signal-to-cost ratio drops below this threshold. Defaults disabled because calibrating the threshold needs real FAIL-verdict data; once you have it, a value like `0.2` halts runs that are burning cost without producing new signal. |

**Two-layer cost guard (F19 + per-session).** The daemon enforces two cost-cap layers in series:

1. **Per-session** — `MAX_SESSION_COST_USD` halts the currently-running daemon process once accumulated spend crosses the cap. Resets on every new run.
2. **Rolling-24h aggregate** — `MAX_DAILY_COST_USD` is checked *before* a new run starts. The daemon walks `evals/results/*/cost-ledger.json`, sums `total_usd` for runs whose `started_at` is within the last 24 hours, and refuses to start if the sum equals or exceeds the cap. This is the layer that makes unsupervised overnight operation safe — a crashing-and-restarting daemon under Docker's `restart: on-failure:3` policy can't burn through dozens of dollars before the next operator check, because the gate trips on restart.

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
| HTTP 404 from OpenRouter | A model was delisted | Check `RED_TEAM_MODEL` / `RED_TEAM_FALLBACK_MODELS` / `JUDGE_MODEL` / `JUDGE_FALLBACK_MODEL` / `DOCUMENTATION_MODEL` / `DOCUMENTATION_FALLBACK_MODEL` against current https://openrouter.ai/models. Per-tier fallback (429/5xx/connect/404) auto-degrades to the fallback chain; if both primary AND fallback fail across a tier there's a config issue. |
| Connection refused on `localhost:8000` | SSH tunnel dropped | Restart the tunnel (§4 Path B). Use `-o ServerAliveInterval=30` to keep it alive. |
| Cost cap fires too early | `MAX_SESSION_COST_USD` too low or you're running expensive models | Either raise the cap or switch tier models to cheaper alternatives. Inspect `cost-ledger.json` to see where the spend went. |
| Daemon won't start, error mentions `MAX_DAILY_COST_USD` (exit code 8) | Rolling-24h aggregate spend across recent runs has hit the F19 daily cap | Either wait for the rolling-24h window to age out (the gate checks runs started in the last 24h; older runs roll off automatically), or raise `MAX_DAILY_COST_USD` in `/opt/redteam/.env` (or local `.env`) and restart. Inspect `evals/results/*/cost-ledger.json` to confirm the aggregate. |
| Tests fail after `pip install -e ".[dev]"` | Wrong Python version | Check `python --version`. Must be 3.12+ for Pydantic v2 + match types. |

---

## 9. Deploying to the droplet (production-style, co-located with the target)

The MVP attacker is deployed at `https://redteam-142-93-242-40.nip.io` alongside the target Co-Pilot on the same DigitalOcean droplet. Two Docker compose stacks sharing one network: W2's `/opt/agentforge/` (target) + this repo's `/opt/redteam/` (attacker).

### Architecture

```
                       Caddy (W2's stack — ports 80/443, TLS)
                       │
       ┌───────────────┼───────────────┐
       │                               │
  142-93-242-40.nip.io           redteam-142-93-242-40.nip.io
       │                               │
  openemr:443                    redteam-status:8080
                                       │
                                       │ reads evals/ artifacts
                                       │
                                 redteam-daemon ──→ agent:8000 (W2 internal)
                                 (continuous loop)
```

The attacker's `redteam-daemon` reaches the target's `agent:8000` directly over the shared Docker network — no SSH tunnel needed in production. The attacker's status app (read-only HTTP) is fronted by Caddy with auto-TLS via nip.io + Let's Encrypt.

### One-time droplet setup

```bash
# On the droplet, as root (DigitalOcean's Docker image works out of the box).
# Assumes W2 AgentForge is already deployed at /opt/agentforge/ — that's the
# prerequisite. If W2 isn't deployed yet, see companion repo's .deploy/README.md.

mkdir -p /opt/redteam
cd /opt/redteam
git clone https://labs.gauntletai.com/coryvandenberg/clinical-redteam.git repo
cd repo
sudo bash .deploy/bootstrap.sh
```

The bootstrap is **idempotent** — safe to re-run. On first run it:

1. Generates `/opt/redteam/.env` with the W2 HMAC secret already wired (pulled from `/opt/agentforge/.env`) — only `OPENROUTER_API_KEY` needs manual entry
2. Writes `/opt/redteam/repo/.deploy/docker-compose.redteam.yml` from the template at `.deploy/docker-compose.redteam.yml`
3. Patches `/opt/agentforge/Caddyfile` to add the `redteam-142-93-242-40.nip.io` server block (managed-block markers keep the patch idempotent)
4. Reloads Caddy in the W2 stack so the new TLS cert provisions on first request
5. Builds the attacker image (~2-3 min on first build)
6. Brings up `redteam-daemon` + `redteam-status` services
7. Verifies the status URL responds via curl through Caddy

### After first run — set the OpenRouter key

```bash
sudo nano /opt/redteam/.env
# Set OPENROUTER_API_KEY=sk-or-v1-...
sudo bash /opt/redteam/repo/.deploy/bootstrap.sh   # re-run is safe
```

The daemon starts attacking the moment the key is set. Monitor cost via the status URL (`https://redteam-142-93-242-40.nip.io`) or:

```bash
docker compose -f /opt/redteam/repo/.deploy/docker-compose.redteam.yml logs -f redteam-daemon
```

### Operational commands

| Action | Command |
|---|---|
| Daemon logs | `docker compose -f /opt/redteam/repo/.deploy/docker-compose.redteam.yml logs -f redteam-daemon` |
| Status logs | `docker compose -f /opt/redteam/repo/.deploy/docker-compose.redteam.yml logs -f redteam-status` |
| Stop daemon (status stays up) | `docker compose -f /opt/redteam/repo/.deploy/docker-compose.redteam.yml stop redteam-daemon` |
| Resume daemon | `docker compose -f /opt/redteam/repo/.deploy/docker-compose.redteam.yml start redteam-daemon` |
| Update from main | `cd /opt/redteam/repo && git pull && sudo bash .deploy/bootstrap.sh` |
| Smoke status URL | `curl -fsS https://redteam-142-93-242-40.nip.io/health` |

### What deployment adds beyond local

| Concern | Local-only state | Droplet-deployed state |
|---|---|---|
| Public URL | None — local-only | `https://redteam-142-93-242-40.nip.io` |
| Process supervision | Manual `python -m ...` | Docker `restart: on-failure:3` (compose) — auto-recovers from genuine crashes; respects intentional halts (cost cap, target circuit open, etc.) without burning OpenRouter on retry loops |
| Tunnel to target | Required (SSH `-L 8000`) | Not needed — Docker DNS (`agent:8000`) |
| Secret management | `.env` in repo dir | `.env` in `/opt/redteam/` (mode 600, outside repo) |
| Artifact persistence | Local filesystem | Bind-mounted `/opt/redteam/evals/` survives container restarts |
| Cost cap | Per-invocation `--max-budget` | **Two layers**: per-session `MAX_SESSION_COST_USD` (default $10) in `.env` halts the running daemon; rolling-24h aggregate `MAX_DAILY_COST_USD` (default $50, F19) refuses to start a new run when crossed. Paired with `restart: on-failure:3` for safe unsupervised overnight operation. |
| TLS | None | Caddy auto-TLS via Let's Encrypt |

### What deployment does NOT add (out of MVP scope)

| Phase 3 concern | Why not at MVP |
|---|---|
| Process supervision beyond `restart: on-failure:3` | systemd / k8s deferred — Docker restart-policy is good enough at this scale |
| Secret management beyond `.env` | Vault / SSM is for multi-host or compliance-bound deployments |
| Long-term artifact storage (S3) | Filesystem fine for 100s of runs; cost analysis at Final makes the call for 10K+ |
| Failure alerting | Status URL is the surface for now; Slack/PagerDuty integration is Phase 3 |
| Per-day cost rollups | `cost-ledger.json` per-run is enough at this scale |
| Grafana dashboards | Cleo P5 static-HTML dashboard covers the trend-analytics gap for Final |

ARCH §8 (cost + scale) and the cost analysis at Final (`docs/cost-analysis.md`) document the architectural-changes-per-scale call for 100 / 1K / 10K / 100K test runs.

---

## 10. References

- `README.md` — what this is + grader-facing artifact map
- `ARCHITECTURE.md` — multi-agent design + agent definitions + framework anchoring
- `THREAT_MODEL.md` — attack surface map + OWASP/ASI/ATLAS coverage
- `RESPONSIBLE_USE.md` — sentinel-only-patient hard rule + scope boundary
- `evals/` — seeds, criteria, run artifacts, vulnerability reports
- `.env.example` — every env var with inline comments
