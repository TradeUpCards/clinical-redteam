#!/bin/bash
# scripts/overnight_targeted_attacks.sh
#
# Runs N targeted single-shot attacks against each of the audit-derived seeds
# from F8a (C-A), F8b (C-C), and F6 (multi-turn PI). Designed for overnight
# operation on the droplet — single-shot mode is more predictable than
# continuous-mode rotation when you want depth on specific high-value seeds.
#
# TRADEOFF vs continuous mode:
#   - Single-shot does NOT use F5 verdict-informed mutation (each invocation
#     is an independent mutation; the Orchestrator's prior-verdicts plumbing
#     only fires in continuous mode).
#   - Single-shot DOES auto-promote FAILs to evals/regression/ via F17.
#   - Single-shot is cheaper because the daemon's coverage logic doesn't
#     halt economically on "no open vulnerabilities."
#
# COST GUARDRAIL:
#   - Each invocation respects MAX_SESSION_COST_USD (per-run cap, default $5)
#   - Cumulative invocations respect MAX_DAILY_COST_USD (F19 daily cap,
#     default $50). If the rolling-24h sum exceeds the cap, daemon refuses
#     to start a new run and this script exits early.
#
# USAGE:
#   bash scripts/overnight_targeted_attacks.sh                    # 100 per seed (default)
#   ATTACKS_PER_SEED=300 bash scripts/overnight_targeted_attacks.sh
#   nohup bash scripts/overnight_targeted_attacks.sh > overnight.log 2>&1 &  # detached
#
# Output: each invocation writes a new run dir under evals/results/.
# Aggregate summary printed at the end (count of FAIL/PASS/UNCERTAIN per seed).

set -uo pipefail

# Per-seed count — override via env var.
ATTACKS_PER_SEED="${ATTACKS_PER_SEED:-100}"

REPO=/opt/redteam/repo
COMPOSE_FILE="$REPO/.deploy/docker-compose.redteam.yml"
ENV_FILE=/opt/redteam/.env

# Sanity check
if [[ ! -f "$COMPOSE_FILE" ]]; then
    echo "ERROR: compose file not found at $COMPOSE_FILE"
    exit 1
fi
if [[ ! -f "$ENV_FILE" ]]; then
    echo "ERROR: env file not found at $ENV_FILE"
    exit 1
fi

DCRT="docker compose -f $COMPOSE_FILE --env-file $ENV_FILE"

# Seeds to hammer, in priority order.
# Format: "<seed_id>|<category>"
SEEDS=(
    "pi-indirect-extraction-block-injection|prompt_injection"
    "sid-scrubber-format-bypass|sensitive_information_disclosure"
    "pi-multi-turn-context-poison|prompt_injection"
)

run_one_seed() {
    local seed="$1"
    local category="$2"
    local count="$3"
    echo ""
    echo "========================================================"
    echo "Seed: $seed"
    echo "Category: $category"
    echo "Iterations: $count"
    echo "Started: $(date -Iseconds)"
    echo "========================================================"

    local fails=0 partials=0 passes=0 uncertains=0 errors=0
    for i in $(seq 1 "$count"); do
        # Each invocation = ephemeral container, fresh run-id, F17 auto-promote
        # on FAIL/PARTIAL via Doc Agent.
        local out
        if ! out=$($DCRT run --rm redteam-daemon \
            python -m clinical_redteam.run \
            --category "$category" --seed "$seed" 2>&1); then
            errors=$((errors+1))
            # Daily budget gate fires exit 8 — stop the whole script
            if echo "$out" | grep -q "MAX_DAILY_COST_USD"; then
                echo ""
                echo "✗ DAILY BUDGET CAP REACHED — halting overnight script"
                echo "$out" | tail -5
                return 8
            fi
            # Otherwise log and continue (transient failure)
            echo "  [$i/$count] error: $(echo "$out" | tail -1)"
            continue
        fi
        # Parse verdict from the summary JSON output (one of: pass/fail/partial/uncertain)
        local verdict
        verdict=$(echo "$out" | grep -oE '"verdict": *"[a-z]*"' | tail -1 | grep -oE '[a-z]+$' || echo "?")
        case "$verdict" in
            fail) fails=$((fails+1)) ;;
            partial) partials=$((partials+1)) ;;
            pass) passes=$((passes+1)) ;;
            uncertain) uncertains=$((uncertains+1)) ;;
        esac
        # Print compact progress line
        if (( i % 10 == 0 )) || (( i == count )); then
            echo "  [$i/$count] running totals: ${fails}F / ${partials}P / ${passes}p / ${uncertains}U / ${errors}E"
        fi
    done

    echo "Completed: $(date -Iseconds)"
    echo "Final: FAIL=$fails  PARTIAL=$partials  PASS=$passes  UNCERTAIN=$uncertains  ERROR=$errors"
}

echo "OVERNIGHT TARGETED ATTACKS"
echo "Started at: $(date -Iseconds)"
echo "Attacks per seed: $ATTACKS_PER_SEED"
echo "Seeds: ${#SEEDS[@]}"
echo ""

for entry in "${SEEDS[@]}"; do
    seed="${entry%|*}"
    category="${entry#*|}"
    if ! run_one_seed "$seed" "$category" "$ATTACKS_PER_SEED"; then
        # Daily budget cap or other halt — exit overall
        exit 0
    fi
done

echo ""
echo "========================================================"
echo "OVERNIGHT RUN COMPLETE"
echo "========================================================"
echo "Finished at: $(date -Iseconds)"
echo ""
echo "Inspect results:"
echo "  ls /opt/redteam/evals/results/ | tail -30"
echo "  ls /opt/redteam/evals/regression/  # any auto-promoted FAILs land here"
echo "  ls /opt/redteam/evals/vulnerabilities/  # any auto-drafted vuln reports"
