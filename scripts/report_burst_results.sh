#!/bin/bash
# scripts/report_burst_results.sh
#
# Summarize the most recent depth/validation burst against the deployed
# Co-Pilot target. Produces a human-readable report that fits on ~one
# screen and is paste-friendly for a remote collaborator.
#
# Aggregates across all run-dirs in evals/results/ whose verdict files
# were written in the last MINUTES_BACK minutes (default 60).
#
# USAGE:
#   sudo bash scripts/report_burst_results.sh             # last 60 min
#   sudo MINUTES_BACK=120 bash scripts/report_burst_results.sh
#
# WHAT IT SHOWS:
#   1. Verdict distribution (pass/fail/partial/uncertain count)
#   2. Spend in last 24h vs F19 daily cap
#   3. All FAIL/PARTIAL findings — attack_id, target status, criteria, evidence
#   4. Random sample of 3 PASSes — confirms target actually returned 200s
#      with real extractions (not 400-confabulated PASSes)
#   5. Doc Agent auto-drafted VULN-NNN.md files (canonical evals/vulnerabilities/)
#   6. F17 auto-promoted regression entries (evals/regression/<cat>/*.json)
#
# Safe to run while a burst is in flight — read-only, won't interfere.

set -uo pipefail

MINUTES_BACK="${MINUTES_BACK:-60}"
RESULTS_DIR=/opt/redteam/evals/results
VULNS_DIR=/opt/redteam/evals/vulnerabilities
REGRESSION_DIR=/opt/redteam/evals/regression

# Sanity
if [[ ! -d "$RESULTS_DIR" ]]; then
    echo "ERROR: $RESULTS_DIR not found. Are you on the droplet?"
    exit 1
fi

echo "========================================================"
echo "BURST RESULTS — $(date -Iseconds)"
echo "Window: last ${MINUTES_BACK} minutes"
echo "========================================================"
echo ""

# ----- Run dirs in window -----
RUN_COUNT=$(find "$RESULTS_DIR" -mindepth 1 -maxdepth 1 -type d -mmin "-${MINUTES_BACK}" | wc -l)
echo "Run dirs in window: $RUN_COUNT"

# Verdict files in window
VERDICT_FILES=$(find "$RESULTS_DIR" -name "*.json" -path "*/verdicts/*" -mmin "-${MINUTES_BACK}" 2>/dev/null)

# ----- Verdict distribution -----
echo ""
echo "--- Verdict distribution -----"
if [[ -z "$VERDICT_FILES" ]]; then
    echo "  (no verdict files found in window)"
else
    echo "$VERDICT_FILES" | xargs -I {} jq -r '.verdict' {} 2>/dev/null | sort | uniq -c | awk '{printf "  %s %s\n", $1, $2}'
fi

# ----- Spend in 24h -----
echo ""
echo "--- Cost (F19 rolling-24h gate) -----"
SPEND_24H=$(find "$RESULTS_DIR" -name cost-ledger.json -mtime -1 \
    -exec jq -r '.total_usd' {} \; 2>/dev/null | \
    awk '{sum+=$1} END {printf "%.2f", sum}')
echo "  \$${SPEND_24H} spent in last 24h (cap \$50.00)"

# ----- FAILs / PARTIALs (full evidence) -----
echo ""
echo "--- FAIL / PARTIAL findings (full evidence) -----"
FAILS_FOUND=0
while IFS= read -r vf; do
    [[ -z "$vf" ]] && continue
    VERDICT=$(jq -r '.verdict' "$vf" 2>/dev/null)
    if [[ "$VERDICT" == "fail" || "$VERDICT" == "partial" ]]; then
        FAILS_FOUND=$((FAILS_FOUND+1))
        RUN_DIR=$(dirname "$(dirname "$vf")")
        RUN_ID=$(basename "$RUN_DIR")
        ATTACK_ID=$(jq -r '.attack_id' "$vf")
        CONF=$(jq -r '.confidence' "$vf")
        CRITERIA=$(jq -r '.criteria_triggered | join(", ")' "$vf")
        HASH=$(jq -r '.target_response_hash' "$vf")
        echo ""
        echo "  [$RUN_ID] $ATTACK_ID — verdict=$VERDICT conf=$CONF"
        echo "    criteria: $CRITERIA"
        echo "    hash: $HASH"
        # Pull the response side-by-side so we can see if hash is empty-{} or real
        RESP_FILE="${RUN_DIR}/responses/${ATTACK_ID}.json"
        if [[ -f "$RESP_FILE" ]]; then
            STATUS=$(jq -r '.status_code' "$RESP_FILE")
            EXT_PREVIEW=$(jq -c '.extraction // .raw_body // "<no body>"' "$RESP_FILE" 2>/dev/null | cut -c1-200)
            echo "    target HTTP $STATUS"
            echo "    response: $EXT_PREVIEW"
        else
            echo "    (no response file — pre-F23 run)"
        fi
        # First evidence item
        FIRST_EV=$(jq -r '.evidence[0] | "    evidence: " + .criterion + " ← " + (.matched_text | tostring | .[0:200])' "$vf" 2>/dev/null)
        [[ -n "$FIRST_EV" && "$FIRST_EV" != *"null"* ]] && echo "$FIRST_EV"
    fi
done <<< "$VERDICT_FILES"
[[ "$FAILS_FOUND" -eq 0 ]] && echo "  (no fail/partial verdicts in window)"

# ----- Sample 3 PASSes (sanity check) -----
echo ""
echo "--- Random sample of 3 PASS verdicts (sanity check) -----"
PASS_SAMPLE=$(echo "$VERDICT_FILES" | xargs -I {} sh -c 'V=$(jq -r .verdict "{}" 2>/dev/null); [ "$V" = "pass" ] && echo "{}"' 2>/dev/null | shuf -n 3)
if [[ -z "$PASS_SAMPLE" ]]; then
    echo "  (no PASS verdicts in window)"
else
    while IFS= read -r vf; do
        [[ -z "$vf" ]] && continue
        RUN_DIR=$(dirname "$(dirname "$vf")")
        RUN_ID=$(basename "$RUN_DIR")
        ATTACK_ID=$(jq -r '.attack_id' "$vf")
        RESP_FILE="${RUN_DIR}/responses/${ATTACK_ID}.json"
        echo ""
        echo "  [$RUN_ID] $ATTACK_ID — PASS"
        if [[ -f "$RESP_FILE" ]]; then
            STATUS=$(jq -r '.status_code' "$RESP_FILE")
            MEDS=$(jq -c '.extraction.current_medications // "<no extraction>"' "$RESP_FILE" 2>/dev/null | cut -c1-300)
            echo "    target HTTP $STATUS"
            echo "    extraction.current_medications: $MEDS"
        else
            echo "    (no response file)"
        fi
    done <<< "$PASS_SAMPLE"
fi

# ----- Doc Agent auto-drafts -----
echo ""
echo "--- Doc Agent auto-drafted VULN reports -----"
if [[ -d "$VULNS_DIR" ]]; then
    VULN_FILES=$(find "$VULNS_DIR" -maxdepth 1 -name "VULN-*.md" -mmin "-${MINUTES_BACK}" 2>/dev/null)
    if [[ -z "$VULN_FILES" ]]; then
        echo "  (no new VULN drafts in window)"
        echo "  Existing VULN files:"
        ls -lt "$VULNS_DIR" 2>/dev/null | head -5 | awk 'NR>1 {printf "    %s %s\n", $6"-"$7"-"$8, $9}'
    else
        echo "$VULN_FILES" | xargs ls -lt 2>/dev/null | awk '{printf "  %s %s (size=%s)\n", $6"-"$7"-"$8, $9, $5}'
    fi
else
    echo "  ($VULNS_DIR not found)"
fi

# ----- F17 auto-promoted regression entries -----
echo ""
echo "--- F17 auto-promoted regression entries -----"
if [[ -d "$REGRESSION_DIR" ]]; then
    REGR_FILES=$(find "$REGRESSION_DIR" -name "*.json" -mmin "-${MINUTES_BACK}" 2>/dev/null)
    if [[ -z "$REGR_FILES" ]]; then
        echo "  (no new regression entries in window)"
    else
        echo "$REGR_FILES" | xargs ls -lt 2>/dev/null | awk '{printf "  %s %s\n", $6"-"$7"-"$8, $9}'
    fi
else
    echo "  ($REGRESSION_DIR not found)"
fi

echo ""
echo "========================================================"
echo "END REPORT"
echo "========================================================"
