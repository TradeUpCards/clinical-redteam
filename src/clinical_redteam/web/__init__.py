"""Web layer for the Clinical Red Team Platform.

Read-only status surface for the deployed attacker. Reads run artifacts
from `evals/results/` and vulnerability reports from `evals/vulnerabilities/`
and exposes them via a tiny HTTP API + HTML index page.

This module is the second URL grader requirement (PRD-adjacent, cohort
guidance): the attacker platform must be deployed at a separate public
URL alongside the target. See `.deploy/` for the Docker compose +
Caddyfile fragment that hosts this on `redteam-142-93-242-40.nip.io`.

NOT included:
- Mutation. Read-only by design — this is the operator's window, not a
  control plane.
- Authentication. The deployed surface is public; we expose only
  already-published artifacts (run metadata, vulnerability reports).
- The agent code itself runs in a sibling `redteam-daemon` container.
  This service only READS what the daemon produces.
"""
