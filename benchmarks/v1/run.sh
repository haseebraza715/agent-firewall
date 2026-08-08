#!/usr/bin/env bash
# Regenerate the benchmarks/v1 development benchmark reports.
#
#   ./benchmarks/v1/run.sh
#
# Runs the policy against the labeled cases and rewrites reports/report.json
# and reports/report.md. Output is deterministic: no timestamps, fixed float
# precision, and the policy/cases SHA-256 hashes are part of the report.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root/benchmarks/v1"

if [ -x "$root/.venv/bin/agent-firewall" ]; then
  fw=("$root/.venv/bin/agent-firewall")
else
  fw=(python3 -m agent_firewall)
  export PYTHONPATH="$root/src${PYTHONPATH:+:$PYTHONPATH}"
fi

mkdir -p reports
"${fw[@]}" benchmark \
  --policy policy.json \
  --cases cases.json \
  --output reports
