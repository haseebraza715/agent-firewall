#!/usr/bin/env bash
# Regenerate the benchmarks/v1 holdout benchmark reports.
#
#   ./benchmarks/v1/holdout/run.sh
#
# Verifies the policy and holdout cases against benchmarks/v1/freeze.json first.
# The policy is frozen: if its SHA-256 has moved since the freeze, this script
# refuses to write reports so the holdout can never tune the policy. Output is
# deterministic, same as the development benchmark.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$root/benchmarks/v1"

if [ -x "$root/.venv/bin/agent-firewall" ]; then
  fw=("$root/.venv/bin/agent-firewall")
else
  fw=(python3 -m agent_firewall)
  export PYTHONPATH="$root/src${PYTHONPATH:+:$PYTHONPATH}"
fi

mkdir -p holdout/reports
"${fw[@]}" benchmark \
  --policy policy.json \
  --cases holdout/cases.json \
  --freeze freeze.json \
  --output holdout/reports
