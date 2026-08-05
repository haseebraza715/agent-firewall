#!/usr/bin/env bash
# Verify every upstream report cited by examples/complaints.json still resolves.
#
#   ./scripts/check-sources.sh
#
# This needs network access, so it is deliberately not part of the test suite.
# Run it before publishing anything that shows the replay output: a citation
# that 404s misrepresents another project's issue tracker.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

urls=$(python3 -c '
import json

for scenario in json.load(open("examples/complaints.json")):
    print(scenario["id"], scenario.get("source_url") or "-", sep="\t")
')

failed=0
while IFS=$'\t' read -r id url; do
  if [ "$url" = "-" ]; then
    printf "  SKIP  %-34s no upstream report\n" "$id"
    continue
  fi
  code=$(curl -sL -o /dev/null -w "%{http_code}" --max-time 20 "$url")
  if [ "$code" = "200" ]; then
    printf "  OK    %-34s %s\n" "$id" "$url"
  else
    printf "  FAIL  %-34s HTTP %s  %s\n" "$id" "$code" "$url"
    failed=$((failed + 1))
  fi
done <<<"$urls"

if [ "$failed" -gt 0 ]; then
  echo "$failed cited source(s) did not resolve" >&2
  exit 1
fi
echo "all cited sources resolve"
