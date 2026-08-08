#!/usr/bin/env bash
# Regenerate the frozen holdout benchmark reports for benchmarks/v1.
#
#   ./scripts/run-holdout-benchmark.sh
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$root/benchmarks/v1/holdout/run.sh"
