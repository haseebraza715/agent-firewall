#!/usr/bin/env bash
# Regenerate the internal development benchmark reports for benchmarks/v1.
#
#   ./scripts/run-benchmark.sh
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$root/benchmarks/v1/run.sh"
