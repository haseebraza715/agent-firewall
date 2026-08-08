#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"

cd "$here"
if [ ! -f node_modules/@modelcontextprotocol/server-puppeteer/dist/index.js ]; then
  PUPPETEER_SKIP_DOWNLOAD=true npm ci --ignore-scripts
fi

cd "$root"
PYTHONPATH=src python3 reproductions/mcp-puppeteer-3662/run.py
