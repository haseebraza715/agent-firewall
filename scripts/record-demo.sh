#!/usr/bin/env bash
# Record the terminal demo to docs/demo.cast and render docs/demo.gif.
# Run from the repository root:
#
#   ./scripts/record-demo.sh          # cast + gif
#   ./scripts/record-demo.sh --svg    # also render a vector docs/demo.svg
#
# Requires: asciinema and agg (cargo install --git
# https://github.com/asciinema/agg). --svg additionally needs npx.
#
# agg rasterises the text, so the GIF renders identically everywhere. The SVG
# is smaller only for short recordings; for this one it is roughly twice the
# size and still depends on the viewer's fonts, so the GIF is what the README
# embeds and the SVG is opt-in.
set -euo pipefail

want_svg=0
for arg in "$@"; do
  case "$arg" in
    --svg) want_svg=1 ;;
    *) echo "usage: $0 [--svg]" >&2; exit 2 ;;
  esac
done

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

if [ ! -x .venv/bin/agent-firewall ]; then
  echo "error: .venv/bin/agent-firewall not found; install the package first" >&2
  exit 1
fi

for tool in asciinema agg; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "error: $tool is required to record the demo" >&2
    exit 1
  }
done

mkdir -p docs

# The demo script contains its own short pauses, cleans up its temporary files,
# and needs no simulated typing. Recording it directly keeps this path reliable.
COLS=120
ROWS=44

TERM=xterm-256color asciinema rec docs/demo.cast \
  --overwrite \
  --quiet \
  --cols "$COLS" \
  --rows "$ROWS" \
  --title "Agent Firewall: allow, hold, block" \
  --idle-time-limit 0.4 \
  --command ./scripts/demo.sh

agg docs/demo.cast docs/demo.gif \
  --theme github-dark \
  --font-size 16 \
  --fps-cap 20 \
  --font-hinting true

rendered="docs/demo.cast and docs/demo.gif"

if [ "$want_svg" = 1 ]; then
  # svg-term-cli requires lru-cache at runtime but does not depend on it, so
  # pull both packages into the same temporary npx install.
  npx --yes --package svg-term-cli --package lru-cache@6 -- svg-term \
    --in docs/demo.cast \
    --out docs/demo.svg \
    --window --width "$COLS" --height "$ROWS"
  # svg-term trusts the viewer's font to space every column; pin the geometry
  # so the recording survives a renderer that has none of its macOS fonts.
  python3 scripts/polish-demo-svg.py docs/demo.svg
  rendered="$rendered and docs/demo.svg"
fi

echo "wrote $rendered"
