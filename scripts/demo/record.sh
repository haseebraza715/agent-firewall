#!/usr/bin/env bash
# record.sh — record the terminal demo and render mp4 + preview gif.
# Run from the repository root:
#
#   ./scripts/demo/record.sh
#
# Writes:
#   assets/demo/demo.cast   raw asciinema recording
#   assets/demo/demo.mp4    h264 render (what the README links)
#   assets/demo/demo.gif    first ~12s preview at lower frame rate
#
# Requires: asciinema and agg (cargo install --git
# https://github.com/asciinema/agg). ffmpeg is resolved from FFMPEG if set,
# else from imageio_ffmpeg inside MEDIA_VENV if set, else from PATH.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

for tool in asciinema agg; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "error: $tool is required to record the demo" >&2
    exit 1
  }
done

find_ffmpeg() {
  if [ -n "${FFMPEG:-}" ] && [ -x "${FFMPEG:-}" ]; then
    printf '%s\n' "$FFMPEG"
    return 0
  fi
  if [ -n "${MEDIA_VENV:-}" ] && [ -x "$MEDIA_VENV/bin/python" ]; then
    "$MEDIA_VENV/bin/python" -c \
      "import imageio_ffmpeg; print(imageio_ffmpeg.get_ffmpeg_exe())" 2>/dev/null &&
      return 0
  fi
  command -v ffmpeg 2>/dev/null
}

ffmpeg_bin="$(find_ffmpeg || true)"
if [ -z "$ffmpeg_bin" ]; then
  echo "error: ffmpeg not found; set FFMPEG or MEDIA_VENV (with imageio_ffmpeg)" >&2
  exit 1
fi

if [ ! -x .venv/bin/agent-firewall ]; then
  echo "error: .venv/bin/agent-firewall not found; install the package first" >&2
  exit 1
fi

mkdir -p assets/demo

IDLE_LIMIT="${IDLE_LIMIT:-4.0}"

TERM=xterm-256color asciinema rec --overwrite --quiet \
  --cols 100 --rows 30 \
  --title "Agent Firewall: allow, hold, block" \
  --command "bash scripts/demo/demo_body.sh" \
  assets/demo/demo.cast

echo "== rendering 30fps source (for mp4)"
agg --theme dracula --cols 100 --rows 30 --fps-cap 30 \
  --idle-time-limit "$IDLE_LIMIT" --speed 1.0 --last-frame-duration 1.5 \
  assets/demo/demo.cast /tmp/agent-firewall-raw30.gif

echo "== transcoding to mp4 (h264, yuv420p, faststart)"
"$ffmpeg_bin" -y -i /tmp/agent-firewall-raw30.gif \
  -vf "scale=trunc(iw/2)*2:trunc(ih/2)*2" \
  -c:v libx264 -preset slow -crf 20 -pix_fmt yuv420p -movflags +faststart -an \
  assets/demo/demo.mp4
rm -f /tmp/agent-firewall-raw30.gif

echo "== rendering preview gif (first 12s, 10fps)"
agg --theme dracula --cols 100 --rows 30 --fps-cap 10 \
  --idle-time-limit "$IDLE_LIMIT" --speed 1.5 --last-frame-duration 1.5 \
  --select ..12 assets/demo/demo.cast assets/demo/demo.gif

echo "== results"
"$ffmpeg_bin" -i assets/demo/demo.mp4 2>&1 | grep -E "Duration" || true
ls -la assets/demo/demo.mp4 assets/demo/demo.gif
