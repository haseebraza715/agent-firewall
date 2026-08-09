#!/usr/bin/env bash
# demo_body.sh — drives the recorded demo session (deterministic, offline).
# Run from the repository root. Set PATH to the project venv so commands look clean.
# NOTE: edit this file to change the demo; then run scripts/demo/record.sh to regenerate.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PATH="$root/.venv/bin:$PATH"
cd "$root"

PROMPT='\033[1;32m❯\033[0m '

header() { printf '\033[1;36m%s\033[0m\n' "$1"; sleep 0.9; }
run() {
  printf "${PROMPT}%s\n" "$1"
  sleep 0.9
  shift
  "$@"
  sleep 4.6
}
pause() { sleep "$1"; }

header "Agent Firewall: every tool call gets a decision before it runs"
pause 0.4

run "agent-firewall policy lint --policy examples/demo_policy.json" \
  agent-firewall policy lint --policy examples/demo_policy.json

header "One policy, three decisions: allow, require_approval, block"
pause 0.4

run "agent-firewall check --policy examples/demo_policy.json \\
  --tool database.query --arguments '{\"query\":\"SELECT * FROM users\"}' --format text" \
  agent-firewall check --policy examples/demo_policy.json \
  --tool database.query --arguments '{"query":"SELECT * FROM users"}' --format text

run "agent-firewall check --policy examples/demo_policy.json \\
  --tool email.send --arguments '{\"to\":\"customer@example.com\"}' --format text" \
  agent-firewall check --policy examples/demo_policy.json \
  --tool email.send --arguments '{"to":"customer@example.com"}' --format text

run "agent-firewall check --policy examples/demo_policy.json \\
  --tool browser.navigate --arguments '{\"url\":\"http://169.254.169.254/\"}' --format text" \
  agent-firewall check --policy examples/demo_policy.json \
  --tool browser.navigate --arguments '{"url":"http://169.254.169.254/"}' --format text

header "Every decision carries its policy reason. Fail closed: no rule, no run."
pause 1.0
