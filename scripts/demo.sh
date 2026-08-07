#!/usr/bin/env bash
#
# scripts/demo.sh -- one-command, fully offline demo of Agent Firewall.
#
#   ./scripts/demo.sh
#
# Three beats, one policy in examples/policy.json:
#   1. DECIDE -- machine-readable allow / require_approval / block decisions
#   2. REPLAY -- 11 real-world public incidents, all stopped by that policy
#   3. GUARD  -- the Python Firewall.wrap() API guarding a real function
#
# This is self-contained: it prefers the repository's own .venv and otherwise
# falls back to the system interpreter with src/ on PYTHONPATH. No network, no
# pip, no jq -- stdlib only. Anything it writes is cleaned up on exit.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# Prefer the project virtualenv; fall back to PYTHONPATH=src so the demo runs
# from a clean clone too.
if [ -x .venv/bin/agent-firewall ]; then
  fw=(.venv/bin/agent-firewall)
  py=.venv/bin/python
else
  fw=(python3 -m agent_firewall)
  py=python3
  export PYTHONPATH="$root/src${PYTHONPATH:+:$PYTHONPATH}"
fi

audit="$(mktemp "${TMPDIR:-/tmp}/agent-firewall-demo-audit.XXXXXX")"
state="$(mktemp "${TMPDIR:-/tmp}/agent-firewall-demo-state.XXXXXX")"
trap 'rm -f "$audit" "$state"' EXIT

policy="examples/policy.json"
scenarios="examples/complaints.json"

# ANSI styling only when stdout is a terminal; plain otherwise.
if [ -t 1 ]; then
  BOLD=$'\033[1m'
  CYAN=$'\033[36m'
  GREEN=$'\033[32m'
  YELLOW=$'\033[33m'
  DIM=$'\033[2m'
  RESET=$'\033[0m'
else
  BOLD=; CYAN=; GREEN=; YELLOW=; DIM=; RESET=
fi

banner() {
  printf '\n%s\n' "${BOLD}${CYAN}$1${RESET}"
  printf '%s\n' "$(printf '%*s' "${#1}" '' | tr ' ' '=')"
}

note() { printf '\n  %s\n' "${DIM}$1${RESET}"; }

meaning() {
  case "$1" in
    0) echo "allowed" ;;
    3) echo "held for human approval" ;;
    4) echo "blocked" ;;
    *) echo "invalid input" ;;
  esac
}

# Evaluate one tool call and print its JSON decision plus the exit code.
run_check() {
  local tool="$1"
  shift
  local out code
  set +e
  out=$("${fw[@]}" check --policy "$policy" --tool "$tool" "$@" 2>&1)
  code=$?
  set -e
  printf '\n  %s\n' "${BOLD}${tool}${RESET}"
  printf '    %s\n' "$out"
  printf '    %s\n' "${DIM}exit ${code} -> $(meaning "$code")${RESET}"
  sleep 1.2
}

banner "AGENT FIREWALL"
printf '%s\n' "${BOLD}Runtime guard for AI-agent tool calls, decided before they execute${RESET}"
printf '%s\n' "${DIM}policy: ${policy}   (no runtime dependencies, Python 3.9+)${RESET}"

# ---------------------------------------------------------------------------
banner "1. DECIDE -- every call gets an answer before it runs"
printf '%s\n' "${DIM}Three calls, one ordered policy, three different verdicts.${RESET}"

note "a read-only query the policy explicitly allows"
run_check "database.query" --arguments '{"sql":"SELECT * FROM accounts"}'

note "an outbound email to a customer (rule matched on the argument)"
run_check "email.send" --arguments '{"to":"customer@example.com"}'

note "a browser navigating to cloud-metadata (an SSRF payload)"
run_check "browser.navigate" \
  --arguments '{"url":"http://169.254.169.254/latest/meta-data/"}'

printf '\n%s\n' "${DIM}Same policy, different calls, different exits: 0 allow, 3 hold, 4 block.${RESET}"

# ---------------------------------------------------------------------------
banner "2. REPLAY -- eleven incidents, one policy"
printf '%s\n' "${DIM}These failures are not new: runaway loops, silent side effects, an SSRF --
all reported as public bugs against other projects. One policy below stops or
gates every one of the eleven scenarios, ten from real reports.${RESET}"

"${fw[@]}" replay \
  --policy "$policy" \
  --scenarios "$scenarios" \
  --format text

sleep 2

# ---------------------------------------------------------------------------
banner "3. GUARD -- the Python API wraps a real function"
printf '%s\n' "${DIM}The same policy is now a boundary around an actual callable. Denial is an
expected outcome, not a crash: Firewall.wrap() raises ToolCallBlocked, which
we catch. Every decision lands in an append-only audit file.${RESET}"

"$py" - "$audit" <<'PY'
import json
import sys
from pathlib import Path

from agent_firewall import Firewall
from agent_firewall.exceptions import ToolCallBlocked

audit_path = Path(sys.argv[1])


def approver(call, decision):
    print(f"    >> approver asked: {call.name} -- {decision.reason}")
    return False  # deny; the demo shows the guard, not a human


firewall = Firewall.from_policy_file(
    Path("examples/policy.json"),
    approver=approver,
    audit_path=audit_path,
)


def send_email(to, subject):
    print(f"    >> executed       : sent {subject!r} to {to}")


send = firewall.wrap("email.send", send_email)

for recipient in ("teammate@mycompany.com", "customer@example.com"):
    print()
    print(f"    agent wants to email {recipient}")
    try:
        send(recipient, "Agent Firewall test")
    except ToolCallBlocked as blocked:
        print(f"    >> NOT EXECUTED   {recipient} ({blocked.decision.reason})")

print()
print("    append-only audit (argument values hashed by policy design):")
for line in audit_path.open():
    record = json.loads(line)
    print(
        f"      {record['event']:<22} {record['tool']:<14} "
        f"decision={record['decision']:<18} usage={record['usage']['tool_calls']}"
    )
PY

sleep 2

# ---------------------------------------------------------------------------
banner "done"
printf '%s\n' "${GREEN}Every tool call is decided before it runs -- allow, hold-for-approval,
or block -- and the whole loop is auditable.${RESET}"
