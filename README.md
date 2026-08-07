# Agent Firewall

[![CI](https://github.com/haseebraza715/agent-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/haseebraza715/agent-firewall/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)

**The guard that decides allow, hold, or block for every agent tool call before it runs.**

![Agent Firewall demo](docs/demo.gif)

## Try it in 60 seconds

```bash
git clone https://github.com/haseebraza715/agent-firewall.git
cd agent-firewall
python3 -m venv .venv && source .venv/bin/activate && pip install .
./scripts/demo.sh
```

What you'll see:

- Three tool calls get three JSON verdicts — `allow`, `require_approval`, `block` — with the matching rule and exit code.
- Eleven incidents replayed against one small policy — ten from real public bug reports (LangGraph, LangChain, Cline, VS Code, Hermes, MCP servers) — every one stopped or gated.
- A guarded `send_email` executes for the safe recipient and raises `ToolCallBlocked` for the external one, with every decision in an append-only audit log.

The demo is fully offline and self-contained: no network, no pip, no runtime dependencies.

## What it does

- **Ordered policy rules** — `allow` / `require_approval` / `block`, matched by tool name and arguments; first match wins, default is block.
- **Budgets and caps** — per-run call and estimated-cost limits, plus per-tool and identical-call repetition caps that catch runaway loops.
- **Sync and async wrappers** — `Firewall.wrap()` and `await firewall.acall(...)` guard any callable; positional arguments are bound to parameter names before the policy is evaluated.
- **Human approval** — your own callback, or terminal and browser prompts.
- **MCP stdio proxy** — sits in front of any local MCP server; blocked calls get a JSON-RPC policy error.
- **SQLite state** — persistent call, cost, and repetition counts across restarts.
- **Loopback dashboard** — approve or deny pending calls in the browser on a localhost URL.
- **Audit log** — argument-free JSONL records of every decision; fail-closed writes.

## How it works

Each proposed call is matched against the ordered policy — rules can match the tool name, the bound arguments, or both. The first match (or the default) produces the decision, budget capacity is reserved before anything can run, and the outcome is written to the audit log. Denial is fail-closed: no rule, no budget, no execution.

## Quick facts

| | |
|---|---|
| Language | Python 3.9+ |
| Runtime dependencies | zero (stdlib only) |
| Offline | yes — everything runs locally |
| Interfaces | CLI, Python API, MCP stdio proxy, browser dashboard |
| License | MIT |

## Quick start

Install and evaluate a tool call without executing it:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .

agent-firewall check \
  --policy examples/policy.json \
  --tool email.send \
  --arguments '{"to":"customer@example.com"}'
```

The output is machine-readable:

```json
{"code": "rule_match", "decision": "require_approval", "reason": "outbound email requires a human decision", "rule_index": 2}
```

Exit codes are `0` for allow, `3` for approval required, `4` for block, and `2` for invalid input. Pass `--format text` to `check` or `replay` for a human-readable version; JSON stays the default.

## Guard a real tool

```python
from pathlib import Path

from agent_firewall import Firewall


def ask_human(call, decision):
    return input(f"Approve {call.name}? [y/N] ").lower() == "y"


firewall = Firewall.from_policy_file(
    Path("examples/policy.json"),
    approver=ask_human,
    audit_path=Path("firewall-audit.jsonl"),
)


def send_email(to, subject):
    return {"sent": True, "to": to, "subject": subject}


safe_send_email = firewall.wrap("email.send", send_email)
safe_send_email("customer@example.com", "Your receipt")
```

A denied call raises `ToolCallBlocked`, which carries the call and decision — denial is an expected outcome, not a crash. See [`examples/wrap_tool.py`](examples/wrap_tool.py) for the full example.

## Guard a local MCP server

Put the firewall in front of any stdio server — no agent changes:

```bash
agent-firewall mcp \
  --policy examples/policy.json \
  --audit firewall-audit.jsonl \
  --approve-terminal \
  -- python path/to/your_mcp_server.py
```

Use the same command in the MCP client configuration:

```json
{
  "command": "agent-firewall",
  "args": [
    "mcp",
    "--policy", "/absolute/path/policy.json",
    "--audit", "/absolute/path/firewall-audit.jsonl",
    "--approve-terminal",
    "--",
    "python", "/absolute/path/server.py"
  ]
}
```

The proxy forwards newline-delimited JSON-RPC unchanged except `tools/call`, which is always policed: missing, null, or non-object arguments are rejected or evaluated without arguments, never passed through, and JSON-RPC batch frames are rejected instead of forwarded. Blocked calls receive a JSON-RPC policy error; approval rules prompt on the proxy's terminal and fail closed otherwise.

For persistent budgets and browser approval, start the dashboard and point the proxy at the same state:

```bash
agent-firewall dashboard --policy examples/policy.json --audit firewall-audit.jsonl --state firewall.db
agent-firewall mcp --policy examples/policy.json --audit firewall-audit.jsonl --state firewall.db --approve-web -- python path/to/your_mcp_server.py
```

## Policy format

Policies are JSON and fail closed by default:

```json
{
  "default_decision": "block",
  "audit_arguments": "hash",
  "budget": {
    "max_calls": 10,
    "max_calls_per_tool": 3,
    "max_identical_calls": 2,
    "max_cost_usd": "0.50"
  },
  "rules": [
    {"tool": "database.query", "decision": "allow", "reason": "read-only query"},
    {"tool": "email.*", "arguments": {"to": "*@mycompany.com"}, "decision": "allow", "reason": "company recipient"},
    {"tool": "email.*", "decision": "require_approval", "reason": "external side effect"}
  ]
}
```

Rules run in order; the first match wins. Tool names and string arguments use shell globs; non-string values match exactly; a missing argument never matches. Unknown keys at any level are rejected at load time, so a typo cannot silently widen enforcement. Cost enforcement uses the caller-supplied estimate — token-cost calculation is outside this MVP. Argument auditing defaults to `none`; use `hash`, `redacted`, or `full` depending on how much you trust the audit destination.

## Replay real incidents

The corpus models eleven failure scenarios — ten from public bug reports on other projects (LangGraph, LangChain, Cline, VS Code, Hermes, and the MCP servers) plus one synthetic spend-cap check — and one small policy stops or gates all eleven. The [Agent Incident Wall](docs/incidents/README.md) maps every report to the smallest deterministic rule that would have caught it, and `./scripts/check-sources.sh` re-verifies every citation still resolves.

```bash
agent-firewall replay --policy examples/policy.json --scenarios examples/complaints.json
```

## Test

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

## MVP boundaries

No semantic prompt-injection detection, no multi-host distributed budgets — both need a threat model and real usage data before they can be implemented honestly.

## Security posture

Agent Firewall is an enforcement point, not a sandbox. Tool implementations still need least-privilege credentials and operating-system isolation. Audit logs omit tool arguments by design because they commonly contain secrets or personal data.

MIT licensed.
