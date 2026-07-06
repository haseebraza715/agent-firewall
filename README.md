# Agent Firewall

[![CI](https://github.com/haseebraza715/agent-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/haseebraza715/agent-firewall/actions/workflows/ci.yml)

![Agent Firewall blocking and approval-gating MCP calls](docs/media/agent-firewall-demo.gif)

## Why

**[11 real, sourced agent failures](docs/incidents/), each stopped by a deterministic policy.**
They include repeat loops, missing approvals, destructive file operations, and unsafe navigation.
The corpus maps every report to the smallest runtime control that would have stopped or paused it.

Agent Firewall is a small, framework-neutral runtime guard for AI-agent tool
calls. It decides whether a proposed call should be allowed, blocked, or held
for human approval **before the tool executes**.

This repository contains the first testable MVP. It has no runtime
dependencies and supports Python 3.9+.

## Install

> **Available after PyPI publish:** the package has not been uploaded yet.

```bash
pip install agent-firewall
```

## What works today

- Ordered allow, block, and approval rules matched by tool name and arguments
- Per-run call and estimated-cost caps
- Per-tool and identical-call repetition caps for runaway loops
- Synchronous and asynchronous tool wrappers
- Human approval callbacks
- Thread-safe budget reservation
- Argument-free JSONL audit logs
- CLI checks and complaint-derived scenario replay
- Transparent MCP stdio proxy with terminal approval
- Persistent local budgets and approvals in SQLite
- Loopback-only dashboard with web approval

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

Evaluate a proposed tool call without executing it:

```bash
agent-firewall check \
  --policy examples/policy.json \
  --tool email.send \
  --arguments '{"to":"customer@example.com"}'
```

The output is machine-readable:

```json
{"code": "rule_match", "decision": "require_approval", "reason": "outbound email requires a human decision", "rule_index": 1}
```

Exit codes are `0` for allow, `3` for approval required, `4` for block, and `2`
for invalid input.

## Guard a real tool

```python
from pathlib import Path

from agent_firewall import Firewall


def ask_human(call, decision):
    answer = input(f"Approve {call.name}? [y/N] ")
    return answer.lower() == "y"


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

Use `await firewall.acall(...)` or wrap an `async def` tool for asynchronous
agents.

## Guard any local MCP server

No agent code changes are required. Put the firewall in front of the existing
stdio server command:

```bash
agent-firewall mcp \
  --policy examples/policy.json \
  --audit firewall-audit.jsonl \
  --approve-terminal \
  -- python path/to/your_mcp_server.py
```

Use the same command and arguments in the MCP client configuration:

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

The proxy forwards newline-delimited JSON-RPC unchanged except for
`tools/call`. Blocked calls receive a JSON-RPC policy error. Approval rules
prompt on the proxy's controlling terminal; without `--approve-terminal`, they
fail closed.

For persistent budgets and browser approval, start the dashboard:

```bash
agent-firewall dashboard \
  --policy examples/policy.json \
  --audit firewall-audit.jsonl \
  --state firewall.db
```

Then run the proxy with the same state and audit files:

```bash
agent-firewall mcp \
  --policy examples/policy.json \
  --audit firewall-audit.jsonl \
  --state firewall.db \
  --approve-web \
  -- python path/to/your_mcp_server.py
```

Open the loopback URL printed by the dashboard. Calls awaiting approval appear
without their arguments; approve or deny them in the browser. Decisions are
idempotent, and an approval rechecks the budget before execution. SQLite keeps
call, cost, per-tool, and identical-call counts across process restarts.

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
    {
      "tool": "database.query",
      "decision": "allow",
      "reason": "read-only query"
    },
    {
      "tool": "email.*",
      "arguments": {"to": "*@mycompany.com"},
      "decision": "allow",
      "reason": "company recipient"
    },
    {
      "tool": "email.*",
      "decision": "require_approval",
      "reason": "external side effect"
    }
  ]
}
```

Rules are evaluated in order and the first match wins. Tool names and string
argument values use shell globs. Non-string argument values use exact matching;
a missing argument does not match.

Cost enforcement uses the estimate supplied by the caller. Agent Firewall does
not calculate provider token costs in this MVP.

Argument auditing defaults to `none`. Use `hash` to compare calls without
logging values, `redacted` to retain only argument shape, or `full` only when
the audit destination is trusted.

## Replay real complaints

The included corpus models 11 sourced reports. The
[Agent Incident Wall](docs/incidents/README.md) maps every report to the
smallest deterministic policy that would have stopped or paused the action.

Examples include:

- [LangGraph database-query loop #6731](https://github.com/langchain-ai/langgraph/issues/6731)
- [LangChain repeated side-effecting tool call #16712](https://github.com/langchain-ai/langchain/issues/16712)
- [LangGraph human-approval bypass #6053](https://github.com/langchain-ai/langgraph/issues/6053)
- [Cline destructive restore #1213](https://github.com/cline/cline/issues/1213)
- [MCP browser SSRF advisory #3662](https://github.com/modelcontextprotocol/servers/issues/3662)

Run them with:

```bash
agent-firewall replay \
  --policy examples/policy.json \
  --scenarios examples/complaints.json
```

To test a new complaint, add a scenario with proposed calls and expected
decisions:

```json
{
  "id": "source-123",
  "source_url": "https://example.com/issue/123",
  "calls": [
    {"tool": "database.query", "estimated_cost_usd": "0.10"}
  ],
  "expected_decisions": ["allow"]
}
```

## Test

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

## MVP boundaries

This release does not provide semantic prompt-injection detection or
multi-host distributed budgets. Both need a threat model and real usage data
before they can be implemented honestly.

## Security posture

Agent Firewall is an enforcement point, not a sandbox. Tool implementations
still need least-privilege credentials and operating-system isolation. Audit
logs omit tool arguments by design because they commonly contain secrets or
personal data.

MIT licensed.
