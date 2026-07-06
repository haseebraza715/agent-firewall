# Agent Firewall

[![CI](https://github.com/haseebraza715/agent-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/haseebraza715/agent-firewall/actions/workflows/ci.yml)

Agent Firewall is a small, framework-neutral runtime guard for AI-agent tool
calls. It decides whether a proposed call should be allowed, blocked, or held
for human approval **before the tool executes**.

This repository contains the first testable MVP. It has no runtime
dependencies and supports Python 3.9+.

## What works today

- Ordered allow, block, and approval rules matched by tool name and arguments
- Per-run call and estimated-cost caps
- Per-tool and identical-call repetition caps for runaway loops
- Synchronous and asynchronous tool wrappers
- Human approval callbacks
- Thread-safe budget reservation
- Argument-free JSONL audit logs
- CLI checks and complaint-derived scenario replay

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

The included scenarios model:

- [LangGraph database-query loop #6731](https://github.com/langchain-ai/langgraph/issues/6731)
- [LangChain repeated side-effecting tool call #16712](https://github.com/langchain-ai/langchain/issues/16712)
- [LangGraph human-approval bypass #6053](https://github.com/langchain-ai/langgraph/issues/6053)

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

This release does not yet provide semantic prompt-injection detection, an MCP
transport adapter, persistent distributed budgets, or a web approval UI.
Those should be added only after testing the policy boundary with real users.

## Security posture

Agent Firewall is an enforcement point, not a sandbox. Tool implementations
still need least-privilege credentials and operating-system isolation. Audit
logs omit tool arguments by design because they commonly contain secrets or
personal data.

MIT licensed.
