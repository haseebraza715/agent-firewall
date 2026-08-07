# Agent Firewall

[![CI](https://github.com/haseebraza715/agent-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/haseebraza715/agent-firewall/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)

**Decide allow, hold, or block for every agent tool call — before it runs.**

![Agent Firewall demo](docs/demo.gif)

## Try it in 60 seconds

```bash
git clone https://github.com/haseebraza715/agent-firewall.git
cd agent-firewall
python3 -m venv .venv && source .venv/bin/activate && pip install .
./scripts/demo.sh
```

What you'll see:

- Three tool calls, three JSON verdicts — `allow`, `require_approval`, `block` — with the matching rule and exit code.
- Eleven incidents replayed against one small policy — ten from real public bug reports — every one stopped or gated.
- A guarded `send_email` raises `ToolCallBlocked` for the risky recipient, with every decision in an append-only audit log.

Fully offline and self-contained: no network, no pip, no runtime dependencies.

## What it does

- **Ordered policy rules** — `allow` / `require_approval` / `block`, matched by tool name and arguments; first match wins, default is block.
- **Budgets and caps** — per-run call and cost limits, plus per-tool and identical-call repetition caps that catch runaway loops.
- **Sync and async guards** — `Firewall.wrap()` and `await firewall.acall(...)`; arguments are bound to parameter names before the policy runs.
- **Human approval** — your own callback, or terminal and browser prompts.
- **MCP stdio proxy** — sits in front of any local MCP server; blocked calls get a JSON-RPC policy error.
- **SQLite state and audit log** — persistent counters across restarts, argument-free JSONL records, fail-closed writes.

## How it works

Each call is matched against the ordered policy by tool name, bound arguments, or both. The first match (or the default) decides, budget capacity is reserved before anything runs, and every outcome lands in the audit log. Fail-closed: no rule, no budget, no execution.

## Quick facts

| | |
|---|---|
| Language | Python 3.9+ |
| Runtime dependencies | zero (stdlib only) |
| Offline | yes — everything runs locally |
| Interfaces | CLI, Python API, MCP stdio proxy, browser dashboard |
| License | MIT |

## Use it

Evaluate a call without executing it (exit codes: `0` allow, `3` approval, `4` block, `2` invalid input):

```bash
agent-firewall check --policy examples/policy.json --tool email.send \
  --arguments '{"to":"customer@example.com"}'
```

Guard a real function — a denial raises `ToolCallBlocked`, not a crash; see [`examples/wrap_tool.py`](examples/wrap_tool.py):

```python
firewall = Firewall.from_policy_file(
    Path("examples/policy.json"),
    approver=ask_human,
    audit_path=Path("firewall-audit.jsonl"),
)
send = firewall.wrap("email.send", send_email)
```

Guard a local MCP server (same command goes in your client's MCP config):

```bash
agent-firewall mcp --policy examples/policy.json --audit firewall-audit.jsonl \
  --approve-terminal -- python path/to/your_mcp_server.py
```

Policies are JSON, fail closed by default, and reject unknown keys at load time so a typo cannot widen enforcement. See [`examples/policy.json`](examples/policy.json).

## Replay real incidents

Eleven failure scenarios — ten from public bug reports on other projects — and one small policy stops or gates all of them:

```bash
agent-firewall replay --policy examples/policy.json --scenarios examples/complaints.json
```

The [Agent Incident Wall](docs/incidents/README.md) maps every report to the rule that would have caught it.

## Security posture

An enforcement point, not a sandbox — tool implementations still need least-privilege credentials and OS isolation. Audit logs omit arguments by design because they commonly contain secrets. No prompt-injection detection or multi-host budgets yet; both need a threat model and real usage data.

## Links

- [Agent Incident Wall](docs/incidents/README.md)
- [SECURITY.md](SECURITY.md)
- [LICENSE](LICENSE) — MIT
