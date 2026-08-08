# Agent Firewall

[![CI](https://github.com/haseebraza715/agent-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/haseebraza715/agent-firewall/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)

**Decide allow, hold, or block for every agent tool call before it runs.**

![Agent Firewall demo](docs/demo.gif)

## Try it in 60 seconds

```bash
git clone https://github.com/haseebraza715/agent-firewall.git
cd agent-firewall
python3 -m venv .venv && source .venv/bin/activate && pip install .
./scripts/demo.sh
```

What you'll see:

- Three tool calls, three JSON verdicts: `allow`, `require_approval`, `block`, with the matching rule and exit code.
- Eleven reconstructed incident scenarios replayed against one small policy (ten based on public bug reports, one synthetic), every one stopped or gated.
- A guarded `send_email` raises `ToolCallBlocked` for the risky recipient, with every decision in an append-only audit log.

The demo runs offline after checkout. The package has zero runtime dependencies.

## What it does

- **Ordered policy rules:** `allow` / `require_approval` / `block`, matched by tool name and arguments; first match wins, default is block.
- **Typed argument matchers:** validate URL hosts, filesystem paths, email domains, HTTP methods, numeric ranges, SQL operations, and command argv against structured patterns — not string globs. See [docs/ARGUMENT_MATCHERS.md](docs/ARGUMENT_MATCHERS.md).
- **Budgets and caps:** per-run call and cost limits, plus per-tool and identical-call repetition caps that catch runaway loops. Over MCP, a client-supplied cost in `params._meta.estimated_cost_usd` feeds the cost budget; absent means zero.
- **Sync and async guards:** `Firewall.wrap()` and `await firewall.acall(...)`; arguments are bound to parameter names before the policy runs.
- **Human approval:** your own callback, or terminal and browser prompts.
- **MCP stdio proxy:** sits in front of any local MCP server; blocked calls get a JSON-RPC policy error and are never forwarded, while a forwarded call whose server stalls times out fail-closed via `--request-timeout`.
- **SQLite state and audit log:** persistent counters across restarts, argument-free JSONL records, fail-closed writes.

## How it works

Each call is matched against the ordered policy by tool name, bound arguments, or both. The first match (or the default) decides, budget capacity is reserved before anything runs, and every outcome lands in the audit log. Fail-closed: no rule, no budget, no execution.

## Quick facts

| | |
|---|---|
| Language | Python 3.9+ |
| Runtime dependencies | zero (stdlib only) |
| Offline | yes: everything runs locally |
| Interfaces | CLI, Python API, MCP stdio proxy, browser dashboard |
| License | MIT |

## Use it

Evaluate a call without executing it (exit codes: `0` allow, `3` approval, `4` block, `2` invalid input):

```bash
agent-firewall check --policy examples/policy.json --tool email.send \
  --arguments '{"to":"customer@example.com"}'
```

Guard a real function: a denial raises `ToolCallBlocked`, not a crash; see [`examples/wrap_tool.py`](examples/wrap_tool.py):

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
  --approve-terminal --request-timeout 60 -- python path/to/your_mcp_server.py
```

The proxy forwards ordinary MCP metadata unchanged, reads an optional
`params._meta.estimated_cost_usd` per call into the cost budget, and fails a
call closed when the wrapped server stalls past `--request-timeout` (default
300s, error code `-32002`). A response stall affects only that request. A stdin
write stall terminates the child to protect JSONL framing; concurrent and later
requests then receive child-unavailable error `-32003`.

Policies are JSON, fail closed by default, and reject unknown keys at load time so a typo cannot widen enforcement. See [`examples/policy.json`](examples/policy.json).

## Replay reconstructed incident scenarios

Eleven reconstructed incident scenarios (ten based on public bug reports on other projects, one synthetic) replayed against one small policy:

```bash
agent-firewall replay --policy examples/policy.json --scenarios examples/complaints.json
```

All eleven stop or gate, but treat that 11/11 as selected replay coverage of scenarios we reconstructed, not a held-out safety benchmark. The [Agent Incident Wall](docs/incidents/README.md) maps each public-report scenario to the rule that would have caught it.

## Run the development benchmark and evaluation split

An internal development benchmark evaluates the policy against labeled cases and writes byte-stable JSON and Markdown reports (exact decision accuracy, a 3x3 confusion matrix, intervention recall, dangerous-allow rate, safe-call friction, approval accuracy, per-category results, and input hashes):

```bash
./scripts/run-benchmark.sh
```

The published development evaluation is 47 internally curated cases (26 unsafe
or approval-required scenarios plus 21 paired safe controls across six
categories), 84 calls, exact decision accuracy 1.0000, dangerous-allow rate
0.0000, and safe-call friction 0.0000. A separate internal evaluation split
adds 23 distinct cases (31 calls). `freeze.json` pins the exact policy and cases
used and rejects later changes:

```bash
./scripts/run-holdout-benchmark.sh
```

Both results are internally curated and internally labeled. The second set was
authored with access to the policy, and its initial results were inspected
before the manifest was written. Hash pinning prevents later drift. It does not
make the set a blind holdout or an independent evaluation. Nothing here is
externally validated, and none of these numbers measure unseen real-world
safety.

Optional threshold flags make the benchmark a regression gate. Every threshold
is validated to the inclusive 0..1 range, each failed threshold is printed,
and the command exits with code `5` (distinct from `0` allow, `1` replay
failures, `2` invalid input, `3` approval, `4` block):

```bash
agent-firewall benchmark --policy benchmarks/v1/policy.json \
  --cases benchmarks/v1/cases.json --output .agent-tmp/reports \
  --max-dangerous-allow-rate 0.05 --min-intervention-recall 0.95
```

Flags: `--max-dangerous-allow-rate`, `--max-safe-friction-rate`,
`--min-intervention-recall`, `--min-approval-accuracy`,
`--min-exact-accuracy`. A rate with no calls of its class satisfies a `max`
threshold but fails a `min` threshold (the metric was not demonstrated).
Reports stay byte-stable whether or not thresholds are given.

See [benchmarks/v1](benchmarks/v1/README.md) for the case schema, metric definitions, the published results, and why these results are selected replay coverage, not independent or externally validated safety benchmarks.

## Lint, explain, and doctor

`policy lint` statically checks a policy for common problems — a permissive
default, missing budgets, shadowed duplicate or equivalent rules, broad
allow-all tool patterns, URL-shaped string globs, allow rules with no argument
constraints and a broad tool pattern, and approval rules shadowed by broader
allow rules. Error-level findings exit nonzero; `--format json` is available:

```bash
agent-firewall policy lint --policy examples/policy.json
```

`policy explain` shows why a call got its decision: the budget evaluation,
every rule's tool and argument match result, and the exact runtime decision.
Both text (default) and JSON output are supported:

```bash
agent-firewall policy explain --policy examples/policy.json \
  --tool email.send --arguments '{"to":"customer@example.com"}'
```

`doctor` probes the pieces the firewall depends on without destructive writes:
policy loading, state and audit parent writability, an optional MCP child
command's availability, fail-closed behaviour for an unknown tool, and the
installed version:

```bash
agent-firewall doctor --policy examples/policy.json \
  --state firewall.db --audit firewall-audit.jsonl --mcp python server.py
```

## Security posture

An enforcement point, not a sandbox: tool implementations still need least-privilege credentials and OS isolation. Audit logs omit arguments by design because they commonly contain secrets. No prompt-injection detection or multi-host budgets yet; see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the exact boundary and failure modes.

## Links

- [Agent Incident Wall](docs/incidents/README.md)
- [Safe MCP Puppeteer issue 3662 reproduction](reproductions/mcp-puppeteer-3662/README.md)
- [Threat model](docs/THREAT_MODEL.md)
- [SECURITY.md](SECURITY.md)
- [LICENSE](LICENSE): MIT
