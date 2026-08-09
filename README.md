# Agent Firewall

> Local, zero-dependency policy enforcement for AI-agent tool calls: decide allow, hold, or block before the tool runs.

<p align="center"><img src="assets/demo/demo.gif" alt="Demo preview" width="720"></p>
<details><summary><b>▶ Watch the full demo (~30s)</b></summary>
<video src="assets/demo/demo.mp4" controls width="720"></video></details>

## Why this exists

LLM agents get real tools — filesystem, shell, email, browsers — and tool-calling frameworks often execute what the model proposes with little between the model and the side effect. A hallucinated or adversarial tool call must be stopped locally, deterministically, before it runs, not by a post-hoc review or a remote service. Agent Firewall is a policy engine that sits between an agent and its tools and answers one question per call: allow, hold, or block.

## What it does

- **Ordered policy rules** — `allow` / `require_approval` / `block` matched by tool name and bound arguments; first match wins, `block` is the default fallback.
- **Typed argument matchers** — URL host/port/path, filesystem path, email domain, HTTP method, numeric range, SQL operation, and command argv patterns instead of string globs. See [docs/ARGUMENT_MATCHERS.md](docs/ARGUMENT_MATCHERS.md).
- **Budgets and caps** — per-run call and cost limits, plus per-tool and identical-call repetition caps; capacity is reserved before anything runs.
- **Human approval** — a Python callback, or terminal and browser prompts, decide `require_approval` calls.
- **MCP stdio proxy** — wrap any local MCP server; blocked or malformed calls are answered with a JSON-RPC error and never forwarded, and stalled servers fail closed.
- **Audit trail** — append-only JSONL audit records with arguments hashed, so secrets in tool arguments never reach disk.

## Architecture

```
          agent tool call
    (CLI | Python API | MCP proxy)
                  │
                  ▼
          Policy.evaluate()
            bind arguments
          │                │
          ▼                ▼
      ordered rules    typed matchers
      (tool + args)   (url, path, ...)
          │                │
          └────────┬───────┘
                   ▼
        decision: allow / require_approval / block
              + reason + rule index
          │                    │
          ▼                    ▼
  budgets & counters    audit record
  (SQLite state,       (JSONL,
   fail-closed writes)  arguments hashed)
```

Module map: `cli.py` (commands) → `policy.py` + `matchers.py` (evaluation) → `models.py` (decision model) → `state.py` + `audit.py` (persistence) → `mcp_proxy.py` + `jsonrpc.py` (MCP), with `approvals.py`, `dashboard.py`, `lint.py`, `explain.py`, `doctor.py`, and `benchmark.py` around the core.

## Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/agent-firewall check --policy examples/policy.json \
  --tool database.query --arguments '{"query":"SELECT 1"}' --format text
```

Output: `allow  database.query` with the matching rule reason. Exit codes: `0` allow, `3` require_approval, `4` block, `2` invalid input. The Python API guards real functions the same way — `Firewall.from_policy_file(...)` plus `firewall.wrap("email.send", send_email)` in [examples/wrap_tool.py](examples/wrap_tool.py); a denial raises `ToolCallBlocked`, not a crash.

## Demo

The recording replays one small policy, [examples/demo_policy.json](examples/demo_policy.json), against three proposed calls — one allowed, one held for approval, one blocked — each with the policy reason behind the decision:

```bash
agent-firewall check --policy examples/demo_policy.json \
  --tool browser.navigate --arguments '{"url":"http://169.254.169.254/"}' --format text
```

To regenerate the recording and the mp4/gif renders:

```bash
./scripts/demo/record.sh        # requires asciinema, agg, and ffmpeg
```

The session itself is scripted in [scripts/demo/demo_body.sh](scripts/demo/demo_body.sh) and runs offline from the repo root.

## Technical decisions

- **Type-strict argument matching.** Exact-value rules compare with type identity: the boolean `true` does not match `1`, and `500` does not match `500.0`. Tool arguments arrive as numbers, floats, booleans, and stringified values that "look like" the intended input; a lenient matcher would accept calls the policy author never approved.
- **SSRF-hardened private-network classification.** The `url` matcher's `deny_private_networks` flag classifies literal IPs only, but covers the encodings resolvers still accept — `127.1`, `2130706433`, `0x7f000001`, leading zeros, and IPv6 zone ids — so rewriting an address cannot sidestep the gate. Hostnames are deliberately not resolved (see Limitations).
- **Fail-closed MCP proxy.** Every client line must be a decodable JSON object before it is forwarded. Undecodable, non-object, and batch lines are answered with a JSON-RPC error and never reach the wrapped server, so a lenient server cannot execute a call the policy never evaluated.
- **Depth-bounded JSON processing.** Every place agent-controlled data is parsed or serialized (audit records, fingerprints, CLI, proxy, policy loading) bounds nesting at 64 levels, and policy and benchmark files reject duplicate JSON keys at load time. Pathological input can neither crash the process with `RecursionError` nor silently widen enforcement through a duplicate-key typo.

## Validation

434 tests, including the security-hardening suite (SSRF address encodings, duplicate-key poisoning, recursion-depth DoS, MCP fail-closed boundaries), pass and run in CI; ruff and strict mypy are clean:

```bash
.venv/bin/python -m pytest tests -q --no-header   # 434 passed, 53 subtests passed
```

[![CI](https://github.com/haseebraza715/agent-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/haseebraza715/agent-firewall/actions/workflows/ci.yml)

## Limitations

- `deny_private_networks` classifies literal IPs only; it does not resolve DNS, so a hostname that points at a private address is not caught by that gate.
- An enforcement point, not a sandbox: tool implementations still need least-privilege credentials and OS isolation. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the exact boundary.
- No prompt-injection detection, and budgets are per-host — a coordinated multi-host agent can exceed them.
- Matcher coverage is the documented set; anything else must be expressed as tool-name rules or exact/glob values.
- The benchmark results in [benchmarks/v1](benchmarks/v1/README.md) are internally curated and labeled — selected replay coverage, not independent or externally validated safety results.
- Alpha: the latest release is the only supported version; see [SECURITY.md](SECURITY.md). License: MIT ([LICENSE](LICENSE)).
