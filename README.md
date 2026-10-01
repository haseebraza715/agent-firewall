# Agent Firewall

> Local, zero-dependency policy enforcement for AI-agent tool calls: allow, hold, or block before the tool runs.

Try the [offline proxy demonstration](#offline-proxy-demonstration). It saves decisions and tool execution receipts so you can check what ran.

This is a local policy gate, not an OS sandbox or a general prompt-injection defense. Only exact `tools/call` traffic is evaluated. Other MCP methods can have side effects and pass through without policy evaluation. See the [enforcement contract](docs/THREAT_MODEL.md#method-contract).

## Why this exists

LLM agents get real tools (filesystem, shell, email, browsers), and tool-calling frameworks often execute what the model proposes without checking it first. Agent Firewall is a policy engine that sits between an agent and its tools and answers one question per call: allow, hold, or block before the tool runs.

## What it does

- **Ordered policy rules**: `allow` / `require_approval` / `block` matched by tool name and bound arguments; first match wins, `block` is the default fallback.
- **Typed argument matchers**: URL host/port/path, filesystem path, email domain, HTTP method, numeric range, SQL operation, and command argv patterns instead of string globs. See [docs/ARGUMENT_MATCHERS.md](docs/ARGUMENT_MATCHERS.md).
- **Budgets and caps**: per-run call and cost limits, plus per-tool and identical-call repetition caps; capacity is reserved before anything runs.
- **Human approval**: a Python callback, or terminal and browser prompts, decide `require_approval` calls.
- **MCP stdio proxy and audit trail**: wrap a compatible local MCP stdio server; blocked or malformed calls are answered with a JSON-RPC error and never forwarded, stalled servers fail closed, and append-only JSONL audit records keep arguments off disk by default (`hash`, `redacted`, and `full` modes trade utility against exposure).

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
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e .
.venv/bin/agent-firewall check --policy examples/policy.json \
  --tool database.query --arguments '{"query":"SELECT 1"}' --format text
```

Python 3.9+ is supported. Upgrade pip inside the environment first: older pip bundled with macOS Python cannot install this pyproject-only package in editable mode. Installation needs access to package indexes for pip and build tools; the installed gate and offline demo need no account or network service.

The example policy matches `database.query`'s `query` argument against single SELECT statements. This is a lexical filter, not a SQL parser or proof of read-only database behavior. Use database permissions to prohibit writes and side-effecting functions. `filesystem.read` requires a `path` lexically within `/workspace`; this declared example scope does not resolve symlinks or create that directory. `/etc/passwd` is blocked for being outside that scope, not because reading it writes data. Every `shell.run` and `email.send` requires approval, including company recipients and ambiguous addresses. Other email methods default to block. The replay now holds a shell command for approval instead of modelling it as automatically executed; calls awaiting approval do not consume executed-call budgets. Review the actual shell command, parsed mailbox and content before approval; budgets and string globs do not establish their safety.

Output: `allow  database.query` with the matching rule reason. Exit codes for `check`: `0` allow, `3` require_approval, `4` block, `2` invalid input; `policy lint`, `replay` with missed scenarios, and `doctor` failures exit `1`; `benchmark` with failed thresholds exits `5`. The Python API guards real functions the same way: `Firewall.from_policy_file(...)` plus `firewall.wrap("email.send", send_email)` in [examples/wrap_tool.py](examples/wrap_tool.py); a denial raises `ToolCallBlocked`, not a crash.

## Guard an MCP server

Wrap a compatible stdio MCP server; only exact `tools/call` traffic passes through the policy. Bounded call-like aliases are rejected with `-32601`; other methods and extensions pass through. The pinned Puppeteer reproduction passed locally with installed Chrome; broader server compatibility must be checked in your environment:

```bash
agent-firewall mcp --policy examples/policy.json \
  --audit firewall-audit.jsonl --state firewall.db \
  --approve-web \
  -- node server.js
```

Held (`require_approval`) calls wait for a decision in the local dashboard. `--approve-web` requires both `--audit` and `--state`, because the dashboard needs the same two paths. The proxy prints the exact command to start it, including `--approval-timeout` when it differs from the 300-second default; the dashboard startup banner echoes its URL and approval token:

```bash
agent-firewall dashboard --policy examples/policy.json --audit firewall-audit.jsonl --state firewall.db
# Agent Firewall dashboard: http://127.0.0.1:8787
# Agent Firewall dashboard token: ...
```

Approve or deny in the browser, or script it with the token against `POST /api/approvals/<call_id>`. The proxy logs lifecycle events (spawned pid, child exit) and held-call guidance on stderr.

## Offline proxy demonstration

Run six proposed calls through the real proxy and a deliberately careless local stub. The stub records received calls and returns text. It never runs SQL, sends email or fetches the supplied URLs.

```bash
DEMO_OUTPUT="$(mktemp -d)/evidence"
.venv/bin/python scripts/demo/attack_demo.py --output "$DEMO_OUTPUT"
cat "$DEMO_OUTPUT/summary.json"
cat "$DEMO_OUTPUT/child-receipts.jsonl"
```

The output directory must be new. The demo starts its own dashboard on an ephemeral loopback port, scripts one approval, stops its processes and saves these artifacts:

| Proposed call | Observed outcome | How to inspect it |
| --- | --- | --- |
| SELECT query | Allowed and received by the stub | First child receipt and `executed` audit event |
| Octal loopback URL | Blocked because the URL allow matcher does not match | Error in `exchanges.json`; no corresponding receipt |
| SELECT followed by DROP | Blocked because the SQL allow matcher rejects stacked statements | Error in `exchanges.json`; no corresponding receipt |
| Duplicate method keys | Parse error before forwarding | `-32700` response; no receipt or policy evaluation |
| Outbound email | Pending with zero email receipts, then executed once after scripted approval | `pending-approval.json`, approval audit events and one email receipt |
| Three identical fetches | Two received; third blocked by the repetition cap | Two fetch receipts; `max_identical_calls` in the third response |

`audit.jsonl` records decisions and terminal outcomes. `exchanges.json` records the actual requests and responses. `summary.json` is written only after execution assertions pass. Matcher failures currently report `no policy rule matched`; that is the default block reason, not a claim that the matcher detected every attack.

This proves those local proxy paths against a stub. It does not measure general attack detection, database safety or current third-party server compatibility. The [pinned Puppeteer reproduction](reproductions/mcp-puppeteer-3662/README.md) is a separate environment-dependent check. The frozen [benchmark](benchmarks/v1/README.md) is internally authored replay coverage, not independent security accuracy; its policies and reports intentionally remain distinct from the improved examples.

## Demo

The existing recording uses an earlier example policy. It illustrates check-only decisions, not current policy coverage or approval before execution. The script replays [examples/demo_policy.json](examples/demo_policy.json) against three proposed calls (one allowed, one held for approval, one blocked), each with the policy reason:

```bash
agent-firewall check --policy examples/demo_policy.json \
  --tool browser.navigate --arguments '{"url":"http://169.254.169.254/"}' --format text
```

Regenerate the recording with `./scripts/demo/record.sh` (requires asciinema, agg, and ffmpeg); the session is scripted in [scripts/demo/demo_body.sh](scripts/demo/demo_body.sh) and runs offline from the repo root.

## Technical decisions

- **Type-strict argument matching.** Exact-value rules compare with type identity: the boolean `true` does not match `1`, and `500` does not match `500.0`. Tool arguments arrive as numbers, floats, booleans, and stringified values; a lenient matcher would accept calls the policy author never approved.
- **SSRF-hardened private-network classification.** The `url` matcher's `deny_private_networks` flag classifies literal IPs only, but covers the encodings resolvers still accept (`127.1`, `2130706433`, `0x7f000001`, `017700000001`-style octal, leading zeros, IPv6 zone ids), so rewriting an address cannot sidestep the gate. Hostnames are deliberately not resolved (see Limitations).
- **Fail-closed MCP proxy.** Every client line must be a decodable JSON object with no duplicate keys before it is forwarded. Undecodable, non-object, duplicate-key, and batch lines are answered with a JSON-RPC error and never reach the wrapped server, so a lenient server cannot execute a call the policy never evaluated.
- **Depth-bounded JSON processing.** Every place agent-controlled data is parsed or serialized (audit records, fingerprints, CLI, proxy, policy loading) bounds nesting at 64 levels, and policy and benchmark files reject duplicate JSON keys at load time. Pathological input can neither crash the process with `RecursionError` nor silently widen enforcement through a duplicate-key typo.

## Validation

Install the development extra before running validation. Use both the CI runner and the pytest visitor command; no fixed test count is promised.

```bash
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/coverage run -m unittest discover -s tests -v
.venv/bin/coverage report
.venv/bin/python -m pytest tests -q --no-header
.venv/bin/ruff format --check src tests examples
.venv/bin/ruff check src tests examples
.venv/bin/mypy src
.venv/bin/agent-firewall replay --policy examples/policy.json --scenarios examples/complaints.json
```

CI also builds and checks the distribution, smoke-tests its wheel, and regenerates frozen benchmark reports for byte comparison. See [.github/workflows/ci.yml](.github/workflows/ci.yml).

[![CI](https://github.com/haseebraza715/agent-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/haseebraza715/agent-firewall/actions/workflows/ci.yml)

## Limitations

- Cost accumulation uses Decimal context precision and can round high-precision inputs; strict monetary accounting remains unresolved. Client-supplied estimated costs are also unverified. Call and repetition limits remain independent controls.
- Web approval records show the tool and policy reason but omit arguments. A dashboard click cannot by itself establish recipient/command review; use an approver with input context for that requirement.
- An incomplete audit tail stops further audited execution. Preserve the log and use a new audit path while keeping the state database and its reserved budgets. See [evidence and recovery limits](docs/THREAT_MODEL.md#evidence-and-recovery-limits).
- `deny_private_networks` classifies literal IPs only; it does not resolve DNS, so a hostname that points at a private address is not caught by that gate.
- An enforcement point, not a sandbox: tool implementations still need least-privilege credentials and OS isolation. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the exact boundary.
- No prompt-injection detection, and budgets are per-host — a coordinated multi-host agent can exceed them.
- Matcher coverage is the documented set; anything else must be expressed as tool-name rules or exact/glob values.
- The benchmark results in [benchmarks/v1](benchmarks/v1/README.md) are internally curated and labeled — selected replay coverage, not independent or externally validated safety results.
- Alpha: the latest release is the only supported version; see [SECURITY.md](SECURITY.md). License: MIT ([LICENSE](LICENSE)).
