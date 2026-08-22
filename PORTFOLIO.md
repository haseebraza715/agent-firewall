# Agent Firewall — portfolio notes

One line: a zero-dependency Python policy engine that decides allow, hold, or
block for every AI-agent tool call before the tool runs, with an audit trail,
budgets, and an MCP proxy for existing servers.

## CV bullets

1. Built a zero-dependency (stdlib-only) Python policy engine that evaluates
   every proposed agent tool call against ordered rules and typed argument
   matchers and decides `allow` / `require_approval` / `block` before
   execution, with exit-code semantics, an append-only JSONL audit trail
   (arguments hashed), and persistent SQLite budgets that cap runaway loops.
2. Hardened the enforcement boundary against bypasses: SSRF-style
   private-network classification that recognizes legacy IPv4 encodings and
   IPv6 zone ids, duplicate-key and unknown-key rejection at policy load,
   depth-bounded JSON processing against `RecursionError` DoS, and a
   fail-closed MCP stdio proxy that never forwards undecodable or batch lines
   and times stalled servers out per-request.
3. Evidence: 486 tests plus 117 subtests (including a security-hardening
   suite) green, ruff and strict mypy clean, CI on GitHub Actions, an
   end-to-end reproduction of a public MCP SSRF incident (Puppeteer #3662),
   and an internally curated 47-case development evaluation (exact decision
   accuracy 1.0000, dangerous-allow rate 0.0000) that is honestly labeled as
   selected replay coverage, not an independent benchmark.

## 15 seconds

It is a zero-dependency Python tool that sits between an AI agent and its
tools. For every proposed tool call it decides allow, hold, or block — with
the matching policy reason, an audit trail, and budgets that stop runaway
loops — and it proxies local MCP servers so existing agents get the same
guard without code changes. Nothing executes unless the policy says so.

## 45 seconds

LLM agents get real tools — shell, filesystem, email, browsers — and
frameworks often execute whatever the model proposes. Agent Firewall is a
policy engine that intercepts each call before execution: rules match tool
name and typed argument patterns (URL host, path, email domain, numeric
range, SQL operation, command argv), budgets reserve capacity first, and a
human can approve or deny `require_approval` calls via terminal or browser.
It ships as a CLI, a Python wrapper (`Firewall.wrap`), and a fail-closed MCP
stdio proxy that blocks or rejects calls without forwarding them. The
hardening pass closed real bypass classes: legacy IPv4 encodings and IPv6
zone ids in the SSRF gate, duplicate JSON keys that could widen a policy,
recursion-depth DoS on agent-controlled input, and undecodable lines that a
lenient MCP server might otherwise execute. Evidence: 486 tests plus a
security-hardening suite, ruff and strict mypy clean, a working reproduction
of a public MCP SSRF incident, and an honestly-labeled internal 47-case
evaluation with zero dangerous allows.

## Staff-level questions

**Q: A client sends a JSON-RPC *batch* containing a `tools/call`. What does the proxy do, and why?**

A: Batches are never forwarded. Lines starting with `[` are parsed and, if
they form an array, answered element-by-element with `-32600`
("batch requests are not supported") for every element carrying an id
(`_reject_batch` in `src/agent_firewall/mcp_proxy.py`). A batch would let a
client smuggle a `tools/call` past the per-line policy check that normally
runs before forwarding, so the proxy rejects the shape itself rather than
evaluating its contents.

**Q: How does `deny_private_networks` classify `2130706433`, and where does it stop?**

A: `_is_private_literal` in `src/agent_firewall/matchers.py` runs the
hostname through `ipaddress.ip_address`, which accepts legacy encodings —
`2130706433` parses as `127.0.0.1`, `0x7f000001` and `127.1` as well — and
splits IPv6 zone ids at `%` first. Any literal address that is not globally
routable fails the matcher. The deliberate boundary: only literal IPs are
classified. DNS is never resolved, so a hostname pointing at a private
address passes this gate; that is documented as a limitation rather than a
silent hole.

**Q: What stops a duplicate key in `policy.json` from silently widening enforcement?**

A: All policy, benchmark-case, and freeze files load through
`json.loads(text, object_pairs_hook=_reject_duplicate_keys)` in
`src/agent_firewall/policy.py`, which raises on the second occurrence of any
key. Combined with rejecting unknown keys at load time, a typo can only make
loading fail — it cannot change what the policy enforces.

**Q: Why can a 100,000-level-deep tool argument not crash the process?**

A: Every path that serializes or parses agent-controlled data is bounded.
`bounded()` in `src/agent_firewall/models.py` copies values with subtrees
deeper than 64 levels replaced by a placeholder, so fingerprints and audit
records cannot trigger `RecursionError` inside `json.dumps`; every load path
(policy, scenarios, proxy lines, CLI input, dashboard) catches
`RecursionError` and converts it into a normal error. A pathological call is
denied or logged — it is never a crash.

**Q: The MCP child server stalls mid-request. What exactly happens?**

A: A request that does not complete within `--request-timeout` (default
300s) is answered with error code `-32002` and affects only that request,
while pending correlation state is released. A *write* stall to the child's
stdin is worse — an oversized or stuck write could break JSONL framing — so
the proxy terminates the child, and concurrent and later requests receive
child-unavailable error `-32003`. The proxy never executes anything outside
the policy; when the child fails, the call fails closed.

**Q: Why does `1` not match `true` in an exact-value rule?**

A: Exact-value rules compare with type identity. Python booleans are ints,
and JSON booleans, ints, and floats are distinct types, so a matcher that
coerced them would let a call match a rule the policy author never approved
— `{"retries": true}` should not satisfy a `{"retries": 1}` rule. The
changelog records this as a deliberate hardening change, and the matcher
unit tests pin the boundary.
