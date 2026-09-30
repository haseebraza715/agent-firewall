# Safe reproduction of MCP Puppeteer issue 3662

This harness runs the affected `@modelcontextprotocol/server-puppeteer@0.6.2`
package against a loopback-only HTTP fixture. It first reproduces the reported
navigation path without a guard. It then starts one guarded MCP session and
checks four paths: an allowed call executes, an approval-required call pauses,
a prohibited call never executes, and a repeated call hits the configured
budget before its second execution.

The public report is
[modelcontextprotocol/servers#3662](https://github.com/modelcontextprotocol/servers/issues/3662).
The affected source is pinned to archived upstream commit
`9be4674d1ddf8c469e6461a27a337eeb65f76c2e`. In that revision,
`puppeteer_navigate` passes `args.url` directly to `page.goto`.

## Run it

Requirements are Node.js 20+, npm, Python 3.9+, and an installed Chrome or
Chromium browser. On macOS the runner finds Google Chrome automatically. On
other systems, set `PUPPETEER_EXECUTABLE_PATH`.

```bash
./reproductions/mcp-puppeteer-3662/run.sh
```

The first run installs the exact npm dependency graph from `package-lock.json`
with Puppeteer's browser download disabled. The runner passes the installed executable through `PUPPETEER_EXECUTABLE_PATH`, which Puppeteer's configuration reads. The pinned server does not read `PUPPETEER_LAUNCH_OPTIONS` and launches with `headless: false`, so a graphical session is required. This does not disable browser or machine security settings.

Successful output has these facts:

- The unguarded endpoint hit count is at least one.
- The guarded safe endpoint hit count is at least one.
- The approval and prohibited endpoint hit counts are zero.
- The approval and prohibited responses contain Agent Firewall error code
  `-32001` with distinct `require_approval` and `block` decisions.
- The first repetition endpoint call executes and the second returns
  `max_identical_calls` without a second endpoint hit.
- `passed` is `true`.

The runner removes stale evidence before starting and writes the normalized
result to `evidence.json` only when the run passes. A failing run prints the results, saves `failure.json` and exits nonzero without leaving an earlier passing artifact behind. Responses and child stderr are included for diagnosis. A JSON-RPC result with `isError: true` is a tool failure, not evidence of execution. Endpoint receipts must also pass.
The evidence records SHA-256 hashes for `package-lock.json` and `policy.json`.
The run uses only `127.0.0.1` and an ephemeral port. It does not contact a cloud
metadata address, internal service, or external website.

## What this proves

On a passing run, this is an end-to-end reproduction of the reported navigation
path against the published affected package. The result shows that Agent
Firewall can allow, pause, or block calls made to this real MCP server and can
stop an identical-call loop before the MCP child handles the second call.

It does not prove complete SSRF prevention or compatibility with current MCP
servers. This is a pinned, archived affected package. The URL matcher does not
resolve DNS or inspect HTTP redirects. Network isolation remains necessary.
