# MCP Server Compatibility

The opt-in compatibility suite lives in `tests/integration/` and is skipped
unless `AGENT_FIREWALL_INTEGRATION=1` is set.

Run it with:

```bash
AGENT_FIREWALL_INTEGRATION=1 \
  PYTHONPATH=src \
  python -m unittest discover -s tests/integration -v
```

The suite wraps each server with `agent-firewall mcp`, performs `initialize`,
`notifications/initialized`, `tools/list`, an allowed `tools/call`, a blocked
`tools/call`, and an approval-required `tools/call`.

| Server | Version | Status | Notes |
| --- | --- | --- | --- |
| `@modelcontextprotocol/server-filesystem` | `2026.7.4` | Blocked in this session | Package is present in the local npx cache, but the full matrix was not run because npm network approval was rejected by the execution environment. |
| `@modelcontextprotocol/server-fetch` | `2026.7.4` | Blocked in this session | Integration case added. Requires live npx package resolution and outbound fetch access for the allowed call. |
| `@modelcontextprotocol/server-memory` | `2026.7.4` | Blocked in this session | Integration case added. Requires live npx package resolution. |
| `@openbnb/mcp-server-airbnb` | `0.1.2` | Blocked in this session | Community stdio MCP package. Package is present in the local npx cache, but the full matrix was not run because npm network approval was rejected by the execution environment. |
