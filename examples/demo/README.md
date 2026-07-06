# MCP proxy demo

This demo starts Agent Firewall in front of the reference filesystem MCP
server and sends three JSON-RPC tool calls:

1. an allowed `read_text_file`;
2. the same read again, blocked by the identical-call budget;
3. a `filesystem.delete` call held for approval.

Run it from the repository root:

```bash
.venv/bin/python examples/demo/run_demo.py
```

`npx` downloads `@modelcontextprotocol/server-filesystem` on the first run.
The demo uses a temporary audit log and does not change the fixture file.
