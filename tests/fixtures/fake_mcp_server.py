import json
import sys
import time

for line in sys.stdin:
    message = json.loads(line)
    if "id" not in message:
        continue

    method = message.get("method")
    if method == "initialize":
        result = {
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fake-mcp", "version": "1.0"},
        }
    elif method == "tools/list":
        result = {
            "tools": [
                {
                    "name": "database.query",
                    "description": "Return its arguments",
                    "inputSchema": {"type": "object"},
                }
            ]
        }
    elif method == "tools/call":
        delay = message["params"].get("arguments", {}).get("delay_seconds", 0)
        if delay:
            time.sleep(delay)
        result = {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(message["params"].get("arguments", {})),
                }
            ]
        }
    else:
        result = {}

    print(
        json.dumps(
            {"jsonrpc": "2.0", "id": message["id"], "result": result},
            separators=(",", ":"),
        ),
        flush=True,
    )
