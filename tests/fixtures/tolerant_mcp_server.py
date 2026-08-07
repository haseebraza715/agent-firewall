import json
import sys

# A lenient stdio server that executes tools/call even when params or
# arguments are null or non-object -- the shape of message the firewall proxy
# must never forward unpoliced. It answers only requests with an id and
# ignores non-object frames (JSON-RPC batches).
for line in sys.stdin:
    message = json.loads(line)
    if not isinstance(message, dict) or "id" not in message:
        continue

    method = message.get("method")
    if method == "tools/call":
        params = message.get("params")
        if not isinstance(params, dict):
            params = {}
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            arguments = {}
        result = {
            "content": [
                {
                    "type": "text",
                    "text": "EXECUTED " + json.dumps(arguments),
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
