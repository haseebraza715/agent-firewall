import json
import os
import sys
import threading
import time
from typing import Any

write_lock = threading.Lock()
cancel_lock = threading.Lock()
cancelled: dict[str, threading.Event] = {}


def request_key(request_id: Any) -> str:
    return json.dumps(request_id, sort_keys=True, separators=(",", ":"))


def cancellation_event(request_id: Any) -> threading.Event:
    key = request_key(request_id)
    with cancel_lock:
        event = cancelled.get(key)
        if event is None:
            event = threading.Event()
            cancelled[key] = event
        return event


def send(message: dict[str, Any]) -> None:
    with write_lock:
        print(json.dumps(message, separators=(",", ":")), flush=True)


def wait(delay_seconds: float, event: threading.Event) -> bool:
    deadline = time.monotonic() + delay_seconds
    while time.monotonic() < deadline:
        if event.is_set():
            return False
        time.sleep(min(0.01, deadline - time.monotonic()))
    return not event.is_set()


def handle_request(message: dict[str, Any]) -> None:
    request_id = message["id"]
    event = cancellation_event(request_id)
    method = message.get("method")
    if method == "initialize":
        params = message.get("params", {})
        result = {
            "protocolVersion": "2025-11-25",
            "capabilities": {
                "logging": {},
                "resources": {"listChanged": True},
                "tools": {"listChanged": True},
            },
            "serverInfo": {"name": "fake-mcp", "version": "1.0"},
            "_meta": {
                "receivedClientCapabilities": params.get("capabilities", {})
                if isinstance(params, dict)
                else {}
            },
        }
    elif method == "tools/list":
        result = {
            "tools": [
                {
                    "name": "database.query",
                    "description": "Return its arguments",
                    "inputSchema": {"type": "object"},
                },
                {
                    "name": "email.send",
                    "description": "Pretend to send an email",
                    "inputSchema": {"type": "object"},
                },
                {
                    "name": "server.crash",
                    "description": "Exit without responding",
                    "inputSchema": {"type": "object"},
                },
            ]
        }
    elif method == "tools/call":
        raw_params = message.get("params", {})
        params = raw_params if isinstance(raw_params, dict) else {}
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            arguments = {}
        if params.get("name") == "server.crash" or arguments.get("crash"):
            os._exit(42)
        delay = float(arguments.get("delay_seconds", 0))
        if delay and not wait(delay, event):
            return
        if event.is_set():
            return
        if arguments.get("emit_notification"):
            send({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
        response_bytes = int(arguments.get("response_bytes", 0))
        text = "x" * response_bytes if response_bytes else json.dumps(arguments)
        result = {"content": [{"type": "text", "text": text}], "isError": False}
    else:
        result = {}

    if not event.is_set():
        send({"jsonrpc": "2.0", "id": request_id, "result": result})


def handle_notification(message: dict[str, Any]) -> None:
    method = message.get("method")
    if method == "notifications/cancelled":
        params = message.get("params", {})
        if isinstance(params, dict) and "requestId" in params:
            cancellation_event(params["requestId"]).set()
        return
    if method == "notifications/initialized":
        send({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
        return
    if method == "notifications/client_ping":
        send({"jsonrpc": "2.0", "method": "notifications/server_saw_client_ping"})


threads: list[threading.Thread] = []
for line in sys.stdin.buffer:
    message = json.loads(line)
    if "id" not in message:
        handle_notification(message)
        continue

    thread = threading.Thread(target=handle_request, args=(message,))
    thread.start()
    threads.append(thread)

for thread in threads:
    thread.join()
