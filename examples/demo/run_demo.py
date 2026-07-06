#!/usr/bin/env python3
"""Run the Agent Firewall MCP demo against the reference filesystem server."""

from __future__ import annotations

import json
import os
import select
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
WORKSPACE = ROOT / "examples" / "demo" / "workspace"
DEMO_FILE = WORKSPACE / "hello.txt"


def send(process: subprocess.Popen[bytes], message: dict[str, Any]) -> None:
    assert process.stdin is not None
    process.stdin.write(
        (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")
    )
    process.stdin.flush()


def receive(process: subprocess.Popen[bytes], request_id: int) -> dict[str, Any]:
    assert process.stdout is not None
    while True:
        ready, _, _ = select.select([process.stdout], [], [], 20)
        if not ready:
            raise TimeoutError(f"timed out waiting for JSON-RPC id {request_id}")
        line = process.stdout.readline()
        if not line:
            raise RuntimeError("MCP proxy exited before responding")
        message = json.loads(line)
        if message.get("id") == request_id:
            return message


def call_tool(
    process: subprocess.Popen[bytes],
    request_id: int,
    name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    send(
        process,
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
    )
    return receive(process, request_id)


def outcome(response: dict[str, Any]) -> str:
    error = response.get("error")
    if isinstance(error, dict):
        data = error.get("data", {})
        if isinstance(data, dict):
            return str(data.get("decision", "error")).upper()
        return "ERROR"
    return "ALLOW"


def main() -> int:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")

    with tempfile.TemporaryDirectory(prefix="agent-firewall-demo-") as temp_dir:
        command = [
            sys.executable,
            "-m",
            "agent_firewall",
            "mcp",
            "--policy",
            str(ROOT / "examples" / "policy.json"),
            "--audit",
            str(Path(temp_dir) / "audit.jsonl"),
            "--",
            "npx",
            "-y",
            "@modelcontextprotocol/server-filesystem",
            str(WORKSPACE),
        ]
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            send(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {
                            "name": "agent-firewall-demo",
                            "version": "1.0",
                        },
                    },
                },
            )
            initialize = receive(process, 1)
            if "error" in initialize:
                raise RuntimeError(f"MCP initialization failed: {initialize['error']}")
            send(
                process,
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                    "params": {},
                },
            )

            print("Agent Firewall + reference filesystem MCP server")
            print("Policy: examples/policy.json")
            print()

            read = call_tool(
                process,
                2,
                "read_text_file",
                {"path": str(DEMO_FILE)},
            )
            text = read.get("result", {}).get("content", [{}])[0].get("text", "")
            print(f"1  {outcome(read):<16} read_text_file")
            print(f"   {text.strip()}")

            repeat = call_tool(
                process,
                3,
                "read_text_file",
                {"path": str(DEMO_FILE)},
            )
            print(f"2  {outcome(repeat):<16} repeated read_text_file")
            print("   identical-call budget stops the loop")

            delete = call_tool(
                process,
                4,
                "filesystem.delete",
                {"path": str(DEMO_FILE)},
            )
            print(f"3  {outcome(delete):<16} filesystem.delete")
            print("   irreversible action waits for human approval")
            return 0
        finally:
            if process.stdin is not None:
                process.stdin.close()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
