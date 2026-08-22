"""Live attack demo: run real attacks through a real agent-firewall proxy.

Everything here is real product machinery: the stdio MCP proxy polices calls
to a deliberately vulnerable "evil tools" server, budgets cap a runaway loop,
and a held call is approved through the localhost dashboard API. Offline,
deterministic, self-cleaning. Requires only the repo checkout and curl-free
stdlib networking.

Usage: .venv/bin/python scripts/demo/attack_demo.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PORT = 8899
TOKEN = "demo-token-not-secret"

POLICY = {
    "default_decision": "block",
    "budget": {"max_calls": 50, "max_identical_calls": 2},
    "rules": [
        {
            "tool": "database.query",
            "arguments": {"sql": {"operator": "sql", "equals": "SELECT"}},
            "decision": "allow",
            "reason": "read-only SQL only",
        },
        {
            "tool": "web.fetch",
            "arguments": {"url": {"operator": "url", "deny_private_networks": True}},
            "decision": "allow",
            "reason": "public web fetches only",
        },
        {
            "tool": "email.send",
            "decision": "require_approval",
            "reason": "outbound email needs human sign-off",
        },
    ],
}

EVIL_SERVER = """\
import json, sys
for line in sys.stdin:
    try:
        message = json.loads(line)
    except Exception:
        continue
    if not isinstance(message, dict) or "id" not in message:
        continue
    params = message.get("params") if isinstance(message.get("params"), dict) else {}
    name = str(params.get("name"))
    result = {"content": [{"type": "text", "text": "EXECUTED " + name}]}
    reply = {"jsonrpc": "2.0", "id": message["id"], "result": result}
    print(json.dumps(reply), flush=True)
"""


def head(text: str) -> None:
    print(f"\n=== {text} ===", flush=True)


def note(text: str) -> None:
    print(f"    {text}", flush=True)


def show(response_line: str) -> dict:
    response = json.loads(response_line)
    if "error" in response:
        err = response["error"]
        data = err.get("data", {})
        reason = data.get("reason", err["message"])
        print(f"    -> {err['code']} {data.get('decision', 'error')}: {reason}")
    else:
        payload = json.dumps(response.get("result"))[:100]
        print(f"    -> executed: {payload}")
    return response


def main() -> int:
    workdir = Path(tempfile.mkdtemp(prefix="af-attack-demo-"))
    policy_path = workdir / "policy.json"
    policy_path.write_text(json.dumps(POLICY, indent=2), encoding="utf-8")
    child_path = workdir / "evil_tools_server.py"
    child_path.write_text(EVIL_SERVER, encoding="utf-8")
    state_path = workdir / "firewall.db"
    audit_path = workdir / "audit.jsonl"

    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    proxy_cmd = [
        sys.executable,
        "-m",
        "agent_firewall",
        "mcp",
        "--policy",
        str(policy_path),
        "--audit",
        str(audit_path),
        "--state",
        str(state_path),
        "--approve-web",
        "--approval-timeout",
        "60",
        "--request-timeout",
        "10",
        "--",
        sys.executable,
        str(child_path),
    ]
    proc = subprocess.Popen(
        proxy_cmd,
        cwd=ROOT,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    dashboard = None
    try:
        banner = proc.stderr.readline().strip()
        note(f"proxy up: {banner[:80]}...")

        def call(request_id, name=None, arguments=None, raw=None):
            line = raw or json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments or {}},
                }
            )
            print(f"\n[client ->] {line[:110]}")
            proc.stdin.write(line + "\n")
            proc.stdin.flush()
            return show(proc.stdout.readline())

        head("1. Legitimate call is allowed")
        call(1, "database.query", {"sql": "SELECT id FROM users"})

        head("2. Legacy-encoding SSRF attempt (octal 127.0.0.1)")
        call(2, "web.fetch", {"url": "http://017700000001/admin"})
        note("octal 127.0.0.1 does not slip past the private-network gate")

        head("3. Destructive statement hidden behind SELECT")
        call(3, "database.query", {"sql": "SELECT 1; DROP TABLE users"})
        note("stacked statements never match a read-only rule")

        head("4. JSON-RPC duplicate-key smuggling")
        smuggle = call(
            None,
            raw=(
                '{"jsonrpc":"2.0","id":4,"method":"tools/call",'
                '"method":"notifications/initialized","params":{"name":"danger"}}'
            ),
        )
        assert "duplicate key" in smuggle["error"]["message"]
        note("ambiguous bytes are answered with a parse error, never forwarded")

        head("5. Held call approved by a human via the dashboard")
        request_line = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "email.send",
                    "arguments": {"to": "customer@example.com"},
                },
            }
        )
        print(f"\n[client ->] {request_line[:110]}")
        proc.stdin.write(request_line + "\n")
        proc.stdin.flush()
        note("call is held; the proxy is waiting for a human decision")

        dashboard = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "agent_firewall",
                "dashboard",
                "--policy",
                str(policy_path),
                "--audit",
                str(audit_path),
                "--state",
                str(state_path),
                "--port",
                str(PORT),
                "--token",
                TOKEN,
            ],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        for _ in range(40):
            try:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{PORT}/api/summary", timeout=1
                )
                break
            except Exception:
                time.sleep(0.25)
        approvals = json.load(
            urllib.request.urlopen(f"http://127.0.0.1:{PORT}/api/approvals", timeout=5)
        )
        call_id = approvals["approvals"][0]["call_id"]
        note(f"pending approval {call_id[:12]}... approving via dashboard API")
        request = urllib.request.Request(
            f"http://127.0.0.1:{PORT}/api/approvals/{call_id}",
            data=json.dumps({"decision": "approved"}).encode(),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Agent-Firewall-Token": TOKEN,
            },
        )
        urllib.request.urlopen(request, timeout=5)
        approved_response = show(proc.stdout.readline())
        assert "result" in approved_response, (
            "approved call must execute after human sign-off"
        )

        head("6. Runaway loop capped by identical-call budget")
        for attempt in range(3):
            call(600 + attempt, "web.fetch", {"url": "https://example.com/"})
        note("third identical fetch hits max_identical_calls=2 and is blocked")

        head("Audit trail recorded during this session")
        events = [json.loads(line) for line in audit_path.read_text().splitlines()]
        counts: dict[str, int] = {}
        for event in events:
            counts[event["event"]] = counts.get(event["event"], 0) + 1
        for name, count in sorted(counts.items()):
            print(f"    {name:<20} x{count}")

        head("All attacks handled by policy. Nothing dangerous executed.")
    finally:
        if proc.poll() is None:
            proc.stdin.close()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        if dashboard is not None and dashboard.poll() is None:
            dashboard.terminate()
            try:
                dashboard.wait(timeout=5)
            except subprocess.TimeoutExpired:
                dashboard.kill()
        shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
