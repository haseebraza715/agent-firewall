"""Offline attack demo: check proposed calls through the real proxy and a local stub.

Everything here is real product machinery: the stdio MCP proxy polices calls
to a deliberately vulnerable "evil tools" server, budgets cap a runaway loop,
and a held call is approved through the localhost dashboard API. Offline,
deterministic, with saved execution evidence. Requires only the repo checkout
and stdlib networking.

Usage: .venv/bin/python scripts/demo/attack_demo.py --output /path/to/new-directory
"""

from __future__ import annotations

import argparse
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
TOKEN = "demo-token-not-secret"

POLICY = {
    "default_decision": "block",
    "budget": {"max_calls": 50, "max_identical_calls": 2},
    "rules": [
        {
            "tool": "database.query",
            "arguments": {"sql": {"operator": "sql", "equals": "SELECT"}},
            "decision": "allow",
            "reason": (
                "single SELECT statements are allowed; "
                "database permissions must enforce read-only access"
            ),
        },
        {
            "tool": "web.fetch",
            "arguments": {
                "url": {
                    "operator": "url",
                    "scheme": ["http", "https"],
                    "hostname": "*",
                    "deny_private_networks": True,
                }
            },
            "decision": "allow",
            "reason": "HTTP(S) with no private literal IP; DNS and redirects unchecked",
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
from pathlib import Path
receipts = Path(sys.argv[1])
for line in sys.stdin:
    try:
        message = json.loads(line)
    except Exception:
        continue
    if not isinstance(message, dict) or "id" not in message:
        continue
    with receipts.open("a") as handle:
        handle.write(json.dumps(message) + "\\n")
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, help="new directory for execution evidence"
    )
    args = parser.parse_args()
    output = args.output or Path(tempfile.mkdtemp(prefix="af-demo-evidence-"))
    if args.output:
        output.mkdir(parents=True, exist_ok=False)
    exchanges = []
    workdir = Path(tempfile.mkdtemp(prefix="af-attack-demo-"))
    policy_path = workdir / "policy.json"
    policy_path.write_text(json.dumps(POLICY, indent=2), encoding="utf-8")
    child_path = workdir / "evil_tools_server.py"
    child_path.write_text(EVIL_SERVER, encoding="utf-8")
    state_path = workdir / "firewall.db"
    audit_path = workdir / "audit.jsonl"
    receipts_path = workdir / "child-receipts.jsonl"

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
        str(receipts_path),
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
            response = show(proc.stdout.readline())
            exchanges.append({"request": line, "response": response})
            return response

        head("1. Legitimate call is allowed")
        assert "result" in call(1, "database.query", {"sql": "SELECT id FROM users"})

        head("2. Legacy-encoding SSRF attempt (octal 127.0.0.1)")
        assert (
            call(2, "web.fetch", {"url": "http://017700000001/admin"})["error"]["code"]
            == -32001
        )
        note("octal 127.0.0.1 does not slip past the private-network gate")

        head("3. Destructive statement hidden behind SELECT")
        assert (
            call(3, "database.query", {"sql": "SELECT 1; DROP TABLE users"})["error"][
                "code"
            ]
            == -32001
        )
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

        head("5. Held call approved by a scripted dashboard decision")
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
                "0",
                "--token",
                TOKEN,
            ],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        address = (
            dashboard.stdout.readline()
            .strip()
            .removeprefix("Agent Firewall dashboard: ")
        )
        dashboard.stdout.readline()  # Discard the local demo token banner.
        for _ in range(100):
            approvals = json.load(
                urllib.request.urlopen(f"{address}/api/approvals", timeout=5)
            )
            if approvals["approvals"]:
                break
            time.sleep(0.02)
        assert approvals["approvals"], "email never entered the approval queue"
        before_approval = [
            json.loads(line) for line in receipts_path.read_text().splitlines()
        ]
        assert len(before_approval) == 1
        assert before_approval[0]["params"]["name"] == "database.query"
        (output / "pending-approval.json").write_text(
            json.dumps(
                {"approvals": approvals, "child_receipts": before_approval}, indent=2
            )
            + "\n"
        )
        call_id = approvals["approvals"][0]["call_id"]
        note(f"pending approval {call_id[:12]}... approving via dashboard API")
        request = urllib.request.Request(
            f"{address}/api/approvals/{call_id}",
            data=json.dumps({"decision": "approved"}).encode(),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Agent-Firewall-Token": TOKEN,
            },
        )
        urllib.request.urlopen(request, timeout=5)
        approved_response = show(proc.stdout.readline())
        exchanges.append({"request": request_line, "response": approved_response})
        assert "result" in approved_response, (
            "approved call must execute after human sign-off"
        )

        head("6. Runaway loop capped by identical-call budget")
        for attempt in range(3):
            response = call(600 + attempt, "web.fetch", {"url": "https://example.com/"})
            if attempt < 2:
                assert "result" in response
            else:
                assert response["error"]["data"]["code"] == "max_identical_calls"
        note("third identical fetch hits max_identical_calls=2 and is blocked")

        head("Audit trail recorded during this session")
        events = [json.loads(line) for line in audit_path.read_text().splitlines()]
        counts: dict[str, int] = {}
        for event in events:
            counts[event["event"]] = counts.get(event["event"], 0) + 1
        for name, count in sorted(counts.items()):
            print(f"    {name:<20} x{count}")

        receipts = [json.loads(line) for line in receipts_path.read_text().splitlines()]
        assert [item["params"] for item in receipts] == [
            {"name": "database.query", "arguments": {"sql": "SELECT id FROM users"}},
            {"name": "email.send", "arguments": {"to": "customer@example.com"}},
            {"name": "web.fetch", "arguments": {"url": "https://example.com/"}},
            {"name": "web.fetch", "arguments": {"url": "https://example.com/"}},
        ]
        assert counts["approval_requested"] == counts["approval_granted"] == 1
        (output / "exchanges.json").write_text(json.dumps(exchanges, indent=2) + "\n")
        for path in (policy_path, audit_path, receipts_path):
            shutil.copy2(path, output / path.name)
        (output / "summary.json").write_text(
            json.dumps(
                {
                    "passed": True,
                    "child_executions": len(receipts),
                    "pending_email_executions": 0,
                    "approved_email_executions": 1,
                    "events": counts,
                    "boundary": "real proxy, local receipt-only stub",
                },
                indent=2,
            )
            + "\n"
        )
        head(f"Verified stub executions. Evidence saved to {output}")
    finally:
        if proc.poll() is None:
            proc.stdin.close()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        if dashboard is not None and dashboard.poll() is None:
            dashboard.terminate()
            try:
                dashboard.wait(timeout=5)
            except subprocess.TimeoutExpired:
                dashboard.kill()
                dashboard.wait(timeout=5)
        shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
