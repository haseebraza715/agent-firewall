import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FAKE_SERVER = ROOT / "tests" / "fixtures" / "fake_mcp_server.py"


class McpProxyTests(unittest.TestCase):
    def run_proxy(self, policy, messages):
        with tempfile.TemporaryDirectory() as directory:
            policy_path = Path(directory) / "policy.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            env = dict(os.environ)
            env["PYTHONPATH"] = str(ROOT / "src")
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "agent_firewall",
                    "mcp",
                    "--policy",
                    str(policy_path),
                    "--",
                    sys.executable,
                    str(FAKE_SERVER),
                ],
                cwd=ROOT,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            payload = "".join(json.dumps(message) + "\n" for message in messages)
            stdout, stderr = process.communicate(payload, timeout=5)

        self.assertEqual(process.returncode, 0, stderr)
        return [json.loads(line) for line in stdout.splitlines()]

    def test_non_tool_requests_pass_through(self):
        responses = self.run_proxy(
            {"default_decision": "block"},
            [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}],
        )

        self.assertEqual(responses[0]["id"], 1)
        self.assertEqual(responses[0]["result"]["serverInfo"]["name"], "fake-mcp")

    def test_allowed_tool_call_reaches_wrapped_server(self):
        responses = self.run_proxy(
            {
                "default_decision": "block",
                "rules": [
                    {"tool": "database.query", "decision": "allow"}
                ],
            },
            [
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "database.query",
                        "arguments": {"sql": "select 1"},
                    },
                }
            ],
        )

        content = responses[0]["result"]["content"][0]["text"]
        self.assertEqual(json.loads(content), {"sql": "select 1"})

    def test_blocked_tool_returns_json_rpc_policy_error(self):
        responses = self.run_proxy(
            {"default_decision": "block"},
            [
                {
                    "jsonrpc": "2.0",
                    "id": "blocked",
                    "method": "tools/call",
                    "params": {"name": "filesystem.delete", "arguments": {}},
                }
            ],
        )

        error = responses[0]["error"]
        self.assertEqual(error["code"], -32001)
        self.assertEqual(error["data"]["decision"], "block")
        self.assertEqual(error["data"]["code"], "default")

    def test_identical_calls_are_stopped_before_forwarding(self):
        message = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "database.query",
                "arguments": {"sql": "select 1"},
            },
        }
        first = dict(message, id=1)
        second = dict(message, id=2)

        responses = self.run_proxy(
            {
                "default_decision": "allow",
                "budget": {"max_identical_calls": 1},
            },
            [first, second],
        )
        by_id = {response["id"]: response for response in responses}

        self.assertIn("result", by_id[1])
        self.assertEqual(
            by_id[2]["error"]["data"]["code"],
            "max_identical_calls",
        )

    def test_approval_rule_fails_closed_without_terminal_flag(self):
        responses = self.run_proxy(
            {
                "rules": [
                    {
                        "tool": "email.send",
                        "decision": "require_approval",
                    }
                ]
            },
            [
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "email.send", "arguments": {}},
                }
            ],
        )

        self.assertEqual(
            responses[0]["error"]["data"]["decision"],
            "require_approval",
        )


if __name__ == "__main__":
    unittest.main()
