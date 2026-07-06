import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from agent_firewall import SQLiteApprovalQueue

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
                "rules": [{"tool": "database.query", "decision": "allow"}],
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

    def test_reserved_firewall_parameter_names_remain_opaque_arguments(self):
        arguments = {
            "tool": "inner-tool",
            "tool_name": "inner-name",
            "estimated_cost_usd": "opaque-value",
        }
        responses = self.run_proxy(
            {
                "default_decision": "block",
                "rules": [{"tool": "database.query", "decision": "allow"}],
            },
            [
                {
                    "jsonrpc": "2.0",
                    "id": "opaque",
                    "method": "tools/call",
                    "params": {
                        "name": "database.query",
                        "arguments": arguments,
                    },
                }
            ],
        )

        content = responses[0]["result"]["content"][0]["text"]
        self.assertEqual(json.loads(content), arguments)

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

    def test_duplicate_in_flight_id_returns_error_and_proxy_stays_alive(self):
        responses = self.run_proxy(
            {"default_decision": "allow"},
            [
                {
                    "jsonrpc": "2.0",
                    "id": "duplicate",
                    "method": "tools/call",
                    "params": {
                        "name": "database.query",
                        "arguments": {"delay_seconds": 0.1},
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": "duplicate",
                    "method": "tools/call",
                    "params": {
                        "name": "database.query",
                        "arguments": {"sql": "select duplicate"},
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": "after-duplicate",
                    "method": "tools/call",
                    "params": {
                        "name": "database.query",
                        "arguments": {"sql": "select alive"},
                    },
                },
            ],
        )

        duplicate_responses = [
            response for response in responses if response["id"] == "duplicate"
        ]
        self.assertEqual(len(duplicate_responses), 2)
        errors = [
            response["error"] for response in duplicate_responses if "error" in response
        ]
        self.assertEqual(errors[0]["code"], -32600)
        self.assertTrue(
            any(
                response["id"] == "after-duplicate" and "result" in response
                for response in responses
            )
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

    def test_web_approval_unblocks_waiting_tool_call(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "policy.json"
            state_path = root / "firewall.db"
            policy_path.write_text(
                json.dumps(
                    {
                        "rules": [
                            {
                                "tool": "email.send",
                                "decision": "require_approval",
                                "reason": "external email",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
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
                    "--state",
                    str(state_path),
                    "--approve-web",
                    "--approval-timeout",
                    "2",
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
            request = {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {
                    "name": "email.send",
                    "arguments": {"to": "person@example.com"},
                },
            }
            process.stdin.write(json.dumps(request) + "\n")
            process.stdin.flush()
            queue = SQLiteApprovalQueue(state_path)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline and not queue.pending():
                time.sleep(0.01)
            self.assertTrue(queue.pending())
            queue.decide(queue.pending()[0].call_id, "approved")
            process.stdin.close()
            stdout = process.stdout.read()
            stderr = process.stderr.read()
            status = process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()

        self.assertEqual(status, 0, stderr)
        response = json.loads(stdout)
        self.assertEqual(response["id"], 9)
        self.assertIn("result", response)


if __name__ == "__main__":
    unittest.main()
