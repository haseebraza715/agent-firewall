import json
import os
import queue
import random
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from agent_firewall import SQLiteApprovalQueue
from agent_firewall.mcp_proxy import PARSE_ERROR, SERVER_UNAVAILABLE_ERROR, _decode

ROOT = Path(__file__).resolve().parents[1]
FAKE_SERVER = ROOT / "tests" / "fixtures" / "fake_mcp_server.py"


class McpProxyTests(unittest.TestCase):
    def run_proxy(self, policy, messages, timeout=5):
        payload = "".join(json.dumps(message) + "\n" for message in messages)
        status, stdout, stderr = self.run_proxy_raw(policy, payload, timeout=timeout)
        self.assertEqual(status, 0, stderr)
        return [json.loads(line) for line in stdout.splitlines()]

    def run_proxy_raw(self, policy, payload, timeout=5, extra_args=None):
        with tempfile.TemporaryDirectory() as directory:
            policy_path = Path(directory) / "policy.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            env = dict(os.environ)
            env["PYTHONPATH"] = str(ROOT / "src")
            command = [
                sys.executable,
                "-m",
                "agent_firewall",
                "mcp",
                "--policy",
                str(policy_path),
            ]
            if extra_args:
                command.extend(extra_args)
            command.extend(["--", sys.executable, str(FAKE_SERVER)])
            process = subprocess.Popen(
                command,
                cwd=ROOT,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, stderr = process.communicate(payload, timeout=timeout)

        return process.returncode, stdout, stderr

    def test_initialize_handshake_and_capability_passthrough(self):
        responses = self.run_proxy(
            {"default_decision": "block"},
            [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {"roots": {"listChanged": True}},
                        "clientInfo": {"name": "proxy-test", "version": "1.0"},
                    },
                }
            ],
        )

        self.assertEqual(responses[0]["id"], 1)
        result = responses[0]["result"]
        self.assertEqual(result["serverInfo"]["name"], "fake-mcp")
        self.assertEqual(result["capabilities"]["tools"], {"listChanged": True})
        self.assertEqual(
            result["_meta"]["receivedClientCapabilities"],
            {"roots": {"listChanged": True}},
        )

    def test_notifications_pass_through_in_both_directions(self):
        responses = self.run_proxy(
            {"default_decision": "block"},
            [
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "method": "notifications/client_ping"},
            ],
        )

        methods = {response["method"] for response in responses}
        self.assertIn("notifications/tools/list_changed", methods)
        self.assertIn("notifications/server_saw_client_ping", methods)

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

    def test_many_concurrent_in_flight_requests_complete(self):
        messages = [
            {
                "jsonrpc": "2.0",
                "id": f"call-{index}",
                "method": "tools/call",
                "params": {
                    "name": "database.query",
                    "arguments": {
                        "index": index,
                        "delay_seconds": 0.03 if index % 2 else 0.01,
                    },
                },
            }
            for index in range(60)
        ]

        responses = self.run_proxy({"default_decision": "allow"}, messages, timeout=10)

        by_id = {response["id"]: response for response in responses}
        self.assertEqual(set(by_id), {f"call-{index}" for index in range(60)})
        for index in range(60):
            content = by_id[f"call-{index}"]["result"]["content"][0]["text"]
            self.assertEqual(json.loads(content)["index"], index)

    def test_multi_megabyte_tool_result_is_forwarded(self):
        responses = self.run_proxy(
            {"default_decision": "allow"},
            [
                {
                    "jsonrpc": "2.0",
                    "id": "large",
                    "method": "tools/call",
                    "params": {
                        "name": "database.query",
                        "arguments": {"response_bytes": 2 * 1024 * 1024},
                    },
                }
            ],
            timeout=10,
        )

        text = responses[0]["result"]["content"][0]["text"]
        self.assertEqual(len(text), 2 * 1024 * 1024)

    def test_invalid_and_partial_json_lines_return_errors_and_proxy_continues(self):
        valid = {
            "jsonrpc": "2.0",
            "id": "after-invalid",
            "method": "tools/call",
            "params": {"name": "database.query", "arguments": {"ok": True}},
        }
        payload = (
            '{"jsonrpc":"2.0","id":1,"method":\n'
            "not-json\n"
            '{"jsonrpc":"2.0","id":null,"method":"tools/list"}\n'
            f"{json.dumps(valid)}\n"
        )

        status, stdout, stderr = self.run_proxy_raw(
            {"default_decision": "allow"},
            payload,
        )

        self.assertEqual(status, 0, stderr)
        responses = [json.loads(line) for line in stdout.splitlines()]
        parse_errors = [
            response
            for response in responses
            if response.get("error", {}).get("code") == PARSE_ERROR
        ]
        self.assertEqual(len(parse_errors), 2)
        self.assertTrue(
            any(response.get("id") == "after-invalid" for response in responses)
        )

    def test_cancelled_request_is_not_answered_and_other_calls_continue(self):
        messages = [
            {
                "jsonrpc": "2.0",
                "id": "slow",
                "method": "tools/call",
                "params": {
                    "name": "database.query",
                    "arguments": {"delay_seconds": 0.5},
                },
            },
            {
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": "slow", "reason": "test cancellation"},
            },
            {
                "jsonrpc": "2.0",
                "id": "quick",
                "method": "tools/call",
                "params": {
                    "name": "database.query",
                    "arguments": {"sql": "select quick"},
                },
            },
        ]

        responses = self.run_proxy({"default_decision": "allow"}, messages, timeout=10)

        self.assertEqual([response["id"] for response in responses], ["quick"])

    def test_wrapped_server_crash_returns_json_rpc_error(self):
        status, stdout, stderr = self.run_proxy_raw(
            {"default_decision": "allow"},
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": "boom",
                    "method": "tools/call",
                    "params": {"name": "server.crash", "arguments": {}},
                }
            )
            + "\n",
            timeout=5,
        )

        self.assertEqual(status, 42, stderr)
        response = json.loads(stdout)
        self.assertEqual(response["id"], "boom")
        self.assertEqual(response["error"]["code"], SERVER_UNAVAILABLE_ERROR)

    def test_stress_mixed_valid_invalid_and_blocked_requests(self):
        raw_lines = []
        for index in range(70):
            raw_lines.append(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": f"ok-{index}",
                        "method": "tools/call",
                        "params": {
                            "name": "database.query",
                            "arguments": {"index": index},
                        },
                    }
                )
            )
        for index in range(25):
            raw_lines.append(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": f"blocked-{index}",
                        "method": "tools/call",
                        "params": {"name": "filesystem.delete", "arguments": {}},
                    }
                )
            )
        for index in range(20):
            raw_lines.append(f'{{"jsonrpc":"2.0","id":"bad-{index}","method":')
        for index in range(10):
            raw_lines.append(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/client_ping",
                        "params": {"index": index},
                    }
                )
            )
        payload = "\n".join(raw_lines) + "\n"

        status, stdout, stderr = self.run_proxy_raw(
            {
                "default_decision": "block",
                "rules": [{"tool": "database.query", "decision": "allow"}],
            },
            payload,
            timeout=15,
        )

        self.assertEqual(status, 0, stderr)
        responses = [json.loads(line) for line in stdout.splitlines()]
        self.assertEqual(
            sum(
                1 for response in responses if str(response.get("id")).startswith("ok-")
            ),
            70,
        )
        self.assertEqual(
            sum(
                1
                for response in responses
                if str(response.get("id")).startswith("blocked-")
                and response.get("error", {}).get("code") == -32001
            ),
            25,
        )
        self.assertEqual(
            sum(
                1
                for response in responses
                if response.get("error", {}).get("code") == PARSE_ERROR
            ),
            20,
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

    def test_approval_timeout_does_not_block_other_calls(self):
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
                            },
                            {"tool": "database.query", "decision": "allow"},
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
            assert process.stdin is not None
            assert process.stdout is not None
            lines: queue.Queue[str] = queue.Queue()
            reader = threading.Thread(
                target=lambda: lines.put(process.stdout.readline()),
                daemon=True,
            )
            reader.start()
            started = time.monotonic()
            process.stdin.write(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "needs-approval",
                        "method": "tools/call",
                        "params": {"name": "email.send", "arguments": {}},
                    }
                )
                + "\n"
            )
            process.stdin.write(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "allowed",
                        "method": "tools/call",
                        "params": {
                            "name": "database.query",
                            "arguments": {"sql": "select 1"},
                        },
                    }
                )
                + "\n"
            )
            process.stdin.flush()
            try:
                first_line = lines.get(timeout=1)
                elapsed_to_first = time.monotonic() - started
            finally:
                process.stdin.close()
            rest = process.stdout.read()
            stderr = process.stderr.read()
            status = process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()

        self.assertEqual(status, 0, stderr)
        self.assertLess(elapsed_to_first, 1)
        first = json.loads(first_line)
        self.assertEqual(first["id"], "allowed")
        responses = [first, *[json.loads(line) for line in rest.splitlines()]]
        by_id = {response["id"]: response for response in responses}
        self.assertEqual(
            by_id["needs-approval"]["error"]["data"]["code"],
            "approval_denied",
        )

    def test_decode_tolerates_malformed_frames(self):
        samples = [
            b"",
            b"\xff\xfe\xfd\n",
            b'{"jsonrpc":"2.0","id":1,"method":',
            b"[]\n",
            b"null\n",
            b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n',
        ]
        rng = random.Random(0)
        for _ in range(200):
            samples.append(bytes(rng.randrange(0, 256) for _ in range(96)))

        for frame in samples:
            result = _decode(frame)
            self.assertTrue(result is None or isinstance(result, dict))


if __name__ == "__main__":
    unittest.main()
