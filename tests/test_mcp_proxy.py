import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from agent_firewall import Firewall, JsonlAuditLog, Policy, SQLiteApprovalQueue
from agent_firewall.jsonrpc import encode_message, request_key
from agent_firewall.mcp_proxy import McpRequestTimeoutError, McpStdioProxy

ROOT = Path(__file__).resolve().parents[1]
FAKE_SERVER = ROOT / "tests" / "fixtures" / "fake_mcp_server.py"
TOLERANT_SERVER = ROOT / "tests" / "fixtures" / "tolerant_mcp_server.py"

ECHO_META_CHILD = (
    "import json,sys\n"
    "for line in sys.stdin:\n"
    "    m=json.loads(line)\n"
    "    if 'id' not in m:\n"
    "        continue\n"
    "    params=m.get('params') if isinstance(m.get('params'),dict) else {}\n"
    "    result={'content':[{'type':'text',"
    "'text':json.dumps({'meta':params.get('_meta')})}]}\n"
    "    print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':result}),flush=True)\n"
)


class McpProxyTests(unittest.TestCase):
    def run_proxy(
        self,
        policy,
        messages,
        server=FAKE_SERVER,
        request_timeout=300,
        child_command=None,
    ):
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
                "--request-timeout",
                str(request_timeout),
                "--",
            ]
            if child_command is not None:
                command.extend(child_command)
            else:
                command.extend([sys.executable, str(server)])
            process = subprocess.Popen(
                command,
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

    def test_method_contract_with_child_receipts(self):
        aliases = [
            "TOOLS/CALL",
            "Tools/Call",
            " tools/call",
            "tools/call ",
            "tools / call",
            "tools//call",
            "\tTOOLS///CALL\n",
        ]
        passthrough = [
            "initialize",
            "tools/list",
            "resources/read",
            "prompts/get",
            "vendor/tools/call",
            "tools/callback",
            "tools/call/extension",
        ]
        with tempfile.TemporaryDirectory() as directory:
            receipts = Path(directory) / "receipts.jsonl"
            child = (
                "import json,sys\n"
                "for line in sys.stdin:\n"
                "    m=json.loads(line)\n"
                f"    with open({str(receipts)!r}, 'a') as f:\n"
                "        f.write(json.dumps(m)+'\\n')\n"
                "    if 'id' in m:\n"
                "        print(json.dumps({'jsonrpc':'2.0','id':m['id'],"
                "'result':{'method':m['method'],'params':m.get('params')}}),"
                "flush=True)\n"
            )
            methods = ["tools/call", *aliases, *passthrough]
            messages = [
                {
                    "jsonrpc": "2.0",
                    "id": i,
                    "method": method,
                    "params": {"name": "danger", "arguments": {"marker": i}},
                }
                for i, method in enumerate(methods)
            ]
            messages.extend(
                {"jsonrpc": "2.0", "method": method, "params": {}}
                for method in [*aliases, "notifications/initialized"]
            )
            responses = self.run_proxy(
                {"default_decision": "block"},
                messages,
                child_command=[sys.executable, "-c", child],
            )
            by_id = {response["id"]: response for response in responses}
            self.assertEqual(len(responses), len(methods))
            self.assertEqual(by_id[0]["error"]["code"], -32001)
            for i in range(1, 1 + len(aliases)):
                self.assertEqual(by_id[i]["error"]["code"], -32601)
            for i in range(1 + len(aliases), len(methods)):
                self.assertEqual(
                    by_id[i]["result"],
                    {
                        "method": methods[i],
                        "params": messages[i]["params"],
                    },
                )
            delivered = [json.loads(line) for line in receipts.read_text().splitlines()]
            self.assertCountEqual(
                [m["method"] for m in delivered],
                [*passthrough, "notifications/initialized"],
            )

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

    def test_duplicate_in_flight_id_is_rejected_before_budget_reservation(self):
        firewall = Firewall(
            Policy.from_dict({"default_decision": "allow", "budget": {"max_calls": 1}})
        )
        proxy = McpStdioProxy(firewall, ["unused"])
        proxy._client_pending.add(request_key("duplicate"))
        message = {
            "jsonrpc": "2.0",
            "id": "duplicate",
            "method": "tools/call",
            "params": {
                "name": "database.query",
                "arguments": {},
                "_meta": {"estimated_cost_usd": "9.50"},
            },
        }

        with patch.object(proxy, "_write_client") as write_client:
            import asyncio

            asyncio.run(proxy._handle_client_line(encode_message(message)))

        self.assertEqual(firewall.state_store.usage().tool_calls, 0)
        self.assertEqual(str(firewall.state_store.usage().estimated_cost_usd), "0")
        self.assertEqual(write_client.call_args.args[0]["error"]["code"], -32600)

    def test_request_timeout_covers_child_write_and_audits_failed(self):
        import asyncio

        with tempfile.TemporaryDirectory() as directory:
            audit_path = Path(directory) / "audit.jsonl"
            firewall = Firewall(
                Policy.from_dict({"default_decision": "allow"}),
                audit_log=JsonlAuditLog(audit_path),
            )
            proxy = McpStdioProxy(firewall, ["unused"], request_timeout=0.01)

            async def blocked_write(_line):
                await asyncio.Event().wait()

            proxy._write_child = AsyncMock(side_effect=blocked_write)
            message = {
                "jsonrpc": "2.0",
                "id": "write-timeout",
                "method": "tools/call",
                "params": {"name": "database.query", "arguments": {}},
            }
            with patch.object(proxy, "_write_client") as write_client:
                asyncio.run(proxy._handle_client_line(encode_message(message)))

            entries = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual([entry["event"] for entry in entries], ["allowed", "failed"])
        self.assertEqual(entries[-1]["error"], "McpRequestTimeoutError")
        self.assertEqual(write_client.call_args.args[0]["error"]["code"], -32002)
        self.assertEqual(firewall.state_store.usage().tool_calls, 1)

    def test_passthrough_request_timeout_is_fail_closed(self):
        import asyncio

        firewall = Firewall(Policy.from_dict({"default_decision": "allow"}))
        proxy = McpStdioProxy(firewall, ["unused"], request_timeout=0.01)

        async def blocked_write(_line):
            await asyncio.Event().wait()

        proxy._write_child = AsyncMock(side_effect=blocked_write)
        message = {
            "jsonrpc": "2.0",
            "id": "initialize-timeout",
            "method": "initialize",
            "params": {},
        }
        with patch.object(proxy, "_write_client") as write_client:
            asyncio.run(proxy._handle_client_line(encode_message(message)))

        self.assertEqual(write_client.call_args.args[0]["error"]["code"], -32002)

    def test_passthrough_notification_timeout_aborts_child(self):
        import asyncio

        proxy = McpStdioProxy(
            Firewall(Policy.from_dict({"default_decision": "allow"})),
            ["unused"],
            request_timeout=0.01,
        )

        async def blocked_write(_line):
            await asyncio.Event().wait()

        proxy._write_child = AsyncMock(side_effect=blocked_write)
        proxy._abort_child = AsyncMock()
        message = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        }
        asyncio.run(proxy._handle_client_line(encode_message(message)))

        proxy._abort_child.assert_awaited_once()

    def test_tool_notification_timeout_is_audited_failed(self):
        import asyncio

        with tempfile.TemporaryDirectory() as directory:
            audit_path = Path(directory) / "audit.jsonl"
            firewall = Firewall(
                Policy.from_dict({"default_decision": "allow"}),
                audit_log=JsonlAuditLog(audit_path),
            )
            proxy = McpStdioProxy(firewall, ["unused"], request_timeout=0.01)

            async def blocked_write(_line):
                await asyncio.Event().wait()

            proxy._write_child = AsyncMock(side_effect=blocked_write)
            proxy._abort_child = AsyncMock()
            message = {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "database.query", "arguments": {}},
            }
            asyncio.run(proxy._handle_client_line(encode_message(message)))
            entries = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual([entry["event"] for entry in entries], ["allowed", "failed"])
        self.assertEqual(entries[-1]["error"], "McpRequestTimeoutError")
        proxy._abort_child.assert_awaited_once()

    def test_real_stalled_write_terminates_child_and_marks_session_unavailable(self):
        import asyncio

        async def exercise():
            proxy = McpStdioProxy(
                Firewall(Policy.from_dict({"default_decision": "allow"})),
                ["unused"],
                request_timeout=0.05,
            )
            proxy.process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-c",
                "import time; time.sleep(60)",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
            )
            with self.assertRaises(McpRequestTimeoutError):
                await proxy._write_child_with_timeout(b"x" * 4_000_000)
            return proxy, proxy.process.returncode

        proxy, returncode = asyncio.run(exercise())
        self.assertIsNotNone(returncode)
        self.assertIsNotNone(proxy._child_failure)

        message = {
            "jsonrpc": "2.0",
            "id": "after-abort",
            "method": "initialize",
            "params": {},
        }
        with patch.object(proxy, "_write_client") as write_client:
            asyncio.run(proxy._handle_client_line(encode_message(message)))
        self.assertEqual(write_client.call_args.args[0]["error"]["code"], -32003)

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

    def test_tools_call_with_null_arguments_is_rejected(self):
        responses = self.run_proxy(
            {
                "default_decision": "block",
                "rules": [{"tool": "email.send", "decision": "require_approval"}],
            },
            [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "email.send", "arguments": None},
                }
            ],
            server=TOLERANT_SERVER,
        )

        self.assertEqual(responses[0]["error"]["code"], -32602)
        self.assertNotIn("EXECUTED", json.dumps(responses))

    def test_tools_call_with_non_object_arguments_is_rejected(self):
        responses = self.run_proxy(
            {
                "default_decision": "block",
                "rules": [{"tool": "email.send", "decision": "require_approval"}],
            },
            [
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "email.send", "arguments": ["arg"]},
                }
            ],
            server=TOLERANT_SERVER,
        )

        self.assertEqual(responses[0]["error"]["code"], -32602)
        self.assertNotIn("EXECUTED", json.dumps(responses))

    def test_name_only_allow_rule_does_not_rescue_malformed_arguments(self):
        responses = self.run_proxy(
            {
                "default_decision": "block",
                "rules": [{"tool": "database.query", "decision": "allow"}],
            },
            [
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {"name": "database.query", "arguments": None},
                }
            ],
            server=TOLERANT_SERVER,
        )

        self.assertEqual(responses[0]["error"]["code"], -32602)
        self.assertNotIn("EXECUTED", json.dumps(responses))

    def test_tools_call_with_non_object_params_is_rejected(self):
        responses = self.run_proxy(
            {"default_decision": "block"},
            [
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": None,
                }
            ],
            server=TOLERANT_SERVER,
        )

        self.assertEqual(responses[0]["error"]["code"], -32602)
        self.assertNotIn("EXECUTED", json.dumps(responses))

    def test_tools_call_without_or_empty_name_is_rejected(self):
        responses = self.run_proxy(
            {"default_decision": "allow"},
            [
                {
                    "jsonrpc": "2.0",
                    "id": 6,
                    "method": "tools/call",
                    "params": {},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "tools/call",
                    "params": {"name": "", "arguments": {}},
                },
            ],
            server=TOLERANT_SERVER,
        )

        by_id = {response["id"]: response for response in responses}
        self.assertEqual(by_id[6]["error"]["code"], -32602)
        self.assertEqual(by_id[7]["error"]["code"], -32602)
        self.assertNotIn("EXECUTED", json.dumps(responses))

    def test_null_arguments_notification_is_dropped_not_forwarded(self):
        responses = self.run_proxy(
            {
                "default_decision": "block",
                "rules": [{"tool": "email.send", "decision": "require_approval"}],
            },
            [
                {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {"name": "email.send", "arguments": None},
                }
            ],
            server=TOLERANT_SERVER,
        )

        self.assertEqual(responses, [])

    def test_jsonrpc_batch_is_rejected_not_forwarded(self):
        responses = self.run_proxy(
            {"default_decision": "block"},
            [
                [
                    {
                        "jsonrpc": "2.0",
                        "id": 10,
                        "method": "tools/call",
                        "params": {
                            "name": "email.send",
                            "arguments": {"to": "anyone@example.com"},
                        },
                    }
                ]
            ],
            server=TOLERANT_SERVER,
        )

        self.assertNotIn("EXECUTED", json.dumps(responses))
        self.assertEqual(len(responses), 1)
        batch = responses[0]
        self.assertIsInstance(batch, list)
        self.assertEqual(batch[0]["error"]["code"], -32600)
        self.assertEqual(batch[0]["id"], 10)

    def test_child_server_failure_fails_pending_call_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            policy_path = Path(directory) / "policy.json"
            policy_path.write_text('{"default_decision": "allow"}', encoding="utf-8")
            env = dict(os.environ)
            env["PYTHONPATH"] = str(ROOT / "src")
            # The wrapped server reads one line, then exits without answering.
            child = (
                "import sys; line = sys.stdin.readline(); sys.exit(1) if line else None"
            )
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
                    "-c",
                    child,
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
                "id": 7,
                "method": "tools/call",
                "params": {"name": "anything"},
            }
            stdout, stderr = process.communicate(json.dumps(request) + "\n", timeout=5)

        response = json.loads(stdout.splitlines()[0])
        self.assertEqual(response["id"], 7)
        self.assertIn("error", response)
        self.assertEqual(response["error"]["code"], -32003)

    def test_lifecycle_lines_reach_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            policy_path = Path(directory) / "policy.json"
            policy_path.write_text('{"default_decision": "block"}', encoding="utf-8")
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
                    "--request-timeout",
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
                "id": 1,
                "method": "initialize",
                "params": {},
            }
            stdout, stderr = process.communicate(json.dumps(request) + "\n", timeout=5)

        self.assertEqual(process.returncode, 0, stderr)
        self.assertIn("spawned", stderr)
        self.assertIn("child exited rc=0", stderr)

    def test_held_without_approver_prints_restart_hint_on_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            policy_path = Path(directory) / "policy.json"
            policy_path.write_text(
                json.dumps(
                    {
                        "default_decision": "block",
                        "rules": [
                            {
                                "tool": "anything",
                                "decision": "require_approval",
                            }
                        ],
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
                    "--request-timeout",
                    "2",
                    "--",
                    sys.executable,
                    str(TOLERANT_SERVER),
                ],
                cwd=ROOT,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            held = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "anything", "arguments": {}},
            }
            stdout, stderr = process.communicate(json.dumps(held) + "\n", timeout=5)

        response = json.loads(stdout.splitlines()[0])
        self.assertEqual(response["error"]["code"], -32001)
        self.assertIn("--approve-terminal", stderr)
        self.assertIn("--approve-web", stderr)

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

    def test_request_timeout_fails_call_closed(self):
        child = (
            "import sys,time; line = sys.stdin.readline(); time.sleep(0.5) "
            "if line else None"
        )
        with tempfile.TemporaryDirectory() as directory:
            policy_path = Path(directory) / "policy.json"
            policy_path.write_text('{"default_decision": "allow"}', encoding="utf-8")
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
                    "--request-timeout",
                    "0.2",
                    "--",
                    sys.executable,
                    "-c",
                    child,
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
                "id": 7,
                "method": "tools/call",
                "params": {"name": "anything", "arguments": {}},
            }
            stdout, stderr = process.communicate(json.dumps(request) + "\n", timeout=5)

        self.assertEqual(process.returncode, 0, stderr)
        response = json.loads(stdout.splitlines()[0])
        self.assertEqual(response["id"], 7)
        self.assertIn("error", response)
        self.assertEqual(response["error"]["code"], -32002)

    def test_late_response_after_timeout_is_discarded_and_proxy_stays_alive(self):
        with tempfile.TemporaryDirectory() as directory:
            policy_path = Path(directory) / "policy.json"
            policy_path.write_text('{"default_decision": "allow"}', encoding="utf-8")
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
                    "--request-timeout",
                    "0.2",
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
            slow = {
                "jsonrpc": "2.0",
                "id": "slow",
                "method": "tools/call",
                "params": {
                    "name": "database.query",
                    "arguments": {"delay_seconds": 1},
                },
            }
            fast = {
                "jsonrpc": "2.0",
                "id": "fast",
                "method": "tools/call",
                "params": {
                    "name": "database.query",
                    "arguments": {"sql": "select 2"},
                },
            }
            process.stdin.write(json.dumps(slow) + "\n")
            process.stdin.flush()
            timeout_response = json.loads(process.stdout.readline())
            self.assertEqual(timeout_response["id"], "slow")
            self.assertEqual(timeout_response["error"]["code"], -32002)
            # Give the child time to produce the late result for the timed-out
            # request; it must be discarded, never forwarded.
            time.sleep(1.2)
            process.stdin.write(json.dumps(fast) + "\n")
            process.stdin.flush()
            process.stdin.close()
            stdout = process.stdout.read()
            stderr = process.stderr.read()
            status = process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()

        self.assertEqual(status, 0, stderr)
        lines = [json.loads(line) for line in stdout.splitlines()]
        self.assertTrue(lines)
        # The remaining output must contain the follow-up result and never a
        # late result for the timed-out request (already answered with the
        # timeout error above).
        self.assertNotIn("slow", {line.get("id") for line in lines})
        fast_lines = [line for line in lines if line.get("id") == "fast"]
        self.assertEqual(len(fast_lines), 1)
        self.assertIn("result", fast_lines[0])

    def test_duplicate_key_child_response_is_dropped_and_request_fails_closed(self):
        dup_child = (
            "import json,sys\n"
            "for line in sys.stdin:\n"
            "    try:\n"
            "        m = json.loads(line)\n"
            "    except Exception:\n"
            "        continue\n"
            "    if not isinstance(m, dict) or 'id' not in m:\n"
            "        continue\n"
            "    rid = json.dumps(m['id'])\n"
            "    params = m.get('params')\n"
            "    clean = isinstance(params, dict) and params.get('mode') == 'clean'\n"
            "    if clean:\n"
            '        body = \'{"jsonrpc":"2.0","id":%s,"result":{"r":1}}\' % rid\n'
            "    else:\n"
            '        body = (\'{"jsonrpc":"2.0","id":%s,"result":{"r":1},\'\n'
            '                \'"result":{"r":2}}\') % rid\n'
            "    sys.stdout.write(body + '\\n')\n"
            "    sys.stdout.flush()\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            policy_path = Path(directory) / "policy.json"
            policy_path.write_text('{"default_decision": "allow"}', encoding="utf-8")
            child_path = Path(directory) / "dup_child.py"
            child_path.write_text(dup_child, encoding="utf-8")
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
                    "--request-timeout",
                    "0.3",
                    "--",
                    sys.executable,
                    str(child_path),
                ],
                cwd=ROOT,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            ambiguous = {
                "jsonrpc": "2.0",
                "id": "amb",
                "method": "tools/call",
                "params": {"name": "database.query", "arguments": {}},
            }
            process.stdin.write(json.dumps(ambiguous) + "\n")
            process.stdin.flush()
            timeout_response = json.loads(process.stdout.readline())
            self.assertEqual(timeout_response["id"], "amb")
            self.assertEqual(timeout_response["error"]["code"], -32002)
            clean = {
                "jsonrpc": "2.0",
                "id": "clean",
                "method": "tools/call",
                "params": {"name": "database.query", "mode": "clean"},
            }
            process.stdin.write(json.dumps(clean) + "\n")
            process.stdin.flush()
            process.stdin.close()
            stdout = process.stdout.read()
            stderr = process.stderr.read()
            status = process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()

        self.assertEqual(status, 0, stderr)
        lines = [json.loads(line) for line in stdout.splitlines()]
        self.assertNotIn("agent-firewall:", stdout)
        by_id = {line.get("id"): line for line in lines}
        self.assertIn("clean", by_id)
        self.assertIn("result", by_id["clean"])
        # The ambiguous response was dropped, never forwarded after the
        # timeout error was already answered above.
        self.assertNotIn("amb", {line.get("id") for line in lines})

    def test_client_can_reuse_id_after_timeout_without_accepting_late_response(self):
        with tempfile.TemporaryDirectory() as directory:
            policy_path = Path(directory) / "policy.json"
            policy_path.write_text('{"default_decision": "allow"}', encoding="utf-8")
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
                    "--request-timeout",
                    "0.2",
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
            slow = {
                "jsonrpc": "2.0",
                "id": "reused",
                "method": "tools/call",
                "params": {
                    "name": "database.query",
                    "arguments": {"delay_seconds": 0.3},
                },
            }
            fast = {
                "jsonrpc": "2.0",
                "id": "reused",
                "method": "tools/call",
                "params": {
                    "name": "database.query",
                    "arguments": {"sql": "select 2"},
                },
            }
            process.stdin.write(json.dumps(slow) + "\n")
            process.stdin.flush()
            timeout_response = json.loads(process.stdout.readline())
            self.assertEqual(timeout_response["error"]["code"], -32002)
            process.stdin.write(json.dumps(fast) + "\n")
            process.stdin.flush()
            reused_response = json.loads(process.stdout.readline())
            process.stdin.close()
            stderr = process.stderr.read()
            status = process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()

        self.assertEqual(status, 0, stderr)
        self.assertEqual(reused_response["id"], "reused")
        self.assertIn("result", reused_response)

    def test_invalid_cost_is_rejected_and_not_forwarded(self):
        responses = self.run_proxy(
            {"default_decision": "allow"},
            [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "email.send",
                        "arguments": {"to": "a@b.c"},
                        "_meta": {"estimated_cost_usd": "not-a-number"},
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "email.send",
                        "arguments": {"to": "a@b.c"},
                        "_meta": {"estimated_cost_usd": "-1"},
                    },
                },
            ],
            server=TOLERANT_SERVER,
        )

        by_id = {response["id"]: response for response in responses}
        self.assertEqual(by_id[1]["error"]["code"], -32602)
        self.assertEqual(by_id[2]["error"]["code"], -32602)
        self.assertNotIn("EXECUTED", json.dumps(responses))

    def test_invalid_cost_notification_is_dropped_not_forwarded(self):
        responses = self.run_proxy(
            {"default_decision": "allow"},
            [
                {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "name": "email.send",
                        "arguments": {"to": "a@b.c"},
                        "_meta": {"estimated_cost_usd": "nan"},
                    },
                }
            ],
            server=TOLERANT_SERVER,
        )

        self.assertEqual(responses, [])

    def test_cost_budget_blocks_without_reaching_child(self):
        responses = self.run_proxy(
            {"default_decision": "allow", "budget": {"max_cost_usd": "0.01"}},
            [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "database.query",
                        "arguments": {"sql": "select 1"},
                        "_meta": {"estimated_cost_usd": "0.02"},
                    },
                }
            ],
            server=TOLERANT_SERVER,
        )

        error = responses[0]["error"]
        self.assertEqual(error["code"], -32001)
        self.assertEqual(error["data"]["code"], "max_cost_usd")
        self.assertNotIn("EXECUTED", json.dumps(responses))

    def test_absent_cost_defaults_to_zero(self):
        responses = self.run_proxy(
            {"default_decision": "allow", "budget": {"max_cost_usd": "0.01"}},
            [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "database.query",
                        "arguments": {"sql": "select 1"},
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "database.query",
                        "arguments": {"sql": "select 2"},
                        "_meta": {"trace_id": "abc"},
                    },
                },
            ],
        )

        self.assertIn("result", responses[0])
        self.assertIn("result", responses[1])

    def test_meta_with_cost_and_other_keys_is_forwarded_unchanged(self):
        responses = self.run_proxy(
            {"default_decision": "allow"},
            [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "database.query",
                        "arguments": {"sql": "select 1"},
                        "_meta": {
                            "estimated_cost_usd": "0.005",
                            "session": "abc",
                        },
                    },
                }
            ],
            child_command=[sys.executable, "-c", ECHO_META_CHILD],
        )

        echoed = json.loads(responses[0]["result"]["content"][0]["text"])
        self.assertEqual(
            echoed["meta"],
            {"estimated_cost_usd": "0.005", "session": "abc"},
        )


if __name__ == "__main__":
    unittest.main()
