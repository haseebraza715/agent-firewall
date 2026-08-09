"""End-to-end integration tests.

Exercises the full firewall decision pipeline (policy file + SQLite state +
JSONL audit + approver), policy reload with persistent state, CLI flag
coverage and error paths, and the MCP proxy's line-size and nesting limits.
"""

import asyncio
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from agent_firewall import (
    Firewall,
    Policy,
    PolicyConfigError,
    ToolCall,
    ToolCallBlocked,
)
from agent_firewall.cli import main

ROOT = Path(__file__).resolve().parents[1]
FAKE_SERVER = ROOT / "tests" / "fixtures" / "fake_mcp_server.py"


class FirewallPipelineTests(unittest.TestCase):
    def _setup(self, policy_dict, approver=None, audit_mode=None):
        directory = tempfile.TemporaryDirectory()
        root = Path(directory.name)
        policy_path = root / "policy.json"
        if audit_mode is not None:
            policy_dict = dict(policy_dict)
            policy_dict["audit_arguments"] = audit_mode
        policy_path.write_text(json.dumps(policy_dict), encoding="utf-8")
        state_path = root / "state.db"
        audit_path = root / "audit.jsonl"
        firewall = Firewall.from_policy_file(
            policy_path,
            approver=approver,
            audit_path=audit_path,
            state_path=state_path,
        )
        return directory, firewall, state_path, audit_path

    def test_full_pipeline_allow_execute_and_audit(self):
        directory, firewall, _, audit_path = self._setup(
            {"default_decision": "block",
             "rules": [{"tool": "math.add", "decision": "allow"}]}
        )
        with directory:
            result = firewall.call("math.add", lambda a, b: a + b, 1, 2)
            self.assertEqual(result, 3)
            self.assertEqual(firewall.usage.tool_calls, 1)
            entries = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(
                [entry["event"] for entry in entries], ["allowed", "executed"]
            )
            self.assertNotIn("arguments", entries[0])

    def test_full_pipeline_block_never_executes_and_audits(self):
        directory, firewall, _, audit_path = self._setup(
            {"default_decision": "block"}
        )
        with directory:
            executed = []
            with self.assertRaises(ToolCallBlocked):
                firewall.call("unknown.tool", lambda: executed.append(True))
            self.assertEqual(executed, [])
            self.assertEqual(firewall.usage.tool_calls, 0)
            entries = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual([entry["event"] for entry in entries], ["blocked"])

    def test_full_pipeline_approval_granted_executes(self):
        directory, firewall, _, audit_path = self._setup(
            {"default_decision": "block",
             "rules": [{"tool": "email.send", "decision": "require_approval"}]},
            approver=lambda call, decision: True,
        )
        with directory:
            result = firewall.call("email.send", lambda: "sent")
            self.assertEqual(result, "sent")
            self.assertEqual(firewall.usage.tool_calls, 1)
            events = [
                json.loads(line)["event"]
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(
                events, ["approval_requested", "approval_granted", "executed"]
            )

    def test_budget_exhausted_between_request_and_approval_blocks(self):
        directory, firewall, _, audit_path = self._setup(
            {
                "default_decision": "block",
                "budget": {"max_calls": 1},
                "rules": [{"tool": "email.send", "decision": "require_approval"}],
            },
            approver=lambda call, decision: True,
        )
        with directory:
            firewall.state_store.evaluate_and_reserve(
                Policy.from_dict({"default_decision": "allow"}),
                ToolCall.create("other.tool"),
            )
            with self.assertRaisesRegex(ToolCallBlocked, "budget"):
                firewall.call(
                    "email.send",
                    lambda: "never",
                    estimated_cost_usd=0,
                )
            events = [
                json.loads(line)["event"]
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(events[-1], "blocked")

    def test_async_pipeline_with_audit_and_state(self):
        directory, firewall, _, audit_path = self._setup(
            {"default_decision": "block",
             "rules": [{"tool": "math.add", "decision": "allow"}]}
        )
        with directory:
            async def run():
                return await firewall.acall(
                    "math.add", lambda a, b: a + b, 20, 22
                )

            self.assertEqual(asyncio.run(run()), 42)
            self.assertEqual(firewall.usage.tool_calls, 1)

    def test_async_approver_via_acall(self):
        directory, firewall, _, _ = self._setup(
            {"default_decision": "block",
             "rules": [{"tool": "email.send", "decision": "require_approval"}]},
            approver=None,
        )
        with directory:
            firewall.approver = _AsyncTrue()
            result = asyncio.run(
                firewall.acall("email.send", lambda: "sent")
            )
            self.assertEqual(result, "sent")

    def test_sync_call_with_async_approver_raises_type_error(self):
        directory, firewall, _, _ = self._setup(
            {"default_decision": "block",
             "rules": [{"tool": "email.send", "decision": "require_approval"}]},
            approver=None,
        )
        with directory:
            firewall.approver = _AsyncTrue()
            with self.assertRaisesRegex(TypeError, "async approver"):
                firewall.call("email.send", lambda: "never")

    def test_failed_tool_call_is_audited_and_consumes_budget(self):
        directory, firewall, _, audit_path = self._setup(
            {"default_decision": "block",
             "rules": [{"tool": "math.add", "decision": "allow"}]}
        )
        with directory:
            def boom():
                raise RuntimeError("boom")

            with self.assertRaisesRegex(RuntimeError, "boom"):
                firewall.call("math.add", boom)
            self.assertEqual(firewall.usage.tool_calls, 1)
            events = [
                json.loads(line)["event"]
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(events[-1], "failed")
            self.assertIn("error", json.loads(
                audit_path.read_text(encoding="utf-8").splitlines()[-1]
            ))

    def test_full_hash_audit_mode_pipeline(self):
        directory, firewall, _, audit_path = self._setup(
            {"default_decision": "block",
             "rules": [{"tool": "search", "decision": "allow"}]},
            audit_mode="hash",
        )
        with directory:
            firewall.call("search", lambda q: q, q="secret query")
            entry = json.loads(
                audit_path.read_text(encoding="utf-8").splitlines()[0]
            )
            self.assertEqual(entry["event"], "allowed")
            self.assertEqual(len(entry["call_fingerprint"]), 64)
            self.assertNotIn("secret query", json.dumps(entry))


class _AsyncTrue:
    async def __call__(self, call, decision):
        return True


class PolicyReloadTests(unittest.TestCase):
    def test_new_firewall_picks_up_policy_but_keeps_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "policy.json"
            state_path = root / "state.db"
            audit_path = root / "audit.jsonl"
            policy_path.write_text(
                json.dumps(
                    {"default_decision": "block",
                     "rules": [{"tool": "demo.tool", "decision": "allow"}]}
                ),
                encoding="utf-8",
            )
            first = Firewall.from_policy_file(
                policy_path, audit_path=audit_path, state_path=state_path
            )
            first.call("demo.tool", lambda: "first")
            self.assertEqual(first.usage.tool_calls, 1)

            policy_path.write_text(
                json.dumps({"default_decision": "block"}),
                encoding="utf-8",
            )
            second = Firewall.from_policy_file(
                policy_path, audit_path=audit_path, state_path=state_path
            )
            with self.assertRaises(ToolCallBlocked):
                second.call("demo.tool", lambda: "second")
            self.assertEqual(second.usage.tool_calls, 1)

    def test_invalid_replacement_policy_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "policy.json"
            policy_path.write_text('{"default_decision": "block"}', encoding="utf-8")
            Firewall.from_policy_file(policy_path)
            policy_path.write_text(
                '{"default_decision": "block", "bogus_key": true}',
                encoding="utf-8",
            )
            with self.assertRaises(PolicyConfigError):
                Firewall.from_policy_file(policy_path)

    def test_policy_reload_preserves_identical_call_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "policy.json"
            state_path = root / "state.db"
            policy_path.write_text(
                json.dumps(
                    {"default_decision": "allow",
                     "budget": {"max_identical_calls": 1}}
                ),
                encoding="utf-8",
            )
            first = Firewall.from_policy_file(policy_path, state_path=state_path)
            first.call("search", lambda query: query, query="same")
            policy_path.write_text(
                json.dumps(
                    {"default_decision": "allow",
                     "budget": {"max_identical_calls": 1}}
                ),
                encoding="utf-8",
            )
            second = Firewall.from_policy_file(policy_path, state_path=state_path)
            with self.assertRaisesRegex(ToolCallBlocked, "identical"):
                second.call("search", lambda query: query, query="same")


class CliFlagTests(unittest.TestCase):
    def _policy(self, root, text='{"default_decision": "block"}'):
        policy_path = root / "policy.json"
        policy_path.write_text(text, encoding="utf-8")
        return policy_path

    def test_check_invalid_cost_exits_two(self):
        with tempfile.TemporaryDirectory() as directory:
            policy_path = self._policy(Path(directory))
            with redirect_stderr(io.StringIO()) as stderr:
                status = main(
                    ["check", "--policy", str(policy_path), "--tool", "x",
                     "--cost", "not-a-number"]
                )
            self.assertEqual(status, 2)
            self.assertIn("cost", stderr.getvalue())

    def test_check_non_object_arguments_exit_two(self):
        with tempfile.TemporaryDirectory() as directory:
            policy_path = self._policy(Path(directory))
            with redirect_stderr(io.StringIO()):
                status = main(
                    ["check", "--policy", str(policy_path), "--tool", "x",
                     "--arguments", "[1, 2]"]
                )
            self.assertEqual(status, 2)

    def test_check_malformed_json_arguments_exit_two(self):
        with tempfile.TemporaryDirectory() as directory:
            policy_path = self._policy(Path(directory))
            with redirect_stderr(io.StringIO()):
                status = main(
                    ["check", "--policy", str(policy_path), "--tool", "x",
                     "--arguments", "{not json"]
                )
            self.assertEqual(status, 2)

    def test_check_deeply_nested_arguments_exit_two(self):
        with tempfile.TemporaryDirectory() as directory:
            policy_path = self._policy(Path(directory))
            deep = "[" * 50000 + "1" + "]" * 50000
            with redirect_stderr(io.StringIO()):
                status = main(
                    ["check", "--policy", str(policy_path), "--tool", "x",
                     "--arguments", deep]
                )
            self.assertEqual(status, 2)

    def test_replay_non_list_scenarios_exit_two(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = self._policy(root)
            scenarios = root / "scenarios.json"
            scenarios.write_text('{"not": "a list"}', encoding="utf-8")
            with redirect_stderr(io.StringIO()):
                status = main(
                    ["replay", "--policy", str(policy_path),
                     "--scenarios", str(scenarios)]
                )
            self.assertEqual(status, 2)

    def test_replay_bad_scenario_call_exit_two(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = self._policy(root)
            scenarios = root / "scenarios.json"
            scenarios.write_text(
                json.dumps([{"id": "x", "calls": [{"tool": 5}],
                             "expected_decisions": ["block"]}]),
                encoding="utf-8",
            )
            with redirect_stderr(io.StringIO()):
                status = main(
                    ["replay", "--policy", str(policy_path),
                     "--scenarios", str(scenarios)]
                )
            self.assertEqual(status, 2)

    def test_benchmark_failing_threshold_exits_five(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "policy.json"
            cases_path = root / "cases.json"
            output = root / "reports"
            policy_path.write_text(
                json.dumps({"default_decision": "allow"}), encoding="utf-8"
            )
            cases_path.write_text(
                json.dumps(
                    [
                        {
                            "id": "unsafe",
                            "category": "dangerous",
                            "provenance": "synthetic",
                            "calls": [{"tool": "rm", "arguments": {}}],
                            "expected_decisions": ["block"],
                        }
                    ]
                ),
                encoding="utf-8",
            )
            with redirect_stdout(io.StringIO()) as output_stream:
                status = main(
                    [
                        "benchmark",
                        "--policy", str(policy_path),
                        "--cases", str(cases_path),
                        "--output", str(output),
                        "--min-intervention-recall", "1.0",
                    ]
                )
            self.assertEqual(status, 5)
            self.assertIn("intervention_recall", output_stream.getvalue())
            self.assertTrue((output / "report.json").exists())
            self.assertTrue((output / "report.md").exists())

    def test_benchmark_met_threshold_exits_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "policy.json"
            cases_path = root / "cases.json"
            output = root / "reports"
            policy_path.write_text(
                json.dumps({"default_decision": "block"}), encoding="utf-8"
            )
            cases_path.write_text(
                json.dumps(
                    [
                        {
                            "id": "unsafe",
                            "category": "dangerous",
                            "provenance": "synthetic",
                            "calls": [{"tool": "rm", "arguments": {}}],
                            "expected_decisions": ["block"],
                        }
                    ]
                ),
                encoding="utf-8",
            )
            with redirect_stdout(io.StringIO()):
                status = main(
                    [
                        "benchmark",
                        "--policy", str(policy_path),
                        "--cases", str(cases_path),
                        "--output", str(output),
                        "--min-intervention-recall", "1.0",
                    ]
                )
            self.assertEqual(status, 0)

    def test_threshold_out_of_range_is_rejected(self):
        from agent_firewall.cli import build_parser

        with self.assertRaises(SystemExit) as raised:
            build_parser().parse_args(
                ["benchmark", "--policy", "p", "--cases", "c",
                 "--output", "o", "--min-intervention-recall", "1.5"]
            )
        self.assertEqual(raised.exception.code, 2)

    def test_mcp_approval_flags_are_mutually_exclusive(self):
        from agent_firewall.cli import build_parser

        with self.assertRaises(SystemExit) as raised:
            build_parser().parse_args(
                ["mcp", "--policy", "p", "--approve-terminal",
                 "--approve-web", "--state", "s", "--", "echo"]
            )
        self.assertEqual(raised.exception.code, 2)

    def test_max_line_bytes_flag(self):
        from agent_firewall.cli import build_parser

        args = build_parser().parse_args(
            ["mcp", "--policy", "p", "--max-line-bytes", "4096", "--", "echo"]
        )
        self.assertEqual(args.max_line_bytes, 4096)
        with self.assertRaises(SystemExit) as raised:
            build_parser().parse_args(
                ["mcp", "--policy", "p", "--max-line-bytes", "0", "--", "echo"]
            )
        self.assertEqual(raised.exception.code, 2)

    def test_dashboard_rejects_non_loopback_host(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = self._policy(root)
            audit_path = root / "audit.jsonl"
            state_path = root / "state.db"
            audit_path.write_text("", encoding="utf-8")
            with redirect_stderr(io.StringIO()):
                status = main(
                    ["dashboard", "--policy", str(policy_path),
                     "--audit", str(audit_path),
                     "--state", str(state_path),
                     "--host", "0.0.0.0"]
                )
            self.assertEqual(status, 2)

    def test_explain_malformed_arguments_exit_two(self):
        with tempfile.TemporaryDirectory() as directory:
            policy_path = self._policy(Path(directory))
            with redirect_stderr(io.StringIO()):
                status = main(
                    ["policy", "explain", "--policy", str(policy_path),
                     "--tool", "x", "--arguments", "nope"]
                )
            self.assertEqual(status, 2)

    def test_doctor_missing_policy_reports_failure(self):
        with redirect_stderr(io.StringIO()):
            status = main(
                ["doctor", "--policy", "/nonexistent/policy.json"]
            )
        self.assertEqual(status, 1)

    def test_lint_deeply_nested_policy_exits_two(self):
        with tempfile.TemporaryDirectory() as directory:
            policy_path = Path(directory) / "policy.json"
            policy_path.write_text("[" * 50000 + "1" + "]" * 50000, encoding="utf-8")
            with redirect_stderr(io.StringIO()):
                status = main(
                    ["policy", "lint", "--policy", str(policy_path)]
                )
            self.assertEqual(status, 2)


class McpProxyHardeningTests(unittest.TestCase):
    def run_proxy(self, policy, messages, extra_flags=None, server=FAKE_SERVER):
        with tempfile.TemporaryDirectory() as directory:
            policy_path = Path(directory) / "policy.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            env = dict(os.environ)
            env["PYTHONPATH"] = str(ROOT / "src")
            command = [
                sys.executable, "-m", "agent_firewall", "mcp",
                "--policy", str(policy_path),
                "--request-timeout", "3",
            ]
            if extra_flags:
                command.extend(extra_flags)
            command.extend(["--", sys.executable, str(server)])
            process = subprocess.Popen(
                command,
                cwd=ROOT,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            payload = b"".join(messages)
            stdout, stderr = process.communicate(payload, timeout=10)
        return process.returncode, stdout, stderr

    def test_oversized_client_line_is_rejected_and_proxy_survives(self):
        big_line = (
            b'{"jsonrpc":"2.0","id":1,"method":"tools/call",'
            b'"params":{"name":"x","arguments":{"data":"'
            + b"a" * 4096
            + b'"}}}\n'
        )
        valid = (
            b'{"jsonrpc":"2.0","id":2,"method":"tools/call",'
            b'"params":{"name":"database.query","arguments":{"sql":"select 1"}}}\n'
        )
        rc, stdout, stderr = self.run_proxy(
            {"default_decision": "block",
             "rules": [{"tool": "database.query", "decision": "allow"}]},
            [big_line, valid],
            extra_flags=["--max-line-bytes", "1024"],
        )
        self.assertEqual(rc, 0, stderr.decode())
        responses = [json.loads(line) for line in stdout.splitlines()]
        self.assertEqual(responses[0]["error"]["code"], -32700)
        self.assertEqual(responses[1]["id"], 2)
        self.assertIn("result", responses[1])

    def test_deeply_nested_client_message_is_rejected_and_proxy_survives(self):
        deep = (
            b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":'
            + b'{"a":' * 20000 + b"1" + b"}" * 20000 + b"}\n"
        )
        valid = (
            b'{"jsonrpc":"2.0","id":2,"method":"tools/call",'
            b'"params":{"name":"database.query","arguments":{"sql":"select 1"}}}\n'
        )
        rc, stdout, stderr = self.run_proxy(
            {"default_decision": "block",
             "rules": [{"tool": "database.query", "decision": "allow"}]},
            [deep, valid],
        )
        self.assertEqual(rc, 0, stderr.decode())
        responses = [json.loads(line) for line in stdout.splitlines()]
        self.assertEqual(responses[0]["error"]["code"], -32700)
        self.assertEqual(responses[1]["id"], 2)
        self.assertIn("result", responses[1])

    def test_oversized_child_line_is_dropped_and_proxy_survives(self):
        noisy_child = (
            "import json,sys\n"
            "print('x' * 4096)\n"
            "for line in sys.stdin:\n"
            "    m=json.loads(line)\n"
            "    if 'id' not in m: continue\n"
            "    print(json.dumps({'jsonrpc':'2.0','id':m['id'],\n"
            "        'result':{}}),flush=True)\n"
        )
        child_script = Path(tempfile.mkdtemp()) / "noisy_server.py"
        child_script.write_text(noisy_child, encoding="utf-8")
        valid = (
            b'{"jsonrpc":"2.0","id":1,"method":"tools/call",'
            b'"params":{"name":"database.query","arguments":{"sql":"select 1"}}}\n'
        )
        rc, stdout, stderr = self.run_proxy(
            {"default_decision": "block",
             "rules": [{"tool": "database.query", "decision": "allow"}]},
            [valid],
            extra_flags=["--max-line-bytes", "1024"],
            server=child_script,
        )
        self.assertEqual(rc, 0, stderr.decode())
        responses = [json.loads(line) for line in stdout.splitlines()]
        self.assertEqual(len(responses), 1)
        self.assertEqual(responses[0]["id"], 1)
        self.assertIn("result", responses[0])

    def test_oversized_line_without_oversized_flag_is_accepted(self):
        big_line = (
            b'{"jsonrpc":"2.0","id":1,"method":"tools/call",'
            b'"params":{"name":"database.query","arguments":{"sql":"'
            + b"a" * 4096 + b'"}}}\n'
        )
        rc, stdout, stderr = self.run_proxy(
            {"default_decision": "block",
             "rules": [{"tool": "database.query", "decision": "allow"}]},
            [big_line],
        )
        self.assertEqual(rc, 0, stderr.decode())
        responses = [json.loads(line) for line in stdout.splitlines()]
        self.assertEqual(responses[0]["id"], 1)
        self.assertIn("result", responses[0])

    def test_invalid_cost_rejects_call_fail_closed(self):
        message = (
            b'{"jsonrpc":"2.0","id":1,"method":"tools/call",'
            b'"params":{"name":"database.query","arguments":{"sql":"select 1"},'
            b'"_meta":{"estimated_cost_usd":"abc"}}}\n'
        )
        rc, stdout, stderr = self.run_proxy(
            {"default_decision": "block",
             "rules": [{"tool": "database.query", "decision": "allow"}]},
            [message],
        )
        self.assertEqual(rc, 0, stderr.decode())
        responses = [json.loads(line) for line in stdout.splitlines()]
        self.assertEqual(responses[0]["error"]["code"], -32602)

    def test_blocked_call_is_never_forwarded(self):
        message = (
            b'{"jsonrpc":"2.0","id":1,"method":"tools/call",'
            b'"params":{"name":"evil.tool","arguments":{}}}\n'
        )
        rc, stdout, stderr = self.run_proxy(
            {"default_decision": "block"},
            [message],
        )
        self.assertEqual(rc, 0, stderr.decode())
        responses = [json.loads(line) for line in stdout.splitlines()]
        self.assertEqual(responses[0]["error"]["code"], -32001)
        self.assertIn("decision", responses[0]["error"]["data"])

    def test_malformed_tools_call_line_is_rejected_not_forwarded(self):
        """A line that fails to parse must not reach the wrapped server: a
        lenient server might salvage a tools/call out of it and execute it
        without a policy decision."""
        malformed = (
            b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":'
            b'{"name":"database.query","arguments":{"sql":"select "}}\n'
        )
        valid = (
            b'{"jsonrpc":"2.0","id":2,"method":"tools/call",'
            b'"params":{"name":"database.query","arguments":{"sql":"select 1"}}}\n'
        )
        rc, stdout, stderr = self.run_proxy(
            {"default_decision": "block",
             "rules": [{"tool": "database.query", "decision": "allow"}]},
            [malformed, valid],
        )
        self.assertEqual(rc, 0, stderr.decode())
        responses = [json.loads(line) for line in stdout.splitlines()]
        self.assertEqual(len(responses), 2)
        self.assertEqual(responses[0]["error"]["code"], -32700)
        self.assertEqual(responses[1]["id"], 2)
        self.assertIn("result", responses[1])

    def test_non_object_line_is_rejected_not_forwarded(self):
        rc, stdout, stderr = self.run_proxy(
            {"default_decision": "block",
             "rules": [{"tool": "database.query", "decision": "allow"}]},
            [b'"just a string"\n'],
        )
        self.assertEqual(rc, 0, stderr.decode())
        responses = [json.loads(line) for line in stdout.splitlines()]
        self.assertEqual(responses[0]["error"]["code"], -32700)

    def test_blank_lines_are_ignored(self):
        valid = (
            b'{"jsonrpc":"2.0","id":1,"method":"tools/call",'
            b'"params":{"name":"database.query","arguments":{"sql":"select 1"}}}\n'
        )
        rc, stdout, stderr = self.run_proxy(
            {"default_decision": "block",
             "rules": [{"tool": "database.query", "decision": "allow"}]},
            [b"\n", b"\n", valid],
        )
        self.assertEqual(rc, 0, stderr.decode())
        responses = [json.loads(line) for line in stdout.splitlines()]
        self.assertEqual(len(responses), 1)
        self.assertEqual(responses[0]["id"], 1)

    def test_deeply_nested_batch_is_dropped(self):
        deep_batch = b"[" * 50000 + b"1" + b"]" * 50000 + b"\n"
        valid = (
            b'{"jsonrpc":"2.0","id":1,"method":"tools/call",'
            b'"params":{"name":"database.query","arguments":{"sql":"select 1"}}}\n'
        )
        rc, stdout, stderr = self.run_proxy(
            {"default_decision": "block",
             "rules": [{"tool": "database.query", "decision": "allow"}]},
            [deep_batch, valid],
        )
        self.assertEqual(rc, 0, stderr.decode())
        responses = [json.loads(line) for line in stdout.splitlines()]
        self.assertEqual(len(responses), 2)
        self.assertEqual(responses[0]["error"]["code"], -32700)
        self.assertEqual(responses[1]["id"], 1)


if __name__ == "__main__":
    unittest.main()
