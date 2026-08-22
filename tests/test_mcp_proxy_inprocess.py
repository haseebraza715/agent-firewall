"""In-process unit tests for the MCP proxy's decision paths.

The subprocess tests in test_mcp_proxy.py exercise the proxy end to end; these
tests drive ``_handle_client_line`` directly so the proxy's branches are also
covered when coverage is measured in the test process.
"""

import asyncio
import io
import json
import unittest
from contextlib import redirect_stderr
from unittest.mock import AsyncMock, patch

from agent_firewall import Firewall, Policy
from agent_firewall.jsonrpc import encode_message, request_key
from agent_firewall.mcp_proxy import McpStdioProxy, TerminalApprover
from agent_firewall.models import Decision, DecisionKind, ToolCall


def _proxy(policy_dict, **kwargs):
    firewall = Firewall(Policy.from_dict(policy_dict))
    return McpStdioProxy(firewall, ["unused"], **kwargs)


def _call(proxy, message):
    captured = {}

    def record(value):
        captured["written"] = value

    with patch.object(proxy, "_write_client", side_effect=record):
        asyncio.run(proxy._handle_client_line(encode_message(message)))
    return captured.get("written")


class InProcessProxyTests(unittest.TestCase):
    def test_blocked_tools_call_writes_policy_error(self):
        proxy = _proxy({"default_decision": "block"})
        written = _call(
            proxy,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "evil.tool", "arguments": {}},
            },
        )
        self.assertEqual(written["error"]["code"], -32001)
        self.assertEqual(written["error"]["data"]["decision"], "block")

    def test_tools_call_without_params_is_rejected(self):
        proxy = _proxy({"default_decision": "allow"})
        written = _call(
            proxy,
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call"},
        )
        self.assertEqual(written["error"]["code"], -32602)

    def test_tools_call_with_non_string_name_is_rejected(self):
        proxy = _proxy({"default_decision": "allow"})
        written = _call(
            proxy,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": 5, "arguments": {}},
            },
        )
        self.assertEqual(written["error"]["code"], -32602)

    def test_tools_call_with_null_name_is_rejected(self):
        proxy = _proxy({"default_decision": "allow"})
        written = _call(
            proxy,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": None, "arguments": {}},
            },
        )
        self.assertEqual(written["error"]["code"], -32602)

    def test_blocked_tools_call_notification_is_dropped(self):
        proxy = _proxy({"default_decision": "block"})
        written = _call(
            proxy,
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "evil.tool", "arguments": {}},
            },
        )
        self.assertIsNone(written)

    def test_invalid_cost_rejects_call(self):
        proxy = _proxy({"default_decision": "allow"})
        written = _call(
            proxy,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "demo.tool",
                    "arguments": {},
                    "_meta": {"estimated_cost_usd": "oops"},
                },
            },
        )
        self.assertEqual(written["error"]["code"], -32602)

    def test_over_cap_cost_is_rejected_as_params_error(self):
        proxy = _proxy({"default_decision": "allow"})
        written = _call(
            proxy,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "demo.tool",
                    "arguments": {},
                    "_meta": {"estimated_cost_usd": "1e300"},
                },
            },
        )
        self.assertEqual(written["error"]["code"], -32602)
        self.assertIn("estimated_cost_usd", written["error"]["message"])

    def test_negative_cost_rejects_call(self):
        proxy = _proxy({"default_decision": "allow"})
        written = _call(
            proxy,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "demo.tool",
                    "arguments": {},
                    "_meta": {"estimated_cost_usd": "-1"},
                },
            },
        )
        self.assertEqual(written["error"]["code"], -32602)

    def test_blocked_call_does_not_reserve_budget(self):
        policy = {"default_decision": "block", "budget": {"max_calls": 1}}
        proxy = _proxy(policy)
        _call(
            proxy,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "evil.tool", "arguments": {}},
            },
        )
        self.assertEqual(proxy.firewall.usage.tool_calls, 0)

    def test_undecodable_line_is_rejected_not_forwarded(self):
        proxy = _proxy({"default_decision": "allow"})
        written = {}

        def record(value):
            written["value"] = value

        with patch.object(proxy, "_write_client", side_effect=record):
            asyncio.run(proxy._handle_client_line(b"{not json\n"))
        self.assertEqual(written["value"]["error"]["code"], -32700)

    def test_deeply_nested_line_is_rejected_not_forwarded(self):
        proxy = _proxy({"default_decision": "allow"})
        written = {}

        def record(value):
            written["value"] = value

        deep = b'{"a":' * 20000 + b"1" + b"}" * 20000 + b"}\n"
        with patch.object(proxy, "_write_client", side_effect=record):
            asyncio.run(proxy._handle_client_line(deep))
        self.assertEqual(written["value"]["error"]["code"], -32700)

    def test_duplicate_key_line_names_the_reason(self):
        proxy = _proxy({"default_decision": "allow"})
        written = {}

        def record(value):
            written["value"] = value

        line = (
            b'{"jsonrpc":"2.0","id":6,"method":"tools/call",'
            b'"params":{"name":"t","a":1,"a":2}}\n'
        )
        with patch.object(proxy, "_write_client", side_effect=record):
            asyncio.run(proxy._handle_client_line(line))
        self.assertEqual(written["value"]["error"]["code"], -32700)
        self.assertIn("duplicate key", written["value"]["error"]["message"])

    def test_blank_line_is_ignored(self):
        proxy = _proxy({"default_decision": "allow"})
        written = {}

        def record(value):
            written["value"] = value

        with patch.object(proxy, "_write_client", side_effect=record):
            asyncio.run(proxy._handle_client_line(b"\n"))
        self.assertNotIn("value", written)

    def test_duplicate_in_flight_id_is_rejected(self):
        proxy = _proxy({"default_decision": "allow"})
        message = {
            "jsonrpc": "2.0",
            "id": "dup",
            "method": "tools/call",
            "params": {"name": "demo.tool", "arguments": {}},
        }
        proxy._client_pending.add(request_key("dup"))
        written = _call(proxy, message)
        self.assertEqual(written["error"]["code"], -32600)
        self.assertEqual(proxy.firewall.usage.tool_calls, 0)

    def test_duplicate_non_tool_request_is_rejected(self):
        proxy = _proxy({"default_decision": "allow"})
        message = {
            "jsonrpc": "2.0",
            "id": "dup",
            "method": "initialize",
            "params": {},
        }
        proxy._client_pending.add(request_key("dup"))
        written = _call(proxy, message)
        self.assertEqual(written["error"]["code"], -32600)

    def test_deep_response_gets_parse_error_fallback(self):
        proxy = _proxy({"default_decision": "allow"})
        captured = {}

        def record_bytes(payload):
            captured["payload"] = payload

        deep_value = []
        node = deep_value
        for _ in range(20000):
            child = []
            node.append(child)
            node = child
        node.append(1)
        message = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": deep_value},
        }
        with patch.object(
            McpStdioProxy, "_write_client_bytes", side_effect=record_bytes
        ):
            proxy._write_client(message)
        response = json.loads(captured["payload"])
        self.assertEqual(response["error"]["code"], -32700)

    def test_reject_batch_answers_each_id(self):
        proxy = _proxy({"default_decision": "block"})
        captured = {}

        def record_bytes(payload):
            captured["payload"] = payload

        batch = [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/foo", "params": {}},
        ]
        line = (
            json.dumps(batch, separators=(",", ":"), ensure_ascii=False) + "\n"
        ).encode("utf-8")
        with patch.object(
            McpStdioProxy, "_write_client_bytes", side_effect=record_bytes
        ):
            proxy._reject_batch(line)
        responses = json.loads(captured["payload"])
        self.assertEqual([response["id"] for response in responses], [1, 2])
        self.assertTrue(
            all(response["error"]["code"] == -32600 for response in responses)
        )

    def test_is_batch_detects_arrays_only(self):
        from agent_firewall.mcp_proxy import _is_batch

        self.assertTrue(_is_batch(b'[{"jsonrpc":"2.0","id":1}]'))
        self.assertTrue(_is_batch(b"\n   [{}, {}]"))
        self.assertFalse(_is_batch(b'{"jsonrpc":"2.0"}'))
        self.assertFalse(_is_batch(b"not json"))
        self.assertFalse(_is_batch(b""))
        self.assertFalse(_is_batch(b"[" * 50000 + b"1" + b"]" * 50000))

    def test_client_write_failure_is_swallowed(self):
        proxy = _proxy({"default_decision": "allow"})

        class BrokenBuffer:
            def write(self, data):
                raise BrokenPipeError()

            def flush(self):
                raise BrokenPipeError()

        class FakeStdout:
            buffer = BrokenBuffer()

        with patch("agent_firewall.mcp_proxy.sys.stdout", FakeStdout()):
            proxy._write_client_bytes(b"anything\n")

    def test_run_rejects_empty_command(self):
        with self.assertRaisesRegex(ValueError, "server command is required"):
            McpStdioProxy(_proxy({"default_decision": "block"}), [])

    def test_run_rejects_bad_timeout_and_line_limit(self):
        with self.assertRaisesRegex(ValueError, "request timeout"):
            McpStdioProxy(_proxy({}), ["echo"], request_timeout=0)
        with self.assertRaisesRegex(ValueError, "max line bytes"):
            McpStdioProxy(_proxy({}), ["echo"], max_line_bytes=0)


class TruthfulProxyErrorTests(unittest.TestCase):
    def test_non_object_arguments_are_rejected_not_forwarded(self):
        proxy = _proxy({"default_decision": "allow"})
        written = _call(
            proxy,
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {"name": "demo.tool", "arguments": ["raw"]},
            },
        )
        self.assertEqual(written["error"]["code"], -32602)
        self.assertIn("arguments", written["error"]["message"])

    def test_null_arguments_are_rejected_not_evaluated_empty(self):
        proxy = _proxy({"default_decision": "allow"})
        written = _call(
            proxy,
            {
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/call",
                "params": {"name": "demo.tool", "arguments": None},
            },
        )
        self.assertEqual(written["error"]["code"], -32602)

    def test_held_call_without_approver_reports_hold_not_block(self):
        proxy = _proxy(
            {
                "default_decision": "block",
                "rules": [{"tool": "email.send", "decision": "require_approval"}],
            }
        )
        written = _call(
            proxy,
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {"name": "email.send", "arguments": {}},
            },
        )
        self.assertEqual(written["error"]["code"], -32001)
        self.assertIn("approval", written["error"]["message"].lower())
        self.assertEqual(written["error"]["data"]["decision"], "require_approval")

    def test_policy_block_still_reports_blocked(self):
        proxy = _proxy({"default_decision": "block"})
        written = _call(
            proxy,
            {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {"name": "evil.tool", "arguments": {}},
            },
        )
        self.assertEqual(written["error"]["code"], -32001)
        self.assertIn("blocked", written["error"]["message"].lower())

    def test_post_execution_audit_failure_never_claims_not_executed(self):
        from agent_firewall.exceptions import AuditWriteError

        proxy = _proxy({"default_decision": "allow"})
        proxy.firewall = AsyncMock(spec=proxy.firewall)
        proxy.firewall.acall_with_arguments.side_effect = AuditWriteError(
            "audit disk full", after_execution=True
        )
        written = _call(
            proxy,
            {
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {"name": "demo.tool", "arguments": {}},
            },
        )
        self.assertEqual(written["error"]["code"], -32603)
        self.assertIn("ran or was attempted", written["error"]["message"])
        self.assertNotIn("call not executed", written["error"]["message"])

    def test_pre_execution_audit_failure_says_not_executed(self):
        from agent_firewall.exceptions import AuditWriteError

        proxy = _proxy({"default_decision": "allow"})
        proxy.firewall = AsyncMock(spec=proxy.firewall)
        proxy.firewall.acall_with_arguments.side_effect = AuditWriteError(
            "audit disk full"
        )
        written = _call(
            proxy,
            {
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {"name": "demo.tool", "arguments": {}},
            },
        )
        self.assertEqual(written["error"]["code"], -32603)
        self.assertIn("not executed", written["error"]["message"])


class TerminalApproverPromptTests(unittest.TestCase):
    class FakeTerminal:
        def __init__(self, answers):
            self.answers = list(answers)
            self.written = []

        def write(self, text):
            self.written.append(text)

        def flush(self):
            pass

        def readline(self):
            if not self.answers:
                raise EOFError
            item = self.answers.pop(0)
            if isinstance(item, Exception):
                raise item
            return item

    def _ask(self, answers, arguments=None):
        call = ToolCall.create(
            name="email.send", arguments=arguments or {"to": "a@b.c"}
        )
        decision = Decision(
            kind=DecisionKind.REQUIRE_APPROVAL,
            reason="outbound email needs sign-off",
            code="rule",
        )
        terminal = self.FakeTerminal(answers)
        approved = TerminalApprover._prompt(call, decision, terminal)
        return approved, "\n".join(terminal.written)

    def test_y_and_yes_approve(self):
        for answer in ("y", "yes", "  YES \n"):
            with self.subTest(answer=answer):
                approved, transcript = self._ask([answer])
                self.assertTrue(approved)

    def test_empty_no_and_n_denies(self):
        for answer in ("", "n", "no\n"):
            with self.subTest(answer=answer):
                approved, _ = self._ask([answer])
                self.assertFalse(approved)

    def test_garbage_reprompts_once_then_denies(self):
        approved, transcript = self._ask(["maybe?", "nope"])
        self.assertFalse(approved)
        self.assertEqual(transcript.count("Answer y or n"), 1)

    def test_eof_denies_with_message(self):
        err = io.StringIO()
        with redirect_stderr(err):
            approved, _ = self._ask([EOFError()])
        self.assertFalse(approved)
        self.assertIn("denied", err.getvalue())

    def test_prompt_shows_arguments_and_truncates_long_ones(self):
        big_args = {"body": "x" * 400}
        _, transcript = self._ask([], arguments=big_args)
        self.assertIn("email.send", transcript)
        self.assertIn("outbound email needs sign-off", transcript)
        self.assertIn("...", transcript)
        arg_lines = [line for line in transcript.splitlines() if '"body"' in line]
        self.assertEqual(len(arg_lines), 1)
        self.assertLessEqual(len(arg_lines[0]), 140)

    def test_missing_tty_prints_guidance_and_denies(self):
        err = io.StringIO()
        approver = TerminalApprover()
        call = ToolCall.create(name="email.send")
        decision = Decision(kind=DecisionKind.REQUIRE_APPROVAL, reason="r", code="rule")
        with patch("agent_firewall.mcp_proxy.open", side_effect=OSError):
            with redirect_stderr(err):
                approved = asyncio.run(approver(call, decision))
        self.assertFalse(approved)
        self.assertIn("no terminal available", err.getvalue())


class HoldHintTests(unittest.TestCase):
    HELD_POLICY = {
        "default_decision": "block",
        "rules": [{"tool": "email.send", "decision": "require_approval"}],
    }

    def _held(self, proxy):
        return _call(
            proxy,
            {
                "jsonrpc": "2.0",
                "id": 21,
                "method": "tools/call",
                "params": {"name": "email.send", "arguments": {}},
            },
        )

    def test_hold_hint_printed_once_to_stderr(self):
        proxy = _proxy(self.HELD_POLICY, hold_hint="HINT-ME")
        err = io.StringIO()
        with redirect_stderr(err):
            self._held(proxy)
            self._held(proxy)
        output = err.getvalue()
        self.assertIn("HINT-ME", output)
        self.assertEqual(output.count("HINT-ME"), 1)

    def test_no_hint_without_configuration(self):
        proxy = _proxy(self.HELD_POLICY)
        err = io.StringIO()
        with redirect_stderr(err):
            self._held(proxy)
        self.assertEqual(err.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
