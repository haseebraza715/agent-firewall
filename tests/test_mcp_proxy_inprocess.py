"""In-process unit tests for the MCP proxy's decision paths.

The subprocess tests in test_mcp_proxy.py exercise the proxy end to end; these
tests drive ``_handle_client_line`` directly so the proxy's branches are also
covered when coverage is measured in the test process.
"""

import asyncio
import json
import unittest
from unittest.mock import patch

from agent_firewall import Firewall, Policy
from agent_firewall.jsonrpc import encode_message, request_key
from agent_firewall.mcp_proxy import McpStdioProxy


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


if __name__ == "__main__":
    unittest.main()
