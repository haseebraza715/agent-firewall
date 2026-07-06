import asyncio
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from agent_firewall import (
    ApprovalRequired,
    Firewall,
    JsonlAuditLog,
    Policy,
    ToolCallBlocked,
)


def policy_with_rule(decision):
    return Policy.from_dict(
        {
            "default_decision": "block",
            "rules": [
                {
                    "tool": "demo.tool",
                    "decision": decision,
                    "reason": "test rule",
                }
            ],
        }
    )


class FirewallTests(unittest.TestCase):
    def test_allowed_tool_executes_and_consumes_budget(self):
        firewall = Firewall(policy_with_rule("allow"))

        result = firewall.call("demo.tool", lambda value: value + 1, 2)

        self.assertEqual(result, 3)
        self.assertEqual(firewall.usage.tool_calls, 1)

    def test_blocked_tool_never_executes(self):
        executed = []
        firewall = Firewall(policy_with_rule("block"))

        with self.assertRaises(ToolCallBlocked):
            firewall.call("demo.tool", lambda: executed.append(True))

        self.assertEqual(executed, [])
        self.assertEqual(firewall.usage.tool_calls, 0)

    def test_missing_approver_pauses_execution(self):
        firewall = Firewall(policy_with_rule("require_approval"))

        with self.assertRaises(ApprovalRequired):
            firewall.call("demo.tool", lambda: "unsafe")

        self.assertEqual(firewall.usage.tool_calls, 0)

    def test_denied_approval_blocks_execution(self):
        executed = []
        firewall = Firewall(
            policy_with_rule("require_approval"),
            approver=lambda call, decision: False,
        )

        with self.assertRaisesRegex(ToolCallBlocked, "approval denied"):
            firewall.call("demo.tool", lambda: executed.append(True))

        self.assertEqual(executed, [])

    def test_granted_approval_executes(self):
        firewall = Firewall(
            policy_with_rule("require_approval"),
            approver=lambda call, decision: True,
        )

        result = firewall.call("demo.tool", lambda: "sent")

        self.assertEqual(result, "sent")
        self.assertEqual(firewall.usage.tool_calls, 1)

    def test_check_does_not_consume_budget(self):
        firewall = Firewall(
            Policy.from_dict(
                {"default_decision": "allow", "budget": {"max_calls": 1}}
            )
        )

        firewall.check("demo.tool")
        firewall.check("demo.tool")

        self.assertEqual(firewall.usage.tool_calls, 0)

    def test_wrapper_preserves_function_metadata(self):
        firewall = Firewall(policy_with_rule("allow"))

        def original():
            """Original documentation."""
            return "ok"

        wrapped = firewall.wrap("demo.tool", original)

        self.assertEqual(wrapped.__name__, "original")
        self.assertEqual(wrapped.__doc__, "Original documentation.")
        self.assertEqual(wrapped(), "ok")

    def test_audit_log_does_not_store_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            firewall = Firewall(
                policy_with_rule("allow"),
                audit_log=JsonlAuditLog(path),
            )

            firewall.call("demo.tool", lambda secret: secret, secret="do-not-log")
            text = path.read_text(encoding="utf-8")
            entries = [json.loads(line) for line in text.splitlines()]

        self.assertNotIn("do-not-log", text)
        self.assertEqual([entry["event"] for entry in entries], ["allowed", "executed"])

    def test_failed_call_still_consumes_reserved_budget(self):
        firewall = Firewall(
            Policy.from_dict(
                {"default_decision": "allow", "budget": {"max_calls": 1}}
            )
        )

        with self.assertRaisesRegex(RuntimeError, "tool failed"):
            firewall.call(
                "demo.tool",
                lambda: (_ for _ in ()).throw(RuntimeError("tool failed")),
            )

        with self.assertRaises(ToolCallBlocked):
            firewall.call("other.tool", lambda: "not reached")

    def test_concurrent_calls_cannot_overspend_budget(self):
        firewall = Firewall(
            Policy.from_dict(
                {"default_decision": "allow", "budget": {"max_calls": 1}}
            )
        )

        def attempt():
            try:
                return firewall.call("demo.tool", lambda: "executed")
            except ToolCallBlocked:
                return "blocked"

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(lambda _: attempt(), range(8)))

        self.assertEqual(results.count("executed"), 1)
        self.assertEqual(results.count("blocked"), 7)


class AsyncFirewallTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_tool_executes(self):
        firewall = Firewall(policy_with_rule("allow"))

        async def tool(value):
            await asyncio.sleep(0)
            return value + 1

        result = await firewall.acall("demo.tool", tool, 2)

        self.assertEqual(result, 3)

    async def test_async_approver_is_supported(self):
        async def approve(call, decision):
            await asyncio.sleep(0)
            return True

        firewall = Firewall(
            policy_with_rule("require_approval"),
            approver=approve,
        )

        result = await firewall.acall("demo.tool", lambda: "approved")

        self.assertEqual(result, "approved")

    async def test_async_wrapper_is_awaitable(self):
        firewall = Firewall(policy_with_rule("allow"))

        async def tool():
            return "ok"

        wrapped = firewall.wrap("demo.tool", tool)

        self.assertEqual(await wrapped(), "ok")


if __name__ == "__main__":
    unittest.main()
