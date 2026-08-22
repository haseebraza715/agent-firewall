import asyncio
import json
import tempfile
import unittest
import warnings
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
            Policy.from_dict({"default_decision": "allow", "budget": {"max_calls": 1}})
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

    def test_hash_audit_records_fingerprint_without_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            policy = Policy.from_dict(
                {"default_decision": "allow", "audit_arguments": "hash"}
            )
            firewall = Firewall(policy, audit_log=JsonlAuditLog(path))

            firewall.call("demo.tool", lambda secret: secret, secret="do-not-log")
            entry = json.loads(path.read_text(encoding="utf-8").splitlines()[0])

        self.assertNotIn("do-not-log", json.dumps(entry))
        self.assertEqual(len(entry["call_fingerprint"]), 64)

    def test_redacted_audit_preserves_shape_not_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            policy = Policy.from_dict(
                {"default_decision": "allow", "audit_arguments": "redacted"}
            )
            firewall = Firewall(policy, audit_log=JsonlAuditLog(path))

            firewall.call(
                "demo.tool",
                lambda **kwargs: kwargs,
                recipient="person@example.com",
                metadata={"secret": "token"},
            )
            entry = json.loads(path.read_text(encoding="utf-8").splitlines()[0])

        self.assertEqual(entry["arguments"]["recipient"], "[REDACTED]")
        self.assertEqual(entry["arguments"]["metadata"]["secret"], "[REDACTED]")

    def test_full_audit_is_explicitly_opt_in(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            policy = Policy.from_dict(
                {"default_decision": "allow", "audit_arguments": "full"}
            )
            firewall = Firewall(policy, audit_log=JsonlAuditLog(path))

            firewall.call("demo.tool", lambda value: value, value="visible")
            entry = json.loads(path.read_text(encoding="utf-8").splitlines()[0])

        self.assertEqual(entry["arguments"]["value"], "visible")

    def test_failed_call_still_consumes_reserved_budget(self):
        firewall = Firewall(
            Policy.from_dict({"default_decision": "allow", "budget": {"max_calls": 1}})
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
            Policy.from_dict({"default_decision": "allow", "budget": {"max_calls": 1}})
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


def policy_matching_argument(decision):
    return Policy.from_dict(
        {
            "default_decision": "allow",
            "rules": [
                {
                    "tool": "demo.tool",
                    "arguments": {"url": "http://169.254.169.254*"},
                    "decision": decision,
                    "reason": "argument rule",
                }
            ],
        }
    )


class ArgumentBindingTests(unittest.TestCase):
    """Argument rules must apply however the caller passes the arguments."""

    def test_positional_argument_matches_named_rule(self):
        firewall = Firewall(policy_matching_argument("block"))

        def navigate(url):
            return url

        with self.assertRaises(ToolCallBlocked):
            firewall.call("demo.tool", navigate, "http://169.254.169.254/latest/")

    def test_keyword_argument_matches_named_rule(self):
        firewall = Firewall(policy_matching_argument("block"))

        def navigate(url):
            return url

        with self.assertRaises(ToolCallBlocked):
            firewall.call("demo.tool", navigate, url="http://169.254.169.254/latest/")

    def test_unrelated_positional_argument_still_allowed(self):
        firewall = Firewall(policy_matching_argument("block"))

        def navigate(url):
            return url

        self.assertEqual(
            firewall.call("demo.tool", navigate, "https://example.com"),
            "https://example.com",
        )

    def test_var_positional_tool_keeps_opaque_argument_list(self):
        recorded = []
        firewall = Firewall(policy_matching_argument("block"))

        def variadic(*parts):
            recorded.append(parts)
            return parts

        result = firewall.call("demo.tool", variadic, "http://169.254.169.254/latest/")

        self.assertEqual(recorded, [("http://169.254.169.254/latest/",)])
        self.assertEqual(result, ("http://169.254.169.254/latest/",))

    def test_builtin_without_signature_does_not_raise(self):
        firewall = Firewall(policy_matching_argument("block"))

        self.assertEqual(firewall.call("demo.tool", len, [1, 2, 3]), 3)


class AsyncArgumentBindingTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_positional_argument_matches_named_rule(self):
        firewall = Firewall(policy_matching_argument("block"))

        async def navigate(url):
            return url

        with self.assertRaises(ToolCallBlocked):
            await firewall.acall(
                "demo.tool", navigate, "http://169.254.169.254/latest/"
            )


class SyncPathAwaitableToolTests(unittest.TestCase):
    """A sync call must never execute or claim execution of an async tool."""

    class AsyncCallableTool:
        def __init__(self):
            self.ran = []

        async def __call__(self, value):
            self.ran.append(value)
            return value

    def test_callable_object_with_async_call_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            audit_path = Path(directory) / "audit.jsonl"
            firewall = Firewall(
                policy_with_rule("allow"),
                audit_log=JsonlAuditLog(audit_path),
            )
            tool = self.AsyncCallableTool()

            with self.assertRaises(TypeError):
                firewall.call("demo.tool", tool, "x")

            self.assertEqual(tool.ran, [])
            events = [
                json.loads(line)["event"]
                for line in audit_path.read_text().splitlines()
            ]
            self.assertIn("failed", events)
            self.assertNotIn("executed", events)

    def test_sync_function_returning_awaitable_is_rejected(self):
        executed = []
        firewall = Firewall(policy_with_rule("allow"))

        async def background():
            executed.append(True)
            return "done"

        def sync_tool():
            return background()

        with self.assertRaises(TypeError):
            firewall.call("demo.tool", sync_tool)

        self.assertEqual(executed, [])

    def test_rejected_awaitable_is_closed_not_leaked(self):
        firewall = Firewall(policy_with_rule("allow"))

        async def background():
            return "done"

        def sync_tool():
            return background()

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with self.assertRaises(TypeError):
                firewall.call("demo.tool", sync_tool)

        self.assertFalse([w for w in caught if "never awaited" in str(w.message)])


class TerminalAuditFailureTests(unittest.TestCase):
    """Audit outages are distinguishable before vs after execution."""

    class _SelectiveAuditLog:
        def __init__(self, fail_on):
            self.fail_on = fail_on
            self.events = []

        def record(self, event, call, usage, **kwargs):
            from agent_firewall.exceptions import AuditWriteError

            if event in self.fail_on:
                raise AuditWriteError(f"cannot write {event}")
            self.events.append(event)

    def _run(self, fail_on):
        executed = []
        audit_log = self._SelectiveAuditLog(fail_on)
        firewall = Firewall(policy_with_rule("allow"), audit_log=audit_log)
        return firewall, audit_log, executed, lambda: executed.append(True)

    def test_failure_after_execution_is_marked(self):
        import asyncio

        from agent_firewall.exceptions import AuditWriteError

        firewall, audit_log, executed, operation = self._run(fail_on={"executed"})
        with self.assertRaises(AuditWriteError) as caught:
            asyncio.run(firewall.acall_with_arguments("demo.tool", {}, operation))
        self.assertTrue(caught.exception.after_execution)
        self.assertEqual(executed, [True])
        self.assertIn("allowed", audit_log.events)

    def test_failure_before_execution_is_not_marked(self):
        import asyncio

        from agent_firewall.exceptions import AuditWriteError

        firewall, audit_log, executed, operation = self._run(fail_on={"allowed"})
        with self.assertRaises(AuditWriteError) as caught:
            asyncio.run(firewall.acall_with_arguments("demo.tool", {}, operation))
        self.assertFalse(caught.exception.after_execution)
        self.assertEqual(executed, [])
        self.assertNotIn("executed", audit_log.events)


if __name__ == "__main__":
    unittest.main()
