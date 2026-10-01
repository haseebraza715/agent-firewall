import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from agent_firewall import (
    Firewall,
    Policy,
    SQLiteStateStore,
    StorageError,
    ToolCallBlocked,
)


class SQLiteStateStoreTests(unittest.TestCase):
    def test_corrupt_database_has_targeted_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "firewall.db"
            path.write_bytes(b"not a sqlite database")
            with self.assertRaisesRegex(StorageError, "initialize firewall state"):
                SQLiteStateStore(path)

    def test_budget_survives_new_firewall_instance(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "firewall.db"
            policy = Policy.from_dict(
                {"default_decision": "allow", "budget": {"max_calls": 1}}
            )
            first = Firewall(policy, state_store=SQLiteStateStore(path))
            first.call("search", lambda: "first")
            second = Firewall(policy, state_store=SQLiteStateStore(path))

            with self.assertRaises(ToolCallBlocked):
                second.call("search", lambda: "second")

            self.assertEqual(second.usage.tool_calls, 1)

    def test_identical_call_counts_survive_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "firewall.db"
            policy = Policy.from_dict(
                {
                    "default_decision": "allow",
                    "budget": {"max_identical_calls": 1},
                }
            )
            first = Firewall(policy, state_store=SQLiteStateStore(path))
            first.call("search", lambda query: query, query="same")
            second = Firewall(policy, state_store=SQLiteStateStore(path))

            with self.assertRaisesRegex(ToolCallBlocked, "identical"):
                second.call("search", lambda query: query, query="same")

            self.assertEqual(
                second.call("search", lambda query: query, query="different"),
                "different",
            )

    def test_multiple_instances_reserve_budget_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "firewall.db"
            policy = Policy.from_dict(
                {"default_decision": "allow", "budget": {"max_calls": 1}}
            )
            firewalls = [
                Firewall(policy, state_store=SQLiteStateStore(path)) for _ in range(8)
            ]

            def attempt(firewall):
                try:
                    return firewall.call("search", lambda: "executed")
                except ToolCallBlocked:
                    return "blocked"

            with ThreadPoolExecutor(max_workers=8) as executor:
                results = list(executor.map(attempt, firewalls))

        self.assertEqual(results.count("executed"), 1)
        self.assertEqual(results.count("blocked"), 7)

    def test_policy_file_factory_accepts_state_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "policy.json"
            state_path = root / "firewall.db"
            policy_path.write_text('{"default_decision":"allow"}', encoding="utf-8")

            firewall = Firewall.from_policy_file(
                policy_path,
                state_path=state_path,
            )
            firewall.call("search", lambda: "ok")

            self.assertEqual(firewall.usage.tool_calls, 1)


class ApprovedCallReservationTests(unittest.TestCase):
    """Approved held calls must consume budgets in every store backend."""

    POLICY = {
        "default_decision": "block",
        "rules": [
            {"tool": "email.send", "decision": "require_approval"},
            {"tool": "*", "decision": "allow"},
        ],
        "budget": {"max_calls": 1},
    }

    def _approve(self, call, decision):
        return True

    def test_approved_call_consumes_sqlite_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "firewall.db"
            policy = Policy.from_dict(self.POLICY)
            firewall = Firewall(
                policy,
                approver=self._approve,
                state_store=SQLiteStateStore(path),
            )

            self.assertEqual(firewall.call("email.send", lambda: "sent"), "sent")
            with self.assertRaises(ToolCallBlocked):
                firewall.call("search", lambda: "second")
            self.assertEqual(firewall.usage.tool_calls, 1)

    def test_approved_call_consumes_memory_budget(self):
        from agent_firewall import MemoryStateStore

        policy = Policy.from_dict(self.POLICY)
        firewall = Firewall(
            policy,
            approver=self._approve,
            state_store=MemoryStateStore(),
        )

        self.assertEqual(firewall.call("email.send", lambda: "sent"), "sent")
        with self.assertRaises(ToolCallBlocked):
            firewall.call("search", lambda: "second")
        self.assertEqual(firewall.usage.tool_calls, 1)


if __name__ == "__main__":
    unittest.main()
