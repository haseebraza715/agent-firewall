import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from agent_firewall import Firewall, Policy, SQLiteStateStore, ToolCallBlocked


class SQLiteStateStoreTests(unittest.TestCase):
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
                Firewall(policy, state_store=SQLiteStateStore(path))
                for _ in range(8)
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


if __name__ == "__main__":
    unittest.main()
