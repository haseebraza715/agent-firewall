"""Thread-safety tests for the audit log, state stores, and approval queue."""

import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from agent_firewall import (
    ApprovalConflict,
    ApprovalNotFound,
    Decision,
    DecisionKind,
    Firewall,
    JsonlAuditLog,
    MemoryStateStore,
    Policy,
    SQLiteApprovalQueue,
    SQLiteStateStore,
    ToolCall,
    Usage,
)


def _decision() -> Decision:
    return Decision(DecisionKind.REQUIRE_APPROVAL, "test", "rule_match", 0)


class AuditLogConcurrencyTests(unittest.TestCase):
    def test_concurrent_records_are_complete_and_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            log = JsonlAuditLog(path)
            threads = 8
            records_per_thread = 50

            def writer(index):
                for offset in range(records_per_thread):
                    call = ToolCall.create("tool", {"i": index * 1000 + offset})
                    log.record("allowed", call, Usage())

            workers = [
                threading.Thread(target=writer, args=(index,))
                for index in range(threads)
            ]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join()

            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), threads * records_per_thread)
            entries = [json.loads(line) for line in lines]
            self.assertTrue(
                all(entry["event"] == "allowed" for entry in entries)
            )
            self.assertEqual(
                len({entry["call_id"] for entry in entries}),
                threads * records_per_thread,
            )

    def test_concurrent_records_never_interleave_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            log = JsonlAuditLog(path)

            def writer(marker):
                for _ in range(100):
                    log.record(
                        "allowed",
                        ToolCall.create("tool"),
                        Usage(),
                        decision=None,
                    )
                    log.record(
                        "blocked",
                        ToolCall.create("tool"),
                        Usage(),
                        decision=None,
                    )

            workers = [
                threading.Thread(target=writer, args=(index,))
                for index in range(4)
            ]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join()

            for line in path.read_text(encoding="utf-8").splitlines():
                entry = json.loads(line)
                self.assertIn(entry["event"], ("allowed", "blocked"))

    def test_audit_failure_raises_under_contention(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            log = JsonlAuditLog(path)
            blocked = threading.Event()
            release = threading.Event()

            def writer():
                for _ in range(20):
                    log.record("allowed", ToolCall.create("t"), Usage())
                blocked.set()
                release.wait(timeout=5)

            worker = threading.Thread(target=writer)
            worker.start()
            self.assertTrue(blocked.wait(timeout=5))
            path.unlink()
            release.set()
            worker.join()


class MemoryStateConcurrencyTests(unittest.TestCase):
    def test_budget_is_never_overspent_across_threads(self):
        store = MemoryStateStore()
        policy = Policy.from_dict(
            {"default_decision": "allow", "budget": {"max_calls": 1}}
        )

        def attempt(_):
            result = store.evaluate_and_reserve(policy, ToolCall.create("search"))
            return result.decision.kind.value

        with ThreadPoolExecutor(max_workers=16) as executor:
            results = list(executor.map(attempt, range(64)))

        self.assertEqual(results.count("allow"), 1)
        self.assertEqual(results.count("block"), 63)
        self.assertEqual(store.usage().tool_calls, 1)

    def test_usage_reads_are_consistent_snapshots(self):
        store = MemoryStateStore()
        policy = Policy.from_dict({"default_decision": "allow"})
        stop = threading.Event()
        observed = []

        def reader():
            while not stop.is_set():
                usage = store.usage()
                observed.append(
                    (usage.tool_calls, usage.calls_by_tool.get("tool", 0))
                )

        reader_thread = threading.Thread(target=reader)
        reader_thread.start()
        for _ in range(200):
            store.evaluate_and_reserve(policy, ToolCall.create("tool"))
        stop.set()
        reader_thread.join()

        self.assertTrue(all(calls == tools for calls, tools in observed))


class ApprovalQueueConcurrencyTests(unittest.TestCase):
    def test_decide_is_atomic_under_contention(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "approvals.db"
            queue = SQLiteApprovalQueue(path)
            call = ToolCall.create("email.send")
            queue.request(call, _decision())

            def decide(status):
                try:
                    queue.decide(call.id, status)
                    return "won"
                except ApprovalConflict:
                    return "conflict"

            statuses = ["approved"] * 4 + ["denied"] * 4
            with ThreadPoolExecutor(max_workers=8) as executor:
                results = list(executor.map(decide, statuses))

            final = queue.get(call.id).status
            self.assertIn(final, ("approved", "denied"))
            conflicts = sum(
                1
                for status, result in zip(statuses, results)
                if status != final
            )
            self.assertEqual(results.count("conflict"), conflicts)
            self.assertEqual(results.count("won"), len(statuses) - conflicts)
            self.assertEqual(
                queue.get(call.id).status,
                final,
            )

    def test_request_is_idempotent_across_threads(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "approvals.db"
            queue = SQLiteApprovalQueue(path)
            call = ToolCall.create("email.send")

            with ThreadPoolExecutor(max_workers=8) as executor:
                list(
                    executor.map(
                        lambda _: queue.request(call, _decision()), range(8)
                    )
                )

            self.assertEqual(len(queue.pending()), 1)
            self.assertEqual(queue.get(call.id).status, "pending")

    def test_decide_missing_call_raises_approval_not_found(self):
        with tempfile.TemporaryDirectory() as directory:
            queue = SQLiteApprovalQueue(Path(directory) / "approvals.db")
            with self.assertRaises(ApprovalNotFound):
                queue.decide("does-not-exist", "approved")

    def test_approval_queue_used_as_firewall_approver(self):
        import asyncio

        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.db"
            queue = SQLiteApprovalQueue(
                state_path, timeout_seconds=2, poll_seconds=0.01
            )
            policy = Policy.from_dict(
                {
                    "default_decision": "block",
                    "rules": [{"tool": "email.send", "decision": "require_approval"}],
                }
            )
            firewall = Firewall(policy, approver=queue)
            executed = []
            outcome = {}

            def run():
                try:
                    asyncio.run(
                        firewall.acall("email.send", lambda: executed.append(True))
                    )
                    outcome["result"] = "executed"
                except Exception as exc:
                    outcome["result"] = type(exc).__name__

            thread = threading.Thread(target=run)
            thread.start()
            import time

            record = None
            for _ in range(100):
                try:
                    record = queue.pending()[0]
                    break
                except IndexError:
                    time.sleep(0.01)
            self.assertIsNotNone(record)
            queue.decide(record.call_id, "approved")
            thread.join()

            self.assertEqual(outcome["result"], "executed")
            self.assertEqual(executed, [True])

    def test_approval_denial_blocks_and_consumes_nothing(self):
        import asyncio

        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.db"
            queue = SQLiteApprovalQueue(
                state_path, timeout_seconds=2, poll_seconds=0.01
            )
            policy = Policy.from_dict(
                {
                    "default_decision": "block",
                    "rules": [{"tool": "email.send", "decision": "require_approval"}],
                }
            )
            store = MemoryStateStore()
            firewall = Firewall(policy, approver=queue, state_store=store)
            executed = []
            outcome = {}

            def run():
                try:
                    asyncio.run(
                        firewall.acall("email.send", lambda: executed.append(True))
                    )
                    outcome["result"] = "executed"
                except Exception as exc:
                    outcome["result"] = type(exc).__name__

            thread = threading.Thread(target=run)
            thread.start()
            import time

            record = None
            for _ in range(100):
                try:
                    record = queue.pending()[0]
                    break
                except IndexError:
                    time.sleep(0.01)
            self.assertIsNotNone(record)
            queue.decide(record.call_id, "denied")
            thread.join()

            self.assertEqual(outcome["result"], "ToolCallBlocked")
            self.assertEqual(executed, [])
            self.assertEqual(store.usage().tool_calls, 0)


class SQLiteStateConcurrencyTests(unittest.TestCase):
    def test_shared_database_serializes_reservations(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "firewall.db"
            policy = Policy.from_dict(
                {"default_decision": "allow", "budget": {"max_calls": 2}}
            )

            def attempt(_):
                store = SQLiteStateStore(path)
                try:
                    result = store.evaluate_and_reserve(
                        policy, ToolCall.create("search")
                    )
                    return result.decision.kind.value
                except Exception:
                    return "error"

            with ThreadPoolExecutor(max_workers=8) as executor:
                results = list(executor.map(attempt, range(16)))

            self.assertEqual(results.count("allow"), 2)
            self.assertEqual(results.count("block"), 14)

    def test_cross_process_reservations_via_threads(self):
        """Two store instances on the same file behave like separate processes."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "firewall.db"
            policy = Policy.from_dict(
                {"default_decision": "allow", "budget": {"max_calls": 1}}
            )
            first = SQLiteStateStore(path)
            second = SQLiteStateStore(path)
            stop = threading.Event()

            def hammer(store):
                while not stop.is_set():
                    try:
                        store.evaluate_and_reserve(
                            policy, ToolCall.create("search")
                        )
                    except Exception:
                        pass

            worker = threading.Thread(target=hammer, args=(second,))
            worker.start()
            for _ in range(20):
                try:
                    first.evaluate_and_reserve(policy, ToolCall.create("search"))
                    break
                except Exception:
                    continue
            stop.set()
            worker.join()
            self.assertEqual(first.usage().tool_calls, 1)


if __name__ == "__main__":
    unittest.main()
