import asyncio
import tempfile
import threading
import time
import unittest
from pathlib import Path

from agent_firewall import (
    ApprovalConflict,
    ApprovalNotFound,
    Decision,
    DecisionKind,
    SQLiteApprovalQueue,
    ToolCall,
)


class ApprovalQueueTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "firewall.db"
        self.queue = SQLiteApprovalQueue(
            self.path,
            timeout_seconds=1,
            poll_seconds=0.01,
        )
        self.call = ToolCall.create("email.send", {"secret": "not-stored"})
        self.decision = Decision(
            DecisionKind.REQUIRE_APPROVAL,
            "external email",
            "rule_match",
        )

    def tearDown(self):
        self.directory.cleanup()

    def test_wait_unblocks_after_approval(self):
        result = []

        def wait():
            result.append(self.queue.wait(self.call, self.decision))

        thread = threading.Thread(target=wait)
        thread.start()
        self._wait_until_pending()
        self.queue.decide(self.call.id, "approved")
        thread.join(timeout=2)

        self.assertEqual(result, [True])

    def test_wait_unblocks_after_denial(self):
        result = []
        thread = threading.Thread(
            target=lambda: result.append(self.queue.wait(self.call, self.decision))
        )
        thread.start()
        self._wait_until_pending()
        self.queue.decide(self.call.id, "denied")
        thread.join(timeout=2)

        self.assertEqual(result, [False])

    def test_repeated_same_decision_is_idempotent(self):
        self.queue.request(self.call, self.decision)

        first = self.queue.decide(self.call.id, "approved")
        second = self.queue.decide(self.call.id, "approved")

        self.assertEqual(first.status, "approved")
        self.assertEqual(second.status, "approved")
        self.assertEqual(first.decided_at, second.decided_at)

    def test_conflicting_second_decision_is_rejected(self):
        self.queue.request(self.call, self.decision)
        self.queue.decide(self.call.id, "approved")

        with self.assertRaises(ApprovalConflict):
            self.queue.decide(self.call.id, "denied")

    def test_unknown_call_is_rejected(self):
        with self.assertRaises(ApprovalNotFound):
            self.queue.decide("missing", "approved")

    def test_pending_record_omits_arguments(self):
        self.queue.request(self.call, self.decision)

        record = self.queue.pending()[0].as_dict()

        self.assertNotIn("arguments", record)
        self.assertNotIn("not-stored", str(record))

    def test_async_approver_interface(self):
        async def exercise():
            task = asyncio.create_task(self.queue(self.call, self.decision))
            await asyncio.to_thread(self._wait_until_pending)
            self.queue.decide(self.call.id, "approved")
            return await task

        self.assertTrue(asyncio.run(exercise()))

    def _wait_until_pending(self):
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            if self.queue.pending():
                return
            time.sleep(0.01)
        self.fail("approval did not become pending")


if __name__ == "__main__":
    unittest.main()
