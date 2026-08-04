import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_firewall import Policy, SQLiteApprovalQueue, SQLiteStateStore
from agent_firewall.models import ToolCall


class _ConnectionTracker:
    """Deterministically record every sqlite3 connection and its close call."""

    def __init__(self) -> None:
        self.open_connections: list[sqlite3.Connection] = []
        # `import sqlite3` shares one module object, so patching
        # agent_firewall.state.sqlite3.connect patches it here too; keep the
        # real callable to avoid recursing into the tracker.
        self._real_connect = sqlite3.connect

    def connect(self, *args, **kwargs) -> sqlite3.Connection:
        connection = self._real_connect(*args, **kwargs)
        tracker = self

        class TrackedConnection:
            def __getattr__(self, name):
                return getattr(connection, name)

            def close(self) -> None:
                tracker.open_connections.remove(connection)
                connection.close()

            def __enter__(self):
                connection.__enter__()
                return self

            def __exit__(self, *exc):
                return connection.__exit__(*exc)

        self.open_connections.append(connection)
        return TrackedConnection()


class ConnectionLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "firewall.db"
        self.policy = Policy.from_dict(
            {"default_decision": "allow", "budget": {"max_calls": 10}}
        )

    def test_state_store_closes_every_connection(self):
        tracker = _ConnectionTracker()
        with patch("agent_firewall.state.sqlite3.connect", tracker.connect):
            store = SQLiteStateStore(self.path)
            store.usage()
            store.evaluate_and_reserve(
                self.policy, ToolCall.create("search", {"q": "x"}, 0)
            )
            store.usage()
        self.assertEqual(tracker.open_connections, [])

    def test_approval_queue_closes_every_connection(self):
        tracker = _ConnectionTracker()
        with patch("agent_firewall.approvals.sqlite3.connect", tracker.connect):
            queue = SQLiteApprovalQueue(self.path)
            call = ToolCall.create("email.send", {"to": "a@example.com"}, 0)
            decision_stub = type("DecisionStub", (), {"reason": "needs approval"})()
            queue.request(call, decision_stub)
            queue.pending()
            queue.get(call.id)
            queue.decide(call.id, "approved")
            queue.get(call.id)
        self.assertEqual(tracker.open_connections, [])


if __name__ == "__main__":
    unittest.main()
