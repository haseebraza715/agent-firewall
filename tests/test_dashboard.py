import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from agent_firewall import (
    Dashboard,
    Decision,
    DecisionKind,
    Firewall,
    JsonlAuditLog,
    SQLiteApprovalQueue,
    SQLiteStateStore,
    ToolCall,
)


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.policy_path = root / "policy.json"
        self.audit_path = root / "audit.jsonl"
        self.state_path = root / "firewall.db"
        self.policy_path.write_text(
            json.dumps(
                {
                    "default_decision": "allow",
                    "budget": {"max_calls": 5, "max_cost_usd": "1.00"},
                }
            ),
            encoding="utf-8",
        )
        self.dashboard = Dashboard(
            self.policy_path,
            self.audit_path,
            self.state_path,
            port=0,
            token="test-token",
        )
        self.thread = threading.Thread(
            target=self.dashboard.server.serve_forever,
            daemon=True,
        )
        self.thread.start()

    def tearDown(self):
        self.dashboard.close()
        self.thread.join(timeout=2)
        self.directory.cleanup()

    def test_summary_reports_audit_and_persistent_usage(self):
        firewall = Firewall(
            self.dashboard.policy,
            audit_log=JsonlAuditLog(self.audit_path),
            state_store=SQLiteStateStore(self.state_path),
        )
        firewall.call(
            "search",
            lambda query: query,
            query="firewall",
            estimated_cost_usd="0.25",
        )

        summary = self.get_json("/api/summary")

        self.assertEqual(summary["allowed"], 1)
        self.assertEqual(summary["tool_calls"], 1)
        self.assertEqual(summary["estimated_cost_usd"], "0.25")
        self.assertEqual(summary["max_cost_usd"], "1.00")

    def test_summary_counts_entire_audit_file(self):
        with self.audit_path.open("w", encoding="utf-8") as handle:
            for index in range(250):
                handle.write(
                    json.dumps(
                        {
                            "timestamp": str(index),
                            "event": "allowed",
                            "tool": "search",
                        }
                    )
                    + "\n"
                )

        summary = self.dashboard.summary()
        recent = self.get_json("/api/events")

        self.assertEqual(summary["allowed"], 250)
        self.assertEqual(len(recent["events"]), 200)

    def test_pending_approval_can_be_approved_idempotently(self):
        call = self.add_pending_approval()

        first = self.post_decision(call.id, "approved")
        second = self.post_decision(call.id, "approved")

        self.assertEqual(first["status"], "approved")
        self.assertEqual(second["status"], "approved")
        self.assertEqual(
            self.get_json("/api/approvals")["approvals"],
            [],
        )

    def test_conflicting_decision_returns_409(self):
        call = self.add_pending_approval()
        self.post_decision(call.id, "approved")

        with self.assertRaises(HTTPError) as caught:
            self.post_decision(call.id, "denied")

        self.assertEqual(caught.exception.code, 409)

    def test_decision_requires_dashboard_token(self):
        call = self.add_pending_approval()
        request = Request(
            self.dashboard.address + "/api/approvals/" + call.id,
            data=b'{"decision":"approved"}',
            method="POST",
            headers={"Content-Type": "application/json"},
        )

        with self.assertRaises(HTTPError) as caught:
            urlopen(request, timeout=2)

        self.assertEqual(caught.exception.code, 403)

    def test_page_has_restrictive_security_headers(self):
        from agent_firewall import __version__

        with urlopen(self.dashboard.address + "/", timeout=2) as response:
            page = response.read().decode("utf-8")
            policy = response.headers["Content-Security-Policy"]
            server = response.headers["Server"]

        self.assertIn("Agent Firewall", page)
        self.assertIn("default-src 'none'", policy)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertTrue(server.startswith(f"AgentFirewall/{__version__}"))

    def test_startup_banner_includes_url_and_token(self):
        banner = self.dashboard.startup_banner()
        self.assertIn(self.dashboard.address, banner)
        self.assertIn("token: test-token", banner)

    def test_page_exposes_decision_error_surface_and_focus_hooks(self):
        with urlopen(self.dashboard.address + "/", timeout=2) as response:
            page = response.read().decode("utf-8")

        self.assertIn('id="alert" role="alert"', page)
        self.assertIn('id="updated"', page)
        self.assertIn("res.ok", page)
        self.assertIn("dataset.cid", page)
        self.assertIn("dataset.decision", page)
        self.assertIn(".focus()", page)

    def test_summary_counts_hidden_stale_approvals(self):
        import sqlite3

        connection = sqlite3.connect(str(self.dashboard.approvals.path))
        held = self.add_pending_approval()
        connection.execute(
            "UPDATE approvals SET requested_at = ? WHERE call_id = ?",
            ("2000-01-01T00:00:00+00:00", held.id),
        )
        connection.commit()
        connection.close()
        summary = json.load(urlopen(self.dashboard.address + "/api/summary", timeout=2))
        self.assertEqual(summary["pending_approvals"], 0)
        self.assertEqual(summary["hidden_pending"], 1)

    def test_foreign_host_header_is_rejected(self):
        request = Request(
            self.dashboard.address + "/api/events",
            headers={"Host": "attacker.example"},
        )

        with self.assertRaises(HTTPError) as caught:
            urlopen(request, timeout=2)

        self.assertEqual(caught.exception.code, 421)

    def test_foreign_origin_post_is_rejected_despite_token(self):
        call = self.add_pending_approval()
        request = Request(
            self.dashboard.address + "/api/approvals/" + call.id,
            data=b'{"decision":"approved"}',
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Agent-Firewall-Token": "test-token",
                "Origin": "http://attacker.example",
            },
        )

        with self.assertRaises(HTTPError) as caught:
            urlopen(request, timeout=2)

        self.assertEqual(caught.exception.code, 403)

    def test_loopback_origin_post_is_accepted(self):
        call = self.add_pending_approval()
        request = Request(
            self.dashboard.address + "/api/approvals/" + call.id,
            data=b'{"decision":"approved"}',
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Agent-Firewall-Token": "test-token",
                "Origin": self.dashboard.address,
            },
        )

        with urlopen(request, timeout=2) as response:
            record = json.loads(response.read())

        self.assertEqual(record["status"], "approved")

    def test_non_loopback_binding_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "loopback"):
            Dashboard(
                self.policy_path,
                self.audit_path,
                self.state_path,
                host="0.0.0.0",
            )

    def add_pending_approval(self):
        call = ToolCall.create("email.send", {"secret": "not-persisted"})
        decision = Decision(
            DecisionKind.REQUIRE_APPROVAL,
            "external email",
            "rule_match",
        )
        SQLiteApprovalQueue(self.state_path).request(call, decision)
        return call

    def get_json(self, path):
        with urlopen(self.dashboard.address + path, timeout=2) as response:
            return json.loads(response.read())

    def post_decision(self, call_id, decision):
        request = Request(
            self.dashboard.address + "/api/approvals/" + call_id,
            data=json.dumps({"decision": decision}).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Agent-Firewall-Token": "test-token",
            },
        )
        with urlopen(request, timeout=2) as response:
            return json.loads(response.read())


if __name__ == "__main__":
    unittest.main()
