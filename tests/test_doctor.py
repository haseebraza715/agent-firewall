import sys
import tempfile
import unittest
from pathlib import Path

from agent_firewall import __version__
from agent_firewall.doctor import (
    UNKNOWN_TOOL_PROBE,
    render_text,
    run_checks,
    to_dict,
)


def _write_policy(root, body='{"default_decision": "block"}'):
    path = Path(root) / "policy.json"
    path.write_text(body, encoding="utf-8")
    return path


class DoctorTests(unittest.TestCase):
    def test_all_checks_pass_for_a_sound_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = _write_policy(root)
            (root / "state").mkdir()
            checks = run_checks(
                policy,
                state_path=root / "state" / "state.db",
                audit_path=root / "audit.jsonl",
                mcp_command=[sys.executable, "server.py"],
            )

            by_name = {check.name: check for check in checks}
            self.assertTrue(all(check.ok for check in checks), checks)
            self.assertEqual(by_name["version"].message, __version__)
            self.assertTrue(by_name["policy"].ok)
            self.assertTrue(by_name["state"].ok)
            self.assertTrue(by_name["audit"].ok)
            self.assertTrue(by_name["mcp"].ok)

    def test_unloadable_policy_is_reported_and_stops(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checks = run_checks(root / "missing.json")

            by_name = {check.name: check for check in checks}
            self.assertFalse(by_name["policy"].ok)
            self.assertFalse(by_name["fail_closed_unknown_tool"].ok)
            self.assertNotIn("mcp", by_name)

    def test_permissive_policy_fails_the_fail_closed_check(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = _write_policy(directory, '{"default_decision": "allow"}')
            checks = run_checks(policy)

            by_name = {check.name: check for check in checks}
            self.assertFalse(by_name["fail_closed_unknown_tool"].ok)
            self.assertIn(
                UNKNOWN_TOOL_PROBE, by_name["fail_closed_unknown_tool"].message
            )

    def test_optional_paths_default_to_not_configured(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = _write_policy(directory)
            checks = run_checks(policy)

            by_name = {check.name: check for check in checks}
            self.assertTrue(by_name["state"].ok)
            self.assertEqual(by_name["state"].message, "not configured")
            self.assertEqual(by_name["mcp"].message, "not configured")

    def test_parent_writability_probe_does_not_touch_the_state_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = _write_policy(root)
            state_path = root / "state.db"
            checks = run_checks(policy, state_path=state_path)

            self.assertTrue({c.name: c.ok for c in checks}["state"])
            self.assertFalse(state_path.exists())

    def test_missing_parent_is_reported_without_creating_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = _write_policy(root)
            missing = root / "missing" / "state.db"

            checks = run_checks(policy, state_path=missing)

            state = {check.name: check for check in checks}["state"]
            self.assertFalse(state.ok)
            self.assertIn("does not exist", state.message)
            self.assertFalse(missing.parent.exists())

    def test_missing_mcp_executable_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = _write_policy(directory)
            checks = run_checks(policy, mcp_command=["no-such-executable-zzz"])

            by_name = {check.name: check for check in checks}
            self.assertFalse(by_name["mcp"].ok)

    def test_render_text_and_json(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = _write_policy(directory)
            checks = run_checks(policy)

        text = render_text(checks)
        self.assertIn("agent-firewall doctor", text)
        self.assertIn("all 6 check(s) passed", text)
        self.assertEqual(to_dict(checks)["all_ok"], True)
        self.assertEqual(len(to_dict(checks)["checks"]), 6)

    def test_failed_checks_drive_render_and_json_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = _write_policy(directory, '{"default_decision": "allow"}')
            checks = run_checks(policy)

        self.assertIn("1 of 6 check(s) failed", render_text(checks))
        data = to_dict(checks)
        self.assertEqual(data["failed_checks"], 1)
        self.assertFalse(data["all_ok"])


if __name__ == "__main__":
    unittest.main()
