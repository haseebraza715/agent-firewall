import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from agent_firewall import Policy
from agent_firewall.cli import _run_scenario, build_parser, main

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "examples" / "policy.json"
SCENARIOS = ROOT / "examples" / "complaints.json"


class CliTests(unittest.TestCase):
    def test_check_returns_machine_readable_allow(self):
        output = io.StringIO()

        with redirect_stdout(output):
            status = main(
                [
                    "check",
                    "--policy",
                    str(POLICY),
                    "--tool",
                    "filesystem.read",
                ]
            )

        self.assertEqual(status, 0)
        self.assertIn('"decision": "allow"', output.getvalue())

    def test_check_uses_distinct_exit_code_for_approval(self):
        with redirect_stdout(io.StringIO()):
            status = main(
                [
                    "check",
                    "--policy",
                    str(POLICY),
                    "--tool",
                    "email.send",
                ]
            )

        self.assertEqual(status, 3)

    def test_check_uses_distinct_exit_code_for_block(self):
        with redirect_stdout(io.StringIO()):
            status = main(
                [
                    "check",
                    "--policy",
                    str(POLICY),
                    "--tool",
                    "unknown.tool",
                ]
            )

        self.assertEqual(status, 4)

    def test_complaint_replay_passes(self):
        output = io.StringIO()

        with redirect_stdout(output):
            status = main(
                [
                    "replay",
                    "--policy",
                    str(POLICY),
                    "--scenarios",
                    str(SCENARIOS),
                ]
            )

        self.assertEqual(status, 0)
        self.assertIn('"failed": 0', output.getvalue())
        self.assertIn('"total": 4', output.getvalue())

    def test_mcp_parser_accepts_web_approval_state(self):
        args = build_parser().parse_args(
            [
                "mcp",
                "--policy",
                "policy.json",
                "--state",
                "firewall.db",
                "--approve-web",
                "--",
                "python",
                "server.py",
            ]
        )

        self.assertTrue(args.approve_web)
        self.assertEqual(str(args.state), "firewall.db")

    def test_dashboard_defaults_to_loopback(self):
        args = build_parser().parse_args(
            [
                "dashboard",
                "--policy",
                "policy.json",
                "--audit",
                "audit.jsonl",
                "--state",
                "firewall.db",
            ]
        )

        self.assertEqual(args.host, "127.0.0.1")
        self.assertEqual(args.port, 8787)

    def test_scenario_errors_include_call_location(self):
        scenario = {
            "id": "bad-case",
            "calls": [{"tool": ""}],
            "expected_decisions": ["block"],
        }

        with self.assertRaisesRegex(
            ValueError,
            r"bad-case: calls\[0\]: tool name must be a non-empty string",
        ):
            _run_scenario(Policy.from_dict({}), scenario)


if __name__ == "__main__":
    unittest.main()
