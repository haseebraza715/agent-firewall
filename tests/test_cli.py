import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from agent_firewall.cli import main

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


if __name__ == "__main__":
    unittest.main()
