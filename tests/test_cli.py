import io
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from agent_firewall import Policy
from agent_firewall.cli import _run_scenario, _short_source, build_parser, main

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
        self.assertIn('"total": 11', output.getvalue())

    def test_check_text_format_names_tool_and_reason(self):
        output = io.StringIO()

        with redirect_stdout(output):
            status = main(
                [
                    "check",
                    "--policy",
                    str(POLICY),
                    "--tool",
                    "email.send",
                    "--arguments",
                    '{"to": "customer@example.com"}',
                    "--format",
                    "text",
                ]
            )

        rendered = output.getvalue()
        self.assertEqual(status, 3)
        self.assertIn("require_approval", rendered)
        self.assertIn("email.send", rendered)
        self.assertIn("outbound email requires a human decision", rendered)
        self.assertNotIn("{", rendered)

    def test_replay_text_format_summarises_every_scenario(self):
        output = io.StringIO()

        with redirect_stdout(output):
            status = main(
                [
                    "replay",
                    "--policy",
                    str(POLICY),
                    "--scenarios",
                    str(SCENARIOS),
                    "--format",
                    "text",
                ]
            )

        rendered = output.getvalue()
        self.assertEqual(status, 0)
        self.assertEqual(rendered.count("CAUGHT"), 11)
        self.assertNotIn("MISSED", rendered)
        self.assertIn("11 caught, 0 missed of 11 scenarios", rendered)
        self.assertIn("Agent repeats database queries until recursion limit", rendered)
        self.assertIn("langchain-ai/langgraph#6731", rendered)
        self.assertNotIn("https://", rendered)

    def test_text_output_is_ascii_and_fits_eighty_columns(self):
        """The recorded terminal demo renders this output in an 80-column SVG."""
        output = io.StringIO()

        with redirect_stdout(output):
            main(
                [
                    "replay",
                    "--policy",
                    str(POLICY),
                    "--scenarios",
                    str(SCENARIOS),
                    "--format",
                    "text",
                ]
            )

        rendered = output.getvalue()
        rendered.encode("ascii")
        for line in rendered.splitlines():
            self.assertLessEqual(len(line), 72, line)

    def test_short_source_handles_every_url_shape(self):
        self.assertEqual(
            _short_source("https://github.com/cline/cline/discussions/1831"),
            "cline/cline#1831",
        )
        self.assertEqual(
            _short_source("https://github.com/sst/opencode/issues/3444"),
            "sst/opencode#3444",
        )
        self.assertEqual(_short_source(None), "no upstream report")
        self.assertEqual(
            _short_source("https://example.com/a/b"),
            "example.com/a/b",
        )

    def test_replay_json_format_stays_default(self):
        output = io.StringIO()

        with redirect_stdout(output):
            main(["replay", "--policy", str(POLICY), "--scenarios", str(SCENARIOS)])

        self.assertIn('"summary"', output.getvalue())
        self.assertNotIn("CAUGHT", output.getvalue())

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

    def test_storage_failure_exits_with_invalid_input_code(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "policy.json"
            policy_path.write_text('{"default_decision":"block"}', encoding="utf-8")
            state_path = root / "state-dir"
            state_path.mkdir()
            with redirect_stderr(io.StringIO()):
                status = main(
                    [
                        "mcp",
                        "--policy",
                        str(policy_path),
                        "--state",
                        str(state_path),
                        "--approve-web",
                        "--",
                        sys.executable,
                        "-c",
                        "pass",
                    ]
                )

            self.assertEqual(status, 2)

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
