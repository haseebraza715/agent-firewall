import io
import json
import os
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
                    "--arguments",
                    '{"path": "/workspace/report.txt"}',
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
                        "--audit",
                        str(root / "audit.jsonl"),
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


class PolicyCommandTests(unittest.TestCase):
    def test_lint_clean_policy_exits_zero(self):
        output = io.StringIO()
        with redirect_stdout(output):
            status = main(["policy", "lint", "--policy", str(POLICY)])

        self.assertEqual(status, 0)
        self.assertIn("no findings", output.getvalue())

    def test_lint_error_policy_exits_nonzero_with_text(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text('{"default_decision": "allow"}', encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                status = main(["policy", "lint", "--policy", str(path)])

        self.assertEqual(status, 1)
        self.assertIn("permissive_default", output.getvalue())
        self.assertIn("error", output.getvalue())

    def test_lint_json_format(self):
        output = io.StringIO()
        with redirect_stdout(output):
            status = main(
                ["policy", "lint", "--policy", str(POLICY), "--format", "json"]
            )

        self.assertEqual(status, 0)
        self.assertIn('"error_count": 0', output.getvalue())

    def test_lint_unreadable_policy_exits_with_invalid_input_code(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.json"
            with redirect_stderr(io.StringIO()):
                status = main(["policy", "lint", "--policy", str(missing)])

        self.assertEqual(status, 2)

    def test_explain_defaults_to_text_and_uses_decision_exit_code(self):
        output = io.StringIO()
        with redirect_stdout(output):
            status = main(
                [
                    "policy",
                    "explain",
                    "--policy",
                    str(POLICY),
                    "--tool",
                    "email.send",
                    "--arguments",
                    '{"to": "customer@example.com"}',
                ]
            )

        rendered = output.getvalue()
        self.assertEqual(status, 3)
        self.assertIn("policy explain: email.send", rendered)
        self.assertIn("budget:", rendered)
        self.assertIn("decision: require_approval (rule 1)", rendered)

    def test_explain_json_output(self):
        output = io.StringIO()
        with redirect_stdout(output):
            status = main(
                [
                    "policy",
                    "explain",
                    "--policy",
                    str(POLICY),
                    "--tool",
                    "unknown.tool",
                    "--format",
                    "json",
                ]
            )

        self.assertEqual(status, 4)
        self.assertIn('"decision": "block"', output.getvalue())
        self.assertIn('"budget"', output.getvalue())
        self.assertIn('"rules"', output.getvalue())


class DoctorCommandTests(unittest.TestCase):
    def test_doctor_clean_policy_exits_zero(self):
        output = io.StringIO()
        with redirect_stdout(output):
            status = main(["doctor", "--policy", str(POLICY)])

        self.assertEqual(status, 0)
        self.assertIn("all 7 check(s) passed", output.getvalue())
        self.assertIn("version: ok", output.getvalue())

    def test_doctor_permissive_policy_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text('{"default_decision": "allow"}', encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                status = main(["doctor", "--policy", str(path)])

        self.assertEqual(status, 1)
        self.assertIn("fail_closed_unknown_tool: FAIL", output.getvalue())

    def test_doctor_json_output(self):
        output = io.StringIO()
        with redirect_stdout(output):
            status = main(["doctor", "--policy", str(POLICY), "--format", "json"])

        self.assertEqual(status, 0)
        self.assertIn('"all_ok": true', output.getvalue())

    def test_request_timeout_accepts_positive_float(self):
        args = build_parser().parse_args(
            ["mcp", "--policy", "p", "--request-timeout", "1.5", "--", "echo"]
        )
        self.assertEqual(args.request_timeout, 1.5)

    def test_request_timeout_must_be_positive(self):
        with self.assertRaises(SystemExit) as raised:
            build_parser().parse_args(
                ["mcp", "--policy", "p", "--request-timeout", "0", "--", "echo"]
            )
        self.assertEqual(raised.exception.code, 2)

    def test_request_timeout_rejects_non_finite_values(self):
        for value in ("nan", "inf", "-inf"):
            with self.subTest(value=value):
                with self.assertRaises(SystemExit) as raised:
                    build_parser().parse_args(
                        [
                            "mcp",
                            "--policy",
                            "p",
                            "--request-timeout",
                            value,
                            "--",
                            "echo",
                        ]
                    )
                self.assertEqual(raised.exception.code, 2)

    def test_approval_timeout_rejects_non_finite_and_non_positive(self):
        for value in ("nan", "inf", "0", "-5"):
            with self.subTest(value=value):
                with self.assertRaises(SystemExit) as raised:
                    build_parser().parse_args(
                        ["mcp", "--policy", "p", "--approval-timeout", value, "--"]
                    )
                self.assertEqual(raised.exception.code, 2)

    def test_finite_positive_error_text_names_the_rule(self):
        error = io.StringIO()
        with self.assertRaises(SystemExit) as raised, redirect_stderr(error):
            build_parser().parse_args(
                ["mcp", "--policy", "p", "--approval-timeout", "0", "--"]
            )
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("must be a finite positive number", error.getvalue())

    def test_approval_timeout_keeps_positive_floats(self):
        args = build_parser().parse_args(
            ["mcp", "--policy", "p", "--approval-timeout", "12.5", "--", "echo"]
        )
        self.assertEqual(args.approval_timeout, 12.5)
        default = build_parser().parse_args(["mcp", "--policy", "p"])
        self.assertEqual(default.approval_timeout, 300)

    def test_dashboard_port_must_be_valid(self):
        for value in ("99999", "-1", "65536"):
            with self.subTest(value=value):
                with self.assertRaises(SystemExit) as raised:
                    build_parser().parse_args(
                        [
                            "dashboard",
                            "--policy",
                            "p",
                            "--audit",
                            "a",
                            "--state",
                            "s",
                            "--port",
                            value,
                        ]
                    )
                self.assertEqual(raised.exception.code, 2)

    def test_dashboard_port_zero_is_allowed_for_ephemeral_binding(self):
        args = build_parser().parse_args(
            [
                "dashboard",
                "--policy",
                "p",
                "--audit",
                "a",
                "--state",
                "s",
                "--port",
                "0",
            ]
        )
        self.assertEqual(args.port, 0)

    def test_dashboard_token_flag_passthrough(self):
        args = build_parser().parse_args(
            [
                "dashboard",
                "--policy",
                "p",
                "--audit",
                "a",
                "--state",
                "s",
                "--token",
                "demo-token-123",
            ]
        )
        self.assertEqual(args.token, "demo-token-123")
        default = build_parser().parse_args(
            ["dashboard", "--policy", "p", "--audit", "a", "--state", "s"]
        )
        self.assertIsNone(default.token)


class ReplayInputValidationTests(unittest.TestCase):
    def _write_scenarios(self, scenarios):
        handle, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(handle, "w", encoding="utf-8") as scenario_file:
            json.dump(scenarios, scenario_file)
        return path

    def _replay(self, scenarios):
        path = self._write_scenarios(scenarios)
        try:
            error = io.StringIO()
            with redirect_stderr(error):
                status = main(["replay", "--policy", str(POLICY), "--scenarios", path])
            return status, error.getvalue()
        finally:
            os.unlink(path)

    def test_non_object_arguments_exit_with_terse_error(self):
        status, message = self._replay(
            [
                {
                    "id": "s1",
                    "calls": [{"tool": "t", "arguments": 5}],
                    "expected_decisions": ["block"],
                }
            ]
        )
        self.assertEqual(status, 2)
        self.assertIn("error:", message)
        self.assertIn("arguments", message)

    def test_non_string_source_url_exits_with_terse_error(self):
        status, message = self._replay(
            [
                {
                    "id": "s1",
                    "source_url": 12345,
                    "calls": [{"tool": "t"}],
                    "expected_decisions": ["block"],
                }
            ]
        )
        self.assertEqual(status, 2)
        self.assertIn("error:", message)
        self.assertIn("source_url", message)

    def test_non_string_title_exits_with_terse_error(self):
        status, message = self._replay(
            [
                {
                    "id": "s1",
                    "title": ["not", "a", "title"],
                    "calls": [{"tool": "t"}],
                    "expected_decisions": ["block"],
                }
            ]
        )
        self.assertEqual(status, 2)
        self.assertIn("error:", message)


class VersionTests(unittest.TestCase):
    def test_version_flag_prints_version(self):
        output = io.StringIO()
        with self.assertRaises(SystemExit) as caught, redirect_stdout(output):
            main(["--version"])

        self.assertEqual(caught.exception.code, 0)
        self.assertEqual(output.getvalue().strip(), "0.3.1")

    def test_package_version_matches_pyproject(self):
        import re

        import agent_firewall

        text = (Path(ROOT) / "pyproject.toml").read_text(encoding="utf-8")
        match = re.search(r'^version = "([^"]+)"', text, flags=re.MULTILINE)
        self.assertIsNotNone(match)
        self.assertEqual(agent_firewall.__version__, match.group(1))

    def test_version_is_0_3_1(self):
        import agent_firewall

        self.assertEqual(agent_firewall.__version__, "0.3.1")


if __name__ == "__main__":
    unittest.main()
