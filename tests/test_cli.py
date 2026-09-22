import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from agent_firewall import Policy
from agent_firewall.cli import _run_scenario, build_parser, main

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "examples" / "policy.json"
SCENARIOS = ROOT / "examples" / "complaints.json"


class CliTests(unittest.TestCase):
    def run_main(self, args):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = main(args)
        return status, stdout.getvalue(), stderr.getvalue()

    def test_init_writes_starter_policy_and_config_snippet(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "policy.json"
            audit = root / "audit.jsonl"
            state = root / "firewall.db"

            status, stdout, stderr = self.run_main(
                [
                    "init",
                    "--policy",
                    str(policy),
                    "--audit",
                    str(audit),
                    "--state",
                    str(state),
                    "--server-name",
                    "filesystem",
                    "--",
                    "python",
                    "server.py",
                ]
            )

            self.assertEqual(status, 0, stderr)
            starter = json.loads(policy.read_text(encoding="utf-8"))
            self.assertEqual(starter["default_decision"], "block")
            self.assertEqual(starter["audit_arguments"], "hash")
            self.assertEqual(starter["budget"]["max_identical_calls"], 3)
            self.assertIn("MCP config snippet:", stdout)
            snippet = json.loads(stdout.split("MCP config snippet:\n", 1)[1])
            config = snippet["mcpServers"]["filesystem"]
            self.assertEqual(config["command"], "agent-firewall")
            self.assertIn(str(policy.resolve()), config["args"])
            self.assertEqual(config["args"][-2:], ["python", "server.py"])

    def test_init_refuses_to_overwrite_existing_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.json"
            policy.write_text("{}", encoding="utf-8")

            status, stdout, stderr = self.run_main(["init", "--policy", str(policy)])

            self.assertEqual(status, 2)
            self.assertEqual(stdout, "")
            self.assertIn("pass --force to overwrite", stderr)

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

    def test_bad_policy_path_is_one_line_and_actionable(self):
        status, stdout, stderr = self.run_main(
            [
                "check",
                "--policy",
                "missing-policy.json",
                "--tool",
                "filesystem.read",
            ]
        )

        self.assertEqual(status, 2)
        self.assertEqual(stdout, "")
        self.assertIn("agent-firewall init --policy missing-policy.json", stderr)
        self.assertNotIn("Traceback", stderr)
        self.assertEqual(stderr.count("\n"), 1)

    def test_malformed_policy_json_is_one_line(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.json"
            policy.write_text("{", encoding="utf-8")

            status, stdout, stderr = self.run_main(
                [
                    "check",
                    "--policy",
                    str(policy),
                    "--tool",
                    "filesystem.read",
                ]
            )

        self.assertEqual(status, 2)
        self.assertEqual(stdout, "")
        self.assertIn("invalid policy JSON at line 1, column 2", stderr)
        self.assertNotIn("Traceback", stderr)
        self.assertEqual(stderr.count("\n"), 1)

    def test_missing_mcp_server_command_is_one_line(self):
        status, stdout, stderr = self.run_main(["mcp", "--policy", str(POLICY)])

        self.assertEqual(status, 2)
        self.assertEqual(stdout, "")
        self.assertIn("MCP server command is required after --", stderr)
        self.assertNotIn("Traceback", stderr)
        self.assertEqual(stderr.count("\n"), 1)

    def test_unknown_mcp_server_command_is_one_line(self):
        status, stdout, stderr = self.run_main(
            [
                "mcp",
                "--policy",
                str(POLICY),
                "--",
                "definitely-not-agent-firewall-test-command",
            ]
        )

        self.assertEqual(status, 2)
        self.assertEqual(stdout, "")
        self.assertIn(
            "MCP server command not found: definitely-not-agent-firewall-test-command",
            stderr,
        )
        self.assertNotIn("Traceback", stderr)
        self.assertEqual(stderr.count("\n"), 1)


if __name__ == "__main__":
    unittest.main()
