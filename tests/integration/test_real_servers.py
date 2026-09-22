import json
import os
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
POLICY_ERROR = -32001


@dataclass(frozen=True)
class ServerCase:
    name: str
    package: str
    version: str
    allowed_tool: str
    allowed_arguments: dict[str, Any]
    blocked_tool: str
    blocked_arguments: dict[str, Any]
    approval_tool: str
    approval_arguments: dict[str, Any]
    args: Sequence[str] = field(default_factory=tuple)
    needs_workspace: bool = False


def npx_command(package: str, args: Sequence[str]) -> list[str]:
    command = ["npx", "-y", package, *args]
    if os.name == "nt":
        return ["cmd", "/c", *command]
    return command


def initialize_message() -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": "initialize",
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "agent-firewall-integration", "version": "1.0"},
        },
    }


def tool_call(request_id: str, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }


CASES = [
    ServerCase(
        name="filesystem",
        package="@modelcontextprotocol/server-filesystem",
        version="2026.7.4",
        allowed_tool="list_allowed_directories",
        allowed_arguments={},
        blocked_tool="write_file",
        blocked_arguments={"path": "blocked.txt", "content": "blocked"},
        approval_tool="write_file",
        approval_arguments={"path": "approval.txt", "content": "approval"},
        needs_workspace=True,
    ),
    ServerCase(
        name="fetch",
        package="@modelcontextprotocol/server-fetch",
        version="2026.7.4",
        allowed_tool="fetch",
        allowed_arguments={"url": "https://example.com", "max_length": 200},
        blocked_tool="fetch",
        blocked_arguments={"url": "http://169.254.169.254/latest/meta-data/"},
        approval_tool="fetch",
        approval_arguments={"url": "https://example.com/destructive-review"},
    ),
    ServerCase(
        name="memory",
        package="@modelcontextprotocol/server-memory",
        version="2026.7.4",
        allowed_tool="read_graph",
        allowed_arguments={},
        blocked_tool="create_entities",
        blocked_arguments={
            "entities": [{"name": "blocked", "entityType": "probe", "observations": []}]
        },
        approval_tool="create_entities",
        approval_arguments={
            "entities": [
                {"name": "approval", "entityType": "probe", "observations": []}
            ]
        },
    ),
    ServerCase(
        name="airbnb-community",
        package="@openbnb/mcp-server-airbnb",
        version="0.1.2",
        allowed_tool="airbnb_search",
        allowed_arguments={
            "location": "Paris, France",
            "adults": 1,
            "checkin": "2026-08-01",
            "checkout": "2026-08-02",
            "ignoreRobotsText": True,
        },
        blocked_tool="airbnb_listing_details",
        blocked_arguments={"id": "1", "ignoreRobotsText": True},
        approval_tool="airbnb_listing_details",
        approval_arguments={"id": "2", "ignoreRobotsText": True},
    ),
]


@unittest.skipUnless(
    os.environ.get("AGENT_FIREWALL_INTEGRATION") == "1",
    "set AGENT_FIREWALL_INTEGRATION=1 to run real npx MCP server tests",
)
class RealServerCompatibilityTests(unittest.TestCase):
    maxDiff = None

    def test_real_server_matrix(self):
        for case in CASES:
            with self.subTest(server=case.name):
                self.assert_server_compatible(case)

    def assert_server_compatible(self, case: ServerCase) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "workspace"
            workspace.mkdir()
            policy_path = root / "policy.json"
            audit_path = root / "audit.jsonl"
            state_path = root / "firewall.db"
            blocked_arguments = self._workspace_arguments(
                case.blocked_arguments, workspace
            )
            approval_arguments = self._workspace_arguments(
                case.approval_arguments, workspace
            )
            policy_path.write_text(
                json.dumps(
                    {
                        "default_decision": "block",
                        "rules": [
                            {
                                "tool": case.allowed_tool,
                                "decision": "allow",
                                "reason": "compatibility allowed call",
                            },
                            {
                                "tool": case.blocked_tool,
                                "arguments": blocked_arguments,
                                "decision": "block",
                                "reason": "compatibility blocked call",
                            },
                            {
                                "tool": case.approval_tool,
                                "arguments": approval_arguments,
                                "decision": "require_approval",
                                "reason": "compatibility approval call",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            server_args = list(case.args)
            if case.needs_workspace:
                server_args.append(str(workspace))
            command = [
                sys.executable,
                "-m",
                "agent_firewall",
                "mcp",
                "--policy",
                str(policy_path),
                "--audit",
                str(audit_path),
                "--state",
                str(state_path),
                "--",
                *npx_command(case.package, server_args),
            ]
            env = dict(os.environ)
            env["PYTHONPATH"] = str(ROOT / "src")
            process = subprocess.Popen(
                command,
                cwd=ROOT,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            payload = "\n".join(
                json.dumps(message)
                for message in [
                    initialize_message(),
                    {"jsonrpc": "2.0", "method": "notifications/initialized"},
                    {"jsonrpc": "2.0", "id": "tools", "method": "tools/list"},
                    tool_call(
                        "allowed",
                        case.allowed_tool,
                        self._workspace_arguments(case.allowed_arguments, workspace),
                    ),
                    tool_call("blocked", case.blocked_tool, blocked_arguments),
                    tool_call("approval", case.approval_tool, approval_arguments),
                ]
            )
            stdout, stderr = process.communicate(payload + "\n", timeout=90)

        self.assertEqual(process.returncode, 0, stderr)
        responses = [json.loads(line) for line in stdout.splitlines() if line.strip()]
        by_id = {response["id"]: response for response in responses if "id" in response}
        self.assertIn("result", by_id["initialize"], by_id["initialize"])
        self.assertIn("result", by_id["tools"], by_id["tools"])
        tool_names = {
            tool["name"] for tool in by_id["tools"]["result"].get("tools", [])
        }
        self.assertIn(case.allowed_tool, tool_names)
        self.assertIn(case.blocked_tool, tool_names)
        self.assertIn(case.approval_tool, tool_names)
        self.assertIn("allowed", by_id)
        self.assertNotEqual(
            by_id["allowed"].get("error", {}).get("code"),
            POLICY_ERROR,
            by_id["allowed"],
        )
        self.assertEqual(by_id["blocked"]["error"]["code"], POLICY_ERROR)
        self.assertEqual(
            by_id["blocked"]["error"]["data"]["decision"],
            "block",
        )
        self.assertEqual(by_id["approval"]["error"]["code"], POLICY_ERROR)
        self.assertEqual(
            by_id["approval"]["error"]["data"]["decision"],
            "require_approval",
        )

    @staticmethod
    def _workspace_arguments(
        arguments: dict[str, Any],
        workspace: Path,
    ) -> dict[str, Any]:
        result = dict(arguments)
        path = result.get("path")
        if isinstance(path, str) and not Path(path).is_absolute():
            result["path"] = str(workspace / path)
        return result


if __name__ == "__main__":
    unittest.main()
