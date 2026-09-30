import asyncio
import json
import os
import runpy
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from functools import partial
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from agent_firewall import (
    Dashboard,
    Firewall,
    JsonlAuditLog,
    Policy,
    SQLiteStateStore,
    StorageError,
    ToolCall,
    ToolCallBlocked,
    Usage,
)
from agent_firewall.dashboard import read_events
from agent_firewall.exceptions import AuditWriteError

ROOT = Path(__file__).resolve().parents[1]


class FoundationWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="afw-regression-")
        artifact_root = os.environ.get("AFW_WORKFLOW_ARTIFACTS")
        self.root = (
            Path(artifact_root) / self._testMethodName
            if artifact_root
            else Path(self.directory.name)
        )
        self.root.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.directory.cleanup()

    def save(self, name, value):
        (self.root / name).write_text(json.dumps(value, indent=2) + "\n")

    def test_wrapped_defaults_are_authorized_and_audited(self):
        policy = Policy.from_dict(
            {
                "default_decision": "allow",
                "audit_arguments": "full",
                "rules": [
                    {
                        "tool": "file.read",
                        "decision": "block",
                        "arguments": {"path": "/private/example"},
                    }
                ],
            }
        )
        audit = self.root / "audit.jsonl"
        firewall = Firewall(
            policy,
            audit_log=JsonlAuditLog(audit),
            state_store=SQLiteStateStore(self.root / "state.db"),
        )
        receipts = []

        def reader(label="demo", *, path="/private/example"):
            receipts.append({"label": label, "path": path})
            return path

        async def async_reader(label="demo", *, path="/private/example"):
            return reader(label, path=path)

        outcomes = []
        for tool in (reader, async_reader):
            for args, kwargs in (((), {}), (("label",), {}), ((), {"label": "x"})):
                wrapped = firewall.wrap("file.read", tool)
                try:
                    result = wrapped(*args, **kwargs)
                    if asyncio.iscoroutine(result):
                        result = asyncio.run(result)
                    outcomes.append("executed")
                except ToolCallBlocked:
                    outcomes.append("blocked")
        self.save("outcomes.json", {"outcomes": outcomes, "receipts": receipts})
        self.assertEqual(outcomes, ["blocked"] * 6)
        self.assertEqual(receipts, [])
        self.assertEqual(firewall.usage.tool_calls, 0)
        self.assertEqual(
            firewall.wrap("file.read", reader)(path="/workspace/example"),
            "/workspace/example",
        )
        self.assertEqual(receipts, [{"label": "demo", "path": "/workspace/example"}])
        events = read_events(audit, limit=None)
        self.assertEqual(events[-1]["arguments"], receipts[0])
        self.assertEqual(firewall.usage.tool_calls, 1)
        self.save("receipts.json", receipts)

    def test_partial_bound_arguments_are_authorized_and_audited(self):
        policy = Policy.from_dict(
            {
                "default_decision": "allow",
                "audit_arguments": "full",
                "rules": [
                    {
                        "tool": "file.read",
                        "decision": "block",
                        "arguments": {
                            "path": {"operator": "path", "within": "/private"}
                        },
                    }
                ],
            }
        )
        audit = self.root / "audit.jsonl"
        firewall = Firewall(policy, audit_log=JsonlAuditLog(audit))
        receipts = []

        def read(path, mode="r"):
            receipts.append(path)
            return path

        class Partial(partial):
            """A subclass is not flattened by functools, so it stays nested."""

        cases = {
            "positional": (partial(read, "/private/p"), (), {}),
            "keyword": (partial(read, path="/private/p"), (), {}),
            "nested": (Partial(partial(read, "/private/p"), "rb"), (), {}),
            "nested-keyword": (
                Partial(Partial(read, mode="rb"), path="/private/p"),
                (),
                {},
            ),
            "call-overrides-keyword": (
                partial(read, path="/private/p"),
                (),
                {"path": "/workspace/ok"},
            ),
        }
        outcomes = {}
        for label, (tool, args, kwargs) in cases.items():
            try:
                firewall.call("file.read", tool, *args, **kwargs)
                outcomes[label] = "executed"
            except ToolCallBlocked:
                outcomes[label] = "blocked"
        events = read_events(audit, limit=None)
        recorded = [
            {"event": event["event"], "arguments": event["arguments"]}
            for event in events
            if event["event"] in {"blocked", "executed"}
        ]
        self.save(
            "outcomes.json",
            {"outcomes": outcomes, "receipts": receipts, "audit": recorded},
        )
        self.assertEqual(
            outcomes,
            {
                "positional": "blocked",
                "keyword": "blocked",
                "nested": "blocked",
                "nested-keyword": "blocked",
                "call-overrides-keyword": "executed",
            },
        )
        self.assertEqual(receipts, ["/workspace/ok"])
        self.assertEqual(
            recorded,
            [
                {"event": "blocked", "arguments": {"path": "/private/p", "mode": "r"}},
                {"event": "blocked", "arguments": {"path": "/private/p", "mode": "r"}},
                {"event": "blocked", "arguments": {"path": "/private/p", "mode": "rb"}},
                {"event": "blocked", "arguments": {"path": "/private/p", "mode": "rb"}},
                {
                    "event": "executed",
                    "arguments": {"path": "/workspace/ok", "mode": "r"},
                },
            ],
        )

    def test_incomplete_audit_tail_refuses_execution_without_rewriting_history(self):
        audit = self.root / "audit.jsonl"
        partial = b'{"event":"interrupted"'
        audit.write_bytes(partial)
        receipts = []
        firewall = Firewall(
            Policy.from_dict({"default_decision": "allow"}),
            audit_log=JsonlAuditLog(audit),
        )
        error = None
        try:
            firewall.call("safe.stub", lambda: receipts.append("ran"))
        except AuditWriteError as exc:
            error = exc
        self.save(
            "outcome.json",
            {"receipts": receipts, "error": str(error), "events": read_events(audit)},
        )
        self.assertIsNotNone(error)
        self.assertFalse(error.after_execution)
        self.assertEqual(receipts, [])
        self.assertEqual(audit.read_bytes(), partial)
        firewall.audit_log = JsonlAuditLog(self.root / "recovered-audit.jsonl")
        firewall.call("safe.stub", lambda: receipts.append("ran"))
        self.assertEqual(receipts, ["ran"])

    def test_invalid_saved_usage_is_rejected_after_restart(self):
        values = [
            ("tool_calls", -1, {"max_calls": 1}),
            ("estimated_cost_usd", "-2", {"max_cost_usd": "0.50"}),
            ("estimated_cost_usd", "NaN", {"max_cost_usd": "0.50"}),
            ("estimated_cost_usd", "Infinity", {"max_cost_usd": "0.50"}),
            ("tool_usage", -1, {"max_calls_per_tool": 1}),
            ("fingerprint_usage", -1, {"max_identical_calls": 1}),
            ("tool_usage", "not-an-integer", {"max_calls_per_tool": 1}),
        ]
        outcomes = []
        for index, (field, value, budget) in enumerate(values):
            with self.subTest(field=field, value=value):
                path = self.root / f"state-{index}.db"
                policy = Policy.from_dict(
                    {"default_decision": "allow", "budget": budget}
                )
                firewall = Firewall(policy, state_store=SQLiteStateStore(path))
                firewall.call("safe.stub", lambda: None, estimated_cost_usd="0.50")
                with sqlite3.connect(path) as connection:
                    if field in {"tool_calls", "estimated_cost_usd"}:
                        connection.execute(
                            f"UPDATE run_usage SET {field} = ?", (value,)
                        )
                    else:
                        connection.execute(
                            f"UPDATE {field} SET call_count = ?", (value,)
                        )
                receipts = []
                restarted = Firewall(policy, state_store=SQLiteStateStore(path))
                error = None
                try:
                    restarted.call("safe.stub", partial(receipts.append, "ran"))
                except Exception as exc:
                    error = exc
                outcomes.append(
                    {
                        "field": field,
                        "value": value,
                        "error": type(error).__name__,
                        "receipts": receipts,
                    }
                )
                self.save("outcomes.json", outcomes)
                self.assertIsInstance(error, StorageError)
                self.assertEqual(receipts, [])

    def test_approval_http_rejects_invalid_shapes_and_unknown_ids(self):
        policy = self.root / "policy.json"
        policy.write_text('{"default_decision":"block"}')
        dashboard = Dashboard(
            policy,
            self.root / "audit.jsonl",
            self.root / "state.db",
            port=0,
            token="local-test-token",
        )
        thread = threading.Thread(target=dashboard.server.serve_forever, daemon=True)
        thread.start()
        call = ToolCall.create("email.send", {"to": "fixture@example.com"})
        pending = dashboard.approvals.request(
            call, dashboard.policy.evaluate(call, Usage())
        )
        outcomes = []
        try:
            for body in (
                None,
                [],
                {},
                {"decision": []},
                {"decision": {}},
                {"decision": True},
                {"decision": "unknown"},
            ):
                request = Request(
                    dashboard.address + "/api/approvals/" + pending.call_id,
                    data=json.dumps(body).encode(),
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "X-Agent-Firewall-Token": "local-test-token",
                    },
                )
                try:
                    with urlopen(request, timeout=3) as response:
                        status, content = response.status, json.load(response)
                except HTTPError as exc:
                    status, content = exc.code, json.load(exc)
                except Exception as exc:
                    status, content = None, {"exception": type(exc).__name__}
                outcomes.append({"input": body, "status": status, "body": content})
            request = Request(
                dashboard.address + "/api/approvals/missing",
                data=b'{"decision":"approved"}',
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "X-Agent-Firewall-Token": "local-test-token",
                },
            )
            try:
                with urlopen(request, timeout=3) as response:
                    missing = response.status
            except HTTPError as exc:
                missing = exc.code
            self.save("responses.json", {"invalid": outcomes, "missing": missing})
            self.assertEqual(
                [item["status"] for item in outcomes], [400] * len(outcomes)
            )
            self.assertEqual(missing, 404)
            self.assertEqual(dashboard.approvals.get(call.id).status, "pending")
        finally:
            dashboard.close()
            thread.join(timeout=3)

    def test_malformed_policy_is_a_controlled_cli_error(self):
        outcomes = []
        for index, operator in enumerate(([], {}, "unknown")):
            policy = self.root / f"policy-{index}.json"
            policy.write_text(
                json.dumps(
                    {
                        "rules": [
                            {
                                "tool": "safe.stub",
                                "decision": "allow",
                                "arguments": {"x": {"operator": operator}},
                            }
                        ]
                    }
                )
            )
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "agent_firewall",
                    "check",
                    "--policy",
                    str(policy),
                    "--tool",
                    "safe.stub",
                ],
                cwd=ROOT,
                env=dict(os.environ, PYTHONPATH=str(ROOT / "src")),
                capture_output=True,
                text=True,
                timeout=5,
            )
            outcomes.append(
                {
                    "operator": operator,
                    "exit": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }
            )
        self.save("responses.json", outcomes)
        self.assertEqual([item["exit"] for item in outcomes], [2] * len(outcomes))
        self.assertTrue(all("Traceback" not in item["stderr"] for item in outcomes))

    def test_benchmark_zero_tolerance_uses_counts_before_display_rounding(self):
        policy, cases = self.root / "policy.json", self.root / "cases.json"
        policy.write_text(
            json.dumps(
                {
                    "default_decision": "block",
                    "rules": [
                        {
                            "tool": "danger.stub",
                            "arguments": {"index": 0},
                            "decision": "allow",
                        }
                    ],
                }
            )
        )
        cases.write_text(
            json.dumps(
                [
                    {
                        "id": "rare-miss",
                        "category": "fixture",
                        "provenance": "synthetic",
                        "calls": [
                            {"tool": "danger.stub", "arguments": {"index": index}}
                            for index in range(20001)
                        ],
                        "expected_decisions": ["block"] * 20001,
                    }
                ]
            )
        )
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "agent_firewall",
                "benchmark",
                "--policy",
                str(policy),
                "--cases",
                str(cases),
                "--output",
                str(self.root / "report"),
                "--max-dangerous-allow-rate",
                "0",
                "--min-intervention-recall",
                "1",
                "--min-exact-accuracy",
                "1",
            ],
            env=dict(os.environ, PYTHONPATH=str(ROOT / "src")),
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        report = json.loads((self.root / "report/report.json").read_text())
        self.save(
            "outcome.json",
            {
                "exit": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "totals": report["totals"],
            },
        )
        self.assertEqual(result.returncode, 5)
        for metric in (
            "dangerous_allow_rate",
            "intervention_recall",
            "exact_decision_accuracy",
        ):
            self.assertIn("threshold failed: " + metric, result.stdout)
        self.assertEqual(report["totals"]["dangerous_allow_rate"], 0.0)
        self.assertEqual(report["totals"]["exact_decision_accuracy"], 1.0)

    def test_demo_url_policy_rejects_non_network_inputs(self):
        demo = runpy.run_path(str(ROOT / "scripts/demo/attack_demo.py"))
        audit = self.root / "audit.jsonl"
        firewall = Firewall(
            Policy.from_dict(demo["POLICY"]), audit_log=JsonlAuditLog(audit)
        )
        receipts, outcomes = [], []
        urls = [
            "",
            "not a URL",
            "file:///fixture/never-read",
            "https://example.com/",
            "http://127.0.0.1/",
        ]
        for url in urls:
            try:
                firewall.call_with_arguments(
                    "web.fetch",
                    {"url": url},
                    partial(receipts.append, url),
                )
                outcomes.append("executed")
            except ToolCallBlocked:
                outcomes.append("blocked")
        self.save(
            "outcomes.json", {"urls": urls, "outcomes": outcomes, "receipts": receipts}
        )
        self.assertEqual(
            outcomes, ["blocked", "blocked", "blocked", "executed", "blocked"]
        )
        self.assertEqual(receipts, ["https://example.com/"])

    def test_state_failure_after_child_execution_never_claims_no_execution(self):
        policy = self.root / "policy.json"
        policy.write_text('{"default_decision":"allow"}')
        state = self.root / "state.db"
        receipt = self.root / "receipt.json"
        child = (
            "import json,sqlite3,sys\n"
            "for line in sys.stdin:\n"
            " m=json.loads(line)\n"
            " with open(sys.argv[2],'w') as f: json.dump(m,f)\n"
            " with sqlite3.connect(sys.argv[1]) as c:\n"
            "  c.execute('DELETE FROM run_usage')\n"
            " print(json.dumps({'jsonrpc':'2.0','id':m['id'],"
            "'result':{'content':[]}}),flush=True)\n"
        )
        message = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "receipt.stub", "arguments": {}},
        }
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "agent_firewall",
                "mcp",
                "--policy",
                str(policy),
                "--audit",
                str(self.root / "audit.jsonl"),
                "--state",
                str(state),
                "--",
                sys.executable,
                "-c",
                child,
                str(state),
                str(receipt),
            ],
            input=json.dumps(message) + "\n",
            cwd=ROOT,
            env=dict(os.environ, PYTHONPATH=str(ROOT / "src")),
            capture_output=True,
            text=True,
            timeout=10,
        )
        (self.root / "responses.jsonl").write_text(result.stdout)
        (self.root / "stderr.log").write_text(result.stderr)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(receipt.read_text())["params"], message["params"])
        response = json.loads(result.stdout)
        self.assertEqual(response["error"]["code"], -32603)
        self.assertNotIn("call not executed", response["error"]["message"])
        self.assertIn("attempted", response["error"]["message"])

    def test_mcp_failures_keep_responses_and_failed_attempt_evidence(self):
        policy = self.root / "policy.json"
        policy.write_text('{"default_decision":"allow","budget":{"max_calls":3}}')
        audit, state, receipts = (
            self.root / name for name in ("audit.jsonl", "state.db", "receipts.jsonl")
        )
        child = (
            "import json,sys\n"
            "for line in sys.stdin:\n"
            " m=json.loads(line)\n"
            " with open(sys.argv[1],'a') as f: f.write(json.dumps(m)+'\\n')\n"
            " r={'jsonrpc':'2.0','id':m['id']}\n"
            " if m['params']['name']=='protocol.failure':\n"
            "  r['error']={'code':-32601,'message':'no such tool'}\n"
            " else:\n"
            "  r['result']={'content':[],"
            "'isError':m['params']['name']=='tool.failure'}\n"
            " print(json.dumps(r),flush=True)\n"
        )
        names = ["protocol.failure", "tool.failure", "ok", "over-budget"]
        messages = [
            {
                "jsonrpc": "2.0",
                "id": index,
                "method": "tools/call",
                "params": {"name": name, "arguments": {}},
            }
            for index, name in enumerate(names)
        ]
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "agent_firewall",
                "mcp",
                "--policy",
                str(policy),
                "--audit",
                str(audit),
                "--state",
                str(state),
                "--",
                sys.executable,
                "-c",
                child,
                str(receipts),
            ],
            input="".join(json.dumps(message) + "\n" for message in messages),
            env=dict(os.environ, PYTHONPATH=str(ROOT / "src")),
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.save("requests.json", messages)
        (self.root / "responses.jsonl").write_text(result.stdout)
        (self.root / "stderr.log").write_text(result.stderr)
        self.assertEqual(result.returncode, 0, result.stderr)
        responses = {
            item["id"]: item for item in map(json.loads, result.stdout.splitlines())
        }
        self.assertEqual(
            responses[0]["error"], {"code": -32601, "message": "no such tool"}
        )
        self.assertTrue(responses[1]["result"]["isError"])
        self.assertFalse(responses[2]["result"]["isError"])
        self.assertEqual(responses[3]["error"]["data"]["code"], "max_calls")
        delivered = [
            json.loads(line)["params"]["name"]
            for line in receipts.read_text().splitlines()
        ]
        self.assertCountEqual(delivered, names[:3])
        events = read_events(audit, limit=None)
        self.assertCountEqual(
            [event["tool"] for event in events if event["event"] == "failed"], names[:2]
        )
        self.assertEqual(
            [event["tool"] for event in events if event["event"] == "executed"], ["ok"]
        )
        self.assertEqual(SQLiteStateStore(state).usage().tool_calls, 3)

    def test_mcp_invalid_method_is_rejected_and_never_reaches_child(self):
        policy = self.root / "policy.json"
        policy.write_text('{"default_decision":"allow"}')
        receipts = self.root / "receipts.jsonl"
        child = (
            "import json,sys\n"
            "for line in sys.stdin:\n"
            " m=json.loads(line)\n"
            " with open(sys.argv[1],'a') as f: f.write(json.dumps(m)+'\\n')\n"
            " if 'id' in m and 'method' in m:\n"
            "  r={'jsonrpc':'2.0','id':m['id'],'result':{'ran':True}}\n"
            "  print(json.dumps(r),flush=True)\n"
        )
        params = {"name": "database.query", "arguments": {"query": "DROP TABLE x"}}
        invalid_methods = [["tools/call"], None, 7, {"name": "tools/call"}]
        messages = [
            {"jsonrpc": "2.0", "id": index, "method": method, "params": params}
            for index, method in enumerate(invalid_methods, start=1)
        ]
        missing_id = len(invalid_methods) + 1
        messages.append({"jsonrpc": "2.0", "id": missing_id, "params": params})
        messages.extend(
            {"jsonrpc": "2.0", "method": method, "params": params}
            for method in invalid_methods
        )
        messages.append({"jsonrpc": "2.0", "params": params})
        # A client response to a server-initiated request has no method and
        # must still reach the child.
        messages.append({"jsonrpc": "2.0", "id": "server-1", "result": {}})
        messages.append({"jsonrpc": "2.0", "id": 99, "method": "tools/list"})
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "agent_firewall",
                "mcp",
                "--policy",
                str(policy),
                "--",
                sys.executable,
                "-c",
                child,
                str(receipts),
            ],
            input="".join(json.dumps(message) + "\n" for message in messages),
            env=dict(os.environ, PYTHONPATH=str(ROOT / "src")),
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.save("requests.json", messages)
        (self.root / "responses.jsonl").write_text(result.stdout)
        (self.root / "stderr.log").write_text(result.stderr)
        self.assertEqual(result.returncode, 0, result.stderr)
        responses = {
            item["id"]: item for item in map(json.loads, result.stdout.splitlines())
        }
        self.assertEqual(sorted(responses, key=str), [*range(1, missing_id + 1), 99])
        for index in range(1, missing_id + 1):
            self.assertEqual(responses[index]["error"]["code"], -32600)
        self.assertEqual(responses[99]["result"], {"ran": True})
        delivered = [json.loads(line) for line in receipts.read_text().splitlines()]
        self.assertEqual(
            [(item["id"] == "server-1", item.get("method")) for item in delivered],
            [(True, None), (False, "tools/list")],
        )


if __name__ == "__main__":
    unittest.main()
