#!/usr/bin/env python3
"""Safely reproduce modelcontextprotocol/servers issue #3662.

The affected package navigates Chromium to a loopback-only HTTP endpoint. No
cloud metadata address, private service, or external website is contacted.
The guarded run checks allow, approval, block, and repetition-budget paths.
"""

from __future__ import annotations

import hashlib
import json
import os
import queue
import subprocess
import sys
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
SERVER_JS = (
    HERE
    / "node_modules"
    / "@modelcontextprotocol"
    / "server-puppeteer"
    / "dist"
    / "index.js"
)
POLICY = HERE / "policy.json"
EVIDENCE = HERE / "evidence.json"
PACKAGE_LOCK = HERE / "package-lock.json"
ISSUE_URL = "https://github.com/modelcontextprotocol/servers/issues/3662"
UPSTREAM_COMMIT = "9be4674d1ddf8c469e6461a27a337eeb65f76c2e"


class ProbeHandler(BaseHTTPRequestHandler):
    hits: Counter[str] = Counter()
    hits_lock = threading.Lock()

    def do_GET(self) -> None:  # noqa: N802
        with type(self).hits_lock:
            type(self).hits[self.path] += 1
        body = b"safe-loopback-metadata-fixture\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        del format, args

    @classmethod
    def reset_hits(cls) -> None:
        with cls.hits_lock:
            cls.hits.clear()

    @classmethod
    def hit_count(cls, path: str) -> int:
        with cls.hits_lock:
            return cls.hits[path]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


class McpClient:
    def __init__(self, command: list[str], environment: dict[str, str]) -> None:
        self.process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.messages: queue.Queue[dict[str, Any]] = queue.Queue()
        self.stderr: list[str] = []
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()

    def _read_stdout(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(message, dict):
                self.messages.put(message)

    def _read_stderr(self) -> None:
        assert self.process.stderr is not None
        for line in self.process.stderr:
            self.stderr.append(line.rstrip())

    def send(self, message: dict[str, Any]) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        self.process.stdin.flush()

    def request(
        self, request_id: int, method: str, params: dict[str, Any]
    ) -> dict[str, Any]:
        self.send(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params,
            }
        )
        while True:
            try:
                response = self.messages.get(timeout=30)
            except queue.Empty as exc:
                details = "\n".join(self.stderr[-10:])
                raise RuntimeError(
                    f"timed out waiting for {method}: {details}"
                ) from exc
            if response.get("id") == request_id:
                return response

    def initialize(self) -> None:
        response = self.request(
            1,
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "agent-firewall-reproduction", "version": "1"},
            },
        )
        if "error" in response:
            raise RuntimeError(f"MCP initialize failed: {response['error']}")
        self.send(
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
        )

    def close(self) -> None:
        if self.process.stdin is not None:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)


def browser_environment() -> dict[str, str]:
    environment = os.environ.copy()
    executable = environment.get("PUPPETEER_EXECUTABLE_PATH")
    if executable is None:
        mac_chrome = Path(
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        )
        if mac_chrome.is_file():
            executable = str(mac_chrome)
    if executable is None:
        raise RuntimeError(
            "set PUPPETEER_EXECUTABLE_PATH to an installed Chrome or Chromium binary"
        )
    environment["PUPPETEER_EXECUTABLE_PATH"] = executable
    return environment


def call_navigation(
    command: list[str], url: str, environment: dict[str, str]
) -> dict[str, Any]:
    client = McpClient(command, environment)
    try:
        client.initialize()
        response = client.request(
            2,
            "tools/call",
            {"name": "puppeteer_navigate", "arguments": {"url": url}},
        )
    finally:
        client.close()
    return {"response": response, "stderr": client.stderr}


def tool_succeeded(response: dict[str, Any]) -> bool:
    result = response.get("result")
    return isinstance(result, dict) and not result.get("isError", False)


def main() -> int:
    EVIDENCE.unlink(missing_ok=True)
    failure_path = HERE / "failure.json"
    failure_path.unlink(missing_ok=True)
    if not SERVER_JS.is_file():
        print(
            "error: run ./run.sh first so npm can install the pinned package",
            file=sys.stderr,
        )
        return 2

    ProbeHandler.reset_hits()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), ProbeHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    port = httpd.server_address[1]
    base_url = f"http://127.0.0.1:{port}"
    prohibited_url = f"{base_url}/latest/meta-data/"
    safe_url = f"{base_url}/safe"
    approval_url = f"{base_url}/approval"
    repeat_url = f"{base_url}/repeat"
    environment = browser_environment()
    child = ["node", str(SERVER_JS)]

    try:
        unguarded_diagnostics = call_navigation(child, prohibited_url, environment)
        unguarded = unguarded_diagnostics["response"]
        unguarded_hits = ProbeHandler.hit_count("/latest/meta-data/")
        ProbeHandler.reset_hits()
        guarded_command = [
            sys.executable,
            "-m",
            "agent_firewall",
            "mcp",
            "--policy",
            str(POLICY),
            "--",
            *child,
        ]
        client = McpClient(guarded_command, environment)
        try:
            client.initialize()
            safe = client.request(
                10,
                "tools/call",
                {"name": "puppeteer_navigate", "arguments": {"url": safe_url}},
            )
            safe_hits = ProbeHandler.hit_count("/safe")
            approval = client.request(
                11,
                "tools/call",
                {
                    "name": "puppeteer_navigate",
                    "arguments": {"url": approval_url},
                },
            )
            approval_hits = ProbeHandler.hit_count("/approval")
            prohibited = client.request(
                12,
                "tools/call",
                {
                    "name": "puppeteer_navigate",
                    "arguments": {"url": prohibited_url},
                },
            )
            prohibited_hits = ProbeHandler.hit_count("/latest/meta-data/")
            repeat_first = client.request(
                13,
                "tools/call",
                {"name": "puppeteer_navigate", "arguments": {"url": repeat_url}},
            )
            repeat_hits_after_first = ProbeHandler.hit_count("/repeat")
            repeat_second = client.request(
                14,
                "tools/call",
                {"name": "puppeteer_navigate", "arguments": {"url": repeat_url}},
            )
            repeat_hits_after_second = ProbeHandler.hit_count("/repeat")
        finally:
            client.close()
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)

    approval_data = approval.get("error", {}).get("data", {})
    prohibited_data = prohibited.get("error", {}).get("data", {})
    repetition_data = repeat_second.get("error", {}).get("data", {})
    passed = (
        tool_succeeded(unguarded)
        and unguarded_hits >= 1
        and tool_succeeded(safe)
        and safe_hits >= 1
        and approval.get("error", {}).get("code") == -32001
        and approval_data.get("decision") == "require_approval"
        and approval_hits == 0
        and prohibited.get("error", {}).get("code") == -32001
        and prohibited_data.get("decision") == "block"
        and prohibited_hits == 0
        and tool_succeeded(repeat_first)
        and repeat_hits_after_first >= 1
        and repeat_second.get("error", {}).get("code") == -32001
        and repetition_data.get("code") == "max_identical_calls"
        and repeat_hits_after_second == repeat_hits_after_first
    )
    evidence = {
        "schema_version": 1,
        "diagnostics": {
            "unguarded": unguarded_diagnostics,
            "guarded_stderr": client.stderr,
            "safe_response": safe,
            "first_repetition_response": repeat_first,
        },
        "kind": "safe-end-to-end-integration",
        "source_issue": ISSUE_URL,
        "upstream_repository": "https://github.com/modelcontextprotocol/servers-archived",
        "upstream_commit": UPSTREAM_COMMIT,
        "affected_package": "@modelcontextprotocol/server-puppeteer@0.6.2",
        "input_sha256": {
            "package_lock": sha256_file(PACKAGE_LOCK),
            "policy": sha256_file(POLICY),
        },
        "request": {
            "tool": "puppeteer_navigate",
            "url": "http://127.0.0.1:<ephemeral>/latest/meta-data/",
        },
        "unguarded": {
            "endpoint_hits": unguarded_hits,
            "executed": tool_succeeded(unguarded),
        },
        "guarded": {
            "safe_call": {
                "endpoint_hits": safe_hits,
                "executed": tool_succeeded(safe),
            },
            "approval_call": {
                "decision": approval_data.get("decision"),
                "endpoint_hits": approval_hits,
                "executed": approval_hits > 0,
                "jsonrpc_error_code": approval.get("error", {}).get("code"),
            },
            "prohibited_call": {
                "decision": prohibited_data.get("decision"),
                "endpoint_hits": prohibited_hits,
                "executed": prohibited_hits > 0,
                "jsonrpc_error_code": prohibited.get("error", {}).get("code"),
            },
            "repetition_budget": {
                "first_call_executed": tool_succeeded(repeat_first),
                "hits_after_first": repeat_hits_after_first,
                "hits_after_second": repeat_hits_after_second,
                "second_call_decision_code": repetition_data.get("code"),
                "second_call_jsonrpc_error_code": repeat_second.get("error", {}).get(
                    "code"
                ),
            },
        },
        "passed": passed,
        "safety": (
            "loopback fixture only; no cloud metadata or external target contacted"
        ),
    }
    rendered = json.dumps(evidence, indent=2, sort_keys=True)
    result_path = EVIDENCE if passed else failure_path
    result_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
