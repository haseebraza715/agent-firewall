from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .approvals import SQLiteApprovalQueue
from .exceptions import FirewallError
from .firewall import Approver, Firewall
from .jsonrpc import decode_message, encode_message, request_key
from .models import Decision, ToolCall

POLICY_ERROR = -32001
DUPLICATE_ID_ERROR = -32600
INVALID_PARAMS_ERROR = -32602


class TerminalApprover:
    async def __call__(self, call: ToolCall, decision: Decision) -> bool:
        return await asyncio.to_thread(self._prompt, call, decision)

    @staticmethod
    def _prompt(call: ToolCall, decision: Decision) -> bool:
        path = "CON" if os.name == "nt" else "/dev/tty"
        try:
            with open(path, "r+", encoding="utf-8") as terminal:
                terminal.write(f"{call.name}: {decision.reason}. Approve? [y/N] ")
                terminal.flush()
                return terminal.readline().strip().lower() == "y"
        except OSError:
            print(
                "agent-firewall: no terminal available for approval",
                file=sys.stderr,
            )
            return False


class McpStdioProxy:
    def __init__(self, firewall: Firewall, command: Sequence[str]) -> None:
        if command and command[0] == "--":
            command = command[1:]
        if not command:
            raise ValueError("MCP server command is required after --")
        self.firewall = firewall
        self.command = list(command)
        self.process: asyncio.subprocess.Process | None = None
        self.pending: dict[str, asyncio.Future[Mapping[str, Any]]] = {}
        self.write_lock = asyncio.Lock()

    async def run(self) -> int:
        self.process = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )
        child_reader = asyncio.create_task(self._read_child())
        requests: list[asyncio.Task[None]] = []
        try:
            while True:
                line = await asyncio.to_thread(sys.stdin.buffer.readline)
                if not line:
                    break
                task = asyncio.create_task(self._handle_client_line(line))
                requests.append(task)
            if requests:
                await asyncio.gather(*requests)
        finally:
            if self.process.stdin is not None:
                self.process.stdin.close()
                try:
                    await self.process.stdin.wait_closed()
                except (BrokenPipeError, ConnectionResetError):
                    pass
            await child_reader
        return await self.process.wait()

    async def _handle_client_line(self, line: bytes) -> None:
        message = decode_message(line)
        if message is None:
            await self._write_child(line)
            return

        if message.get("method") != "tools/call":
            await self._passthrough_client_message(message, line)
            return

        # A tools/call must always pass through the policy. Never forward it
        # raw: a missing, null, or non-object params/name/arguments shape is a
        # protocol violation, but a lenient wrapped server may still execute
        # the tool, so every variant is evaluated (with no arguments) or
        # rejected instead of being passed through.
        params = message.get("params")
        tool_name = params.get("name") if isinstance(params, dict) else None
        if not isinstance(tool_name, str) or not tool_name.strip():
            self._reject(message, "tools/call requires a string tool name")
            return
        assert isinstance(params, dict)
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            arguments = {}

        async def forward() -> Mapping[str, Any] | None:
            if "id" not in message:
                await self._write_child(line)
                return None
            return await self._forward_request(message)

        try:
            response = await self.firewall.acall_with_arguments(
                tool_name,
                arguments,
                forward,
            )
        except FirewallError as exc:
            if "id" in message:
                self._write_client(
                    {
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "error": {
                            "code": POLICY_ERROR,
                            "message": "Tool call blocked by Agent Firewall",
                            "data": exc.decision.as_dict(),
                        },
                    }
                )
            return
        except Exception:
            self._reject(message, "internal firewall error; call not executed")
            return

        if response is not None:
            self._write_client(response)

    def _reject(self, message: Mapping[str, Any], text: str) -> None:
        if "id" not in message:
            return
        self._write_client(
            {
                "jsonrpc": "2.0",
                "id": message["id"],
                "error": {"code": INVALID_PARAMS_ERROR, "message": text},
            }
        )

    async def _passthrough_client_message(
        self,
        message: Mapping[str, Any],
        line: bytes,
    ) -> None:
        if "method" in message and "id" in message:
            response = await self._forward_request(message)
            self._write_client(response)
        else:
            await self._write_child(line)

    async def _forward_request(
        self,
        message: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        key = request_key(message["id"])
        if key in self.pending:
            return {
                "jsonrpc": "2.0",
                "id": message["id"],
                "error": {
                    "code": DUPLICATE_ID_ERROR,
                    "message": "Duplicate in-flight JSON-RPC id",
                },
            }
        future: asyncio.Future[Mapping[str, Any]] = (
            asyncio.get_running_loop().create_future()
        )
        self.pending[key] = future
        try:
            await self._write_child(encode_message(message))
            return await future
        finally:
            self.pending.pop(key, None)

    async def _read_child(self) -> None:
        assert self.process is not None
        assert self.process.stdout is not None
        try:
            while True:
                line = await self.process.stdout.readline()
                if not line:
                    break
                message = decode_message(line)
                if message is None or "method" in message or "id" not in message:
                    self._write_client_bytes(line)
                    continue
                future = self.pending.get(request_key(message["id"]))
                if future is None or future.done():
                    self._write_client_bytes(line)
                else:
                    future.set_result(message)
        finally:
            error = RuntimeError("wrapped MCP server exited before responding")
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(error)

    async def _write_child(self, line: bytes) -> None:
        assert self.process is not None
        assert self.process.stdin is not None
        async with self.write_lock:
            self.process.stdin.write(line)
            await self.process.stdin.drain()

    @staticmethod
    def _write_client(message: Mapping[str, Any]) -> None:
        McpStdioProxy._write_client_bytes(encode_message(message))

    @staticmethod
    def _write_client_bytes(line: bytes) -> None:
        sys.stdout.buffer.write(line)
        sys.stdout.buffer.flush()


async def run_mcp_proxy(
    policy_path: Path,
    command: Sequence[str],
    audit_path: Path | None = None,
    state_path: Path | None = None,
    approve_terminal: bool = False,
    approve_web: bool = False,
    approval_timeout: float = 300,
) -> int:
    if approve_terminal and approve_web:
        raise ValueError("choose either terminal or web approval")
    if approve_web and state_path is None:
        raise ValueError("--approve-web requires --state")
    approver: Approver | None
    if approve_web:
        assert state_path is not None
        approver = SQLiteApprovalQueue(
            state_path,
            timeout_seconds=approval_timeout,
        )
    elif approve_terminal:
        approver = TerminalApprover()
    else:
        approver = None
    firewall = Firewall.from_policy_file(
        policy_path,
        approver=approver,
        audit_path=audit_path,
        state_path=state_path,
    )
    return await McpStdioProxy(firewall, command).run()
