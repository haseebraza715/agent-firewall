from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from .exceptions import FirewallError
from .firewall import Firewall
from .models import Decision, ToolCall

POLICY_ERROR = -32001


class TerminalApprover:
    async def __call__(self, call: ToolCall, decision: Decision) -> bool:
        return await asyncio.to_thread(self._prompt, call, decision)

    @staticmethod
    def _prompt(call: ToolCall, decision: Decision) -> bool:
        path = "CON" if os.name == "nt" else "/dev/tty"
        try:
            with open(path, "r+", encoding="utf-8") as terminal:
                terminal.write(
                    "{}: {}. Approve? [y/N] ".format(call.name, decision.reason)
                )
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
        self.process: Optional[asyncio.subprocess.Process] = None
        self.pending: Dict[str, asyncio.Future] = {}
        self.write_lock = asyncio.Lock()

    async def run(self) -> int:
        self.process = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )
        child_reader = asyncio.create_task(self._read_child())
        requests: List[asyncio.Task] = []
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
                await self.process.stdin.wait_closed()
            await child_reader
        return await self.process.wait()

    async def _handle_client_line(self, line: bytes) -> None:
        message = _decode(line)
        if message is None:
            await self._write_child(line)
            return

        if message.get("method") != "tools/call":
            await self._passthrough_client_message(message, line)
            return

        params = message.get("params")
        if not isinstance(params, dict):
            await self._passthrough_client_message(message, line)
            return
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(tool_name, str) or not isinstance(arguments, dict):
            await self._passthrough_client_message(message, line)
            return

        async def forward(**_: Any) -> Optional[Mapping[str, Any]]:
            if "id" not in message:
                await self._write_child(line)
                return None
            return await self._forward_request(message)

        try:
            response = await self.firewall.acall(
                tool_name,
                forward,
                **arguments
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

        if response is not None:
            self._write_client(response)

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
        key = _request_key(message["id"])
        if key in self.pending:
            raise ValueError("duplicate in-flight JSON-RPC id")
        future = asyncio.get_running_loop().create_future()
        self.pending[key] = future
        try:
            await self._write_child(_encode(message))
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
                message = _decode(line)
                if message is None or "method" in message or "id" not in message:
                    self._write_client_bytes(line)
                    continue
                future = self.pending.get(_request_key(message["id"]))
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
        McpStdioProxy._write_client_bytes(_encode(message))

    @staticmethod
    def _write_client_bytes(line: bytes) -> None:
        sys.stdout.buffer.write(line)
        sys.stdout.buffer.flush()


async def run_mcp_proxy(
    policy_path: Path,
    command: Sequence[str],
    audit_path: Optional[Path] = None,
    approve_terminal: bool = False,
) -> int:
    approver = TerminalApprover() if approve_terminal else None
    firewall = Firewall.from_policy_file(
        policy_path,
        approver=approver,
        audit_path=audit_path,
    )
    return await McpStdioProxy(firewall, command).run()


def _request_key(request_id: Any) -> str:
    return json.dumps(request_id, sort_keys=True, separators=(",", ":"))


def _decode(line: bytes) -> Optional[Mapping[str, Any]]:
    try:
        message = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return message if isinstance(message, dict) else None


def _encode(message: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(message, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode("utf-8")
