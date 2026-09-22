from __future__ import annotations

import asyncio
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from .approvals import SQLiteApprovalQueue
from .exceptions import FirewallError
from .firewall import Approver, Firewall
from .models import Decision, ToolCall

POLICY_ERROR = -32001
DUPLICATE_ID_ERROR = -32600
PARSE_ERROR = -32700
SERVER_UNAVAILABLE_ERROR = -32002
STDIO_LINE_LIMIT = 64 * 1024 * 1024


class WrappedServerUnavailable(RuntimeError):
    pass


class TerminalApprover:
    async def __call__(self, call: ToolCall, decision: Decision) -> bool:
        return await asyncio.to_thread(self._prompt, call, decision)

    @staticmethod
    def _prompt(call: ToolCall, decision: Decision) -> bool:
        try:
            if os.name == "nt":
                with open("CONOUT$", "w", encoding="utf-8") as output:
                    output.write(f"{call.name}: {decision.reason}. Approve? [y/N] ")
                    output.flush()
                with open("CONIN$", encoding="utf-8") as terminal:
                    return terminal.readline().strip().lower() == "y"
            with open("/dev/tty", "r+", encoding="utf-8") as terminal:
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
        self.client_tasks: dict[str, asyncio.Task[None]] = {}
        self.client_methods: dict[str, str] = {}
        self.cancelled_downstream: set[str] = set()
        self.write_lock = asyncio.Lock()

    async def run(self) -> int:
        try:
            self.process = await asyncio.create_subprocess_exec(
                *self.command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                limit=STDIO_LINE_LIMIT,
            )
        except FileNotFoundError as exc:
            raise ValueError(
                f"MCP server command not found: {self.command[0]}"
            ) from exc
        except PermissionError as exc:
            raise ValueError(
                f"MCP server command is not executable: {self.command[0]}"
            ) from exc
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
                results = await asyncio.gather(*requests, return_exceptions=True)
                for result in results:
                    if isinstance(result, BaseException) and not isinstance(
                        result, asyncio.CancelledError
                    ):
                        print(
                            f"agent-firewall: request handler failed: {result}",
                            file=sys.stderr,
                        )
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
        message = _decode(line)
        if message is None:
            self._write_client(_error_response(None, PARSE_ERROR, "Parse error"))
            return

        invalid = _invalid_client_message_error(message)
        if invalid is not None:
            self._write_client(invalid)
            return

        if _is_cancelled_notification(message):
            await self._handle_cancelled_notification(message)
            return

        if "method" in message and "id" in message:
            key = _request_key(message["id"])
            if key in self.client_tasks:
                self._write_client(_duplicate_id_response(message["id"]))
                return
            current = asyncio.current_task()
            if current is not None:
                self.client_tasks[key] = current
                self.client_methods[key] = str(message["method"])
            try:
                await self._handle_client_message(message, line)
            except asyncio.CancelledError:
                return
            finally:
                self.client_tasks.pop(key, None)
                self.client_methods.pop(key, None)
            return

        await self._handle_client_message(message, line)

    async def _handle_client_message(
        self,
        message: Mapping[str, Any],
        line: bytes,
    ) -> None:
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
        except asyncio.CancelledError:
            return
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

    async def _handle_cancelled_notification(
        self,
        message: Mapping[str, Any],
    ) -> None:
        params = message.get("params")
        if not isinstance(params, dict):
            return
        request_id = params.get("requestId")
        if not _is_request_id(request_id):
            return
        key = _request_key(request_id)
        if self.client_methods.get(key) == "initialize":
            return
        if key in self.pending:
            self.cancelled_downstream.add(key)
            await self._write_child_if_available(_encode(message))
        task = self.client_tasks.get(key)
        if task is not None and not task.done():
            task.cancel()

    async def _passthrough_client_message(
        self,
        message: Mapping[str, Any],
        line: bytes,
    ) -> None:
        if "method" in message and "id" in message:
            response = await self._forward_request(message)
            self._write_client(response)
        else:
            await self._write_child_if_available(line)

    async def _forward_request(
        self,
        message: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        key = _request_key(message["id"])
        if key in self.pending:
            return _duplicate_id_response(message["id"])
        future: asyncio.Future[Mapping[str, Any]] = (
            asyncio.get_running_loop().create_future()
        )
        self.pending[key] = future
        try:
            try:
                await self._write_child(_encode(message))
            except WrappedServerUnavailable:
                return _server_unavailable_response(message["id"])
            return await future
        except WrappedServerUnavailable:
            return _server_unavailable_response(message["id"])
        except asyncio.CancelledError:
            future.cancel()
            raise
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
                if message is None:
                    self._write_client(
                        _error_response(
                            None,
                            PARSE_ERROR,
                            "Wrapped MCP server sent invalid JSON-RPC",
                        )
                    )
                    continue
                if "method" in message or "id" not in message:
                    self._write_client_bytes(line)
                    continue
                key = _request_key(message["id"])
                if key in self.cancelled_downstream:
                    self.cancelled_downstream.discard(key)
                    continue
                future = self.pending.get(key)
                if future is None or future.done():
                    self._write_client_bytes(line)
                else:
                    future.set_result(message)
        finally:
            error = WrappedServerUnavailable(
                "wrapped MCP server exited before responding"
            )
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(error)

    async def _write_child(self, line: bytes) -> None:
        assert self.process is not None
        assert self.process.stdin is not None
        if self.process.returncode is not None or self.process.stdin.is_closing():
            raise WrappedServerUnavailable
        async with self.write_lock:
            try:
                self.process.stdin.write(line)
                await self.process.stdin.drain()
            except (BrokenPipeError, ConnectionResetError) as exc:
                raise WrappedServerUnavailable from exc

    async def _write_child_if_available(self, line: bytes) -> bool:
        try:
            await self._write_child(line)
        except WrappedServerUnavailable:
            return False
        return True

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


def _request_key(request_id: Any) -> str:
    return json.dumps(request_id, sort_keys=True, separators=(",", ":"))


def _is_request_id(value: Any) -> bool:
    return isinstance(value, (str, int)) and not isinstance(value, bool)


def _error_response(
    request_id: Any | None,
    code: int,
    message: str,
    data: Any | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    response: dict[str, Any] = {"jsonrpc": "2.0", "error": error}
    if request_id is not None:
        response["id"] = request_id
    return response


def _duplicate_id_response(request_id: Any) -> dict[str, Any]:
    return _error_response(
        request_id,
        DUPLICATE_ID_ERROR,
        "Duplicate in-flight JSON-RPC id",
    )


def _server_unavailable_response(request_id: Any) -> dict[str, Any]:
    return _error_response(
        request_id,
        SERVER_UNAVAILABLE_ERROR,
        "Wrapped MCP server exited before responding",
    )


def _invalid_client_message_error(
    message: Mapping[str, Any],
) -> dict[str, Any] | None:
    request_id = message.get("id")
    response_id = request_id if _is_request_id(request_id) else None
    if message.get("jsonrpc") != "2.0":
        return _error_response(response_id, DUPLICATE_ID_ERROR, "Invalid JSON-RPC")

    method = message.get("method")
    if method is not None:
        if not isinstance(method, str) or not method:
            return _error_response(
                response_id,
                DUPLICATE_ID_ERROR,
                "Invalid JSON-RPC method",
            )
        if "id" in message and not _is_request_id(request_id):
            return _error_response(None, DUPLICATE_ID_ERROR, "Invalid JSON-RPC id")
        return None

    if "id" in message:
        if not _is_request_id(request_id):
            return _error_response(None, DUPLICATE_ID_ERROR, "Invalid JSON-RPC id")
        has_result = "result" in message
        has_error = "error" in message
        if has_result == has_error:
            return _error_response(
                request_id,
                DUPLICATE_ID_ERROR,
                "Invalid JSON-RPC response",
            )
        return None

    return _error_response(None, DUPLICATE_ID_ERROR, "Invalid JSON-RPC")


def _is_cancelled_notification(message: Mapping[str, Any]) -> bool:
    return message.get("method") == "notifications/cancelled" and "id" not in message


def _decode(line: bytes) -> Mapping[str, Any] | None:
    try:
        message = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return cast(Mapping[str, Any], message) if isinstance(message, dict) else None


def _encode(message: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(message, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode("utf-8")
