from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import sys
from collections.abc import Mapping, Sequence
from decimal import Decimal
from pathlib import Path
from typing import Any

from .approvals import SQLiteApprovalQueue
from .exceptions import ApprovalRequired, AuditWriteError, FirewallError
from .firewall import Approver, Firewall
from .jsonrpc import decode_message, encode_message, request_key
from .models import MAX_CALL_COST_USD, Decision, ToolCall, money

POLICY_ERROR = -32001
DUPLICATE_ID_ERROR = -32600
INVALID_REQUEST_ERROR = -32600
INVALID_PARAMS_ERROR = -32602
INTERNAL_ERROR = -32603
REQUEST_TIMEOUT_ERROR = -32002
CHILD_UNAVAILABLE_ERROR = -32003
PARSE_ERROR = -32700
METHOD_NOT_FOUND_ERROR = -32601
CALL_LIKE_METHOD = re.compile(
    r"[ \t\r\n\f\v]*tools[ \t\r\n\f\v]*/+[ \t\r\n\f\v]*call[ \t\r\n\f\v]*",
    re.IGNORECASE | re.ASCII,
)
DEFAULT_MAX_LINE_BYTES = 64 * 1024 * 1024


class McpRequestTimeoutError(TimeoutError):
    """The wrapped MCP server did not complete an exchange before its deadline."""


class McpChildUnavailableError(RuntimeError):
    """The wrapped MCP server exited or was terminated after a stalled write."""


def _is_batch(line: bytes) -> bool:
    """Return True when the line parses as a JSON-RPC batch (a JSON array).

    Batches can smuggle ``tools/call`` messages past the per-line policy
    check, so they are never forwarded.
    """
    stripped = line.lstrip()
    if not stripped.startswith(b"["):
        return False
    try:
        value = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return False
    return isinstance(value, list)


def _read_line(stream: Any, limit: int) -> tuple[bytes, bool]:
    """Read one newline-terminated line, bounding the memory it can use.

    Returns ``(line, oversized)``. When oversized, the remainder of the
    oversized line is drained so the stream stays frame-aligned and the
    caller can reject the request without losing the messages that follow.
    """
    line = stream.readline(limit + 1)
    if len(line) <= limit:
        return line, False
    while line and not line.endswith(b"\n"):
        chunk = stream.readline(65536)
        if not chunk:
            break
        line = chunk
    return b"", True


async def _read_child_line(
    stream: asyncio.StreamReader,
    limit: int,
    remainder: bytearray,
) -> tuple[bytes, bool, bytearray]:
    """Bounded ``StreamReader`` twin of ``_read_line`` for child responses.

    ``StreamReader.read`` consumes what it returns, so a chunk can hold
    several newline-terminated lines. Bytes after the first newline are
    returned as ``remainder`` and prepended to the next call's line instead
    of being lost; the same applies while draining an oversized line.
    """
    line = bytearray()
    if remainder:
        line.extend(remainder)
        remainder.clear()
        newline_index = line.find(b"\n")
        if newline_index != -1:
            line_end = newline_index + 1
            if len(line) > limit:
                return b"", True, bytearray(line[line_end:])
            return bytes(line[:line_end]), False, bytearray(line[line_end:])
    while True:
        if len(line) > limit:
            drain = await stream.read(65536)
            if not drain:
                return b"", True, bytearray()
            newline_index = drain.find(b"\n")
            if newline_index != -1:
                return b"", True, bytearray(drain[newline_index + 1 :])
            continue
        chunk = await stream.read(limit + 1 - len(line))
        if not chunk:
            if len(line) > limit:
                return b"", True, bytearray()
            return bytes(line), False, bytearray()
        newline_index = chunk.find(b"\n")
        if newline_index != -1:
            line.extend(chunk[: newline_index + 1])
            if len(line) > limit:
                return b"", True, bytearray(chunk[newline_index + 1 :])
            return bytes(line), False, bytearray(chunk[newline_index + 1 :])
        line.extend(chunk)


_ARGS_PREVIEW_LIMIT = 120


def _args_preview(call: ToolCall) -> str:
    try:
        text = json.dumps(call.arguments, ensure_ascii=False, default=repr)
    except (TypeError, ValueError):
        text = repr(call.arguments)
    if len(text) > _ARGS_PREVIEW_LIMIT:
        text = text[: _ARGS_PREVIEW_LIMIT - 3] + "..."
    return text


class TerminalApprover:
    """Interactive [y/N] approval on the controlling terminal.

    The prompt shows the tool, its arguments, and the policy reason so a
    human decides with the same data the policy saw. Anything other than
    y/yes denies; garbage input gets one retry before denial.
    """

    async def __call__(self, call: ToolCall, decision: Decision) -> bool:
        return await asyncio.to_thread(self._decide, call, decision)

    def _decide(self, call: ToolCall, decision: Decision) -> bool:
        path = "CON" if os.name == "nt" else "/dev/tty"
        try:
            with open(path, "r+", encoding="utf-8") as terminal:
                return self._prompt(call, decision, terminal)
        except OSError:
            print(
                "agent-firewall: no terminal available for approval",
                file=sys.stderr,
            )
            return False

    @staticmethod
    def _prompt(
        call: ToolCall,
        decision: Decision,
        terminal: Any,
    ) -> bool:
        prompt = (
            f"agent-firewall approval\n"
            f"  tool: {call.name}\n"
            f"  arguments: {_args_preview(call)}\n"
            f"  reason: {decision.reason}\n"
            f"  Approve? [y/N] "
        )
        for _ in range(2):
            terminal.write(prompt)
            try:
                answer = terminal.readline().strip().lower()
            except EOFError:
                print("agent-firewall: approval input ended; denied", file=sys.stderr)
                return False
            if answer in ("y", "yes"):
                return True
            if answer in ("n", "no"):
                return False
            if answer == "":
                print("agent-firewall: approval input ended; denied", file=sys.stderr)
                return False
            prompt = "Answer y or n. Approve? [y/N] "
        return False


class McpStdioProxy:
    def __init__(
        self,
        firewall: Firewall,
        command: Sequence[str],
        request_timeout: float = 300,
        max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
        hold_hint: str | None = None,
    ) -> None:
        if command and command[0] == "--":
            command = command[1:]
        if not command:
            raise ValueError("MCP server command is required after --")
        if request_timeout <= 0:
            raise ValueError("request timeout must be positive")
        if max_line_bytes <= 0:
            raise ValueError("max line bytes must be positive")
        self.firewall = firewall
        self.command = list(command)
        self.request_timeout = request_timeout
        self.max_line_bytes = max_line_bytes
        self.hold_hint = hold_hint
        self.process: asyncio.subprocess.Process | None = None
        self.pending: dict[str, asyncio.Future[Mapping[str, Any]]] = {}
        self._client_pending: set[str] = set()
        self._request_sequence = 0
        self._internal_id_prefix = f"agent-firewall:{secrets.token_hex(16)}:"
        self._child_failure: str | None = None
        self._hold_hint_shown = False
        # Construct lazily inside the running loop. Python 3.9 binds asyncio
        # primitives at construction time, and callers may build the proxy
        # before entering asyncio.run().
        self.write_lock: asyncio.Lock | None = None

    async def run(self) -> int:
        self.process = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )
        print(
            f"agent-firewall: spawned {' '.join(self.command)} "
            f"(pid {self.process.pid})",
            file=sys.stderr,
            flush=True,
        )
        child_reader = asyncio.create_task(self._read_child())
        requests: list[asyncio.Task[None]] = []
        try:
            while True:
                line, oversized = await asyncio.to_thread(
                    _read_line, sys.stdin.buffer, self.max_line_bytes
                )
                if oversized:
                    self._write_client(self._parse_error_response("request too large"))
                    continue
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
        returncode = await self.process.wait()
        print(
            f"agent-firewall: child exited rc={returncode}",
            file=sys.stderr,
            flush=True,
        )
        return returncode

    async def _handle_client_line(self, line: bytes) -> None:
        try:
            message = decode_message(line)
        except ValueError as exc:
            self._write_client(
                self._parse_error_response(f"invalid JSON-RPC message: {exc}")
            )
            return
        if message is None:
            if _is_batch(line):
                self._reject_batch(line)
                return
            if not line.strip():
                return
            # Undecodable or non-object lines are never forwarded: a lenient
            # wrapped server might salvage a tools/call out of them, so they
            # are rejected here instead of bypassing the policy.
            self._write_client(self._parse_error_response("invalid JSON-RPC message"))
            return

        method = message.get("method")
        if not isinstance(method, str):
            if "method" not in message and ("result" in message or "error" in message):
                # A client response to a server-initiated request.
                await self._passthrough_client_message(message, line)
                return
            # JSON-RPC requires a string method. A lenient wrapped server
            # might still act on anything else, so it is never forwarded.
            self._write_error(
                message, INVALID_REQUEST_ERROR, "JSON-RPC method must be a string"
            )
            return
        if method != "tools/call":
            if CALL_LIKE_METHOD.fullmatch(method):
                self._write_error(
                    message,
                    METHOD_NOT_FOUND_ERROR,
                    "unsupported tools/call alias; use exact tools/call",
                )
                return
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
            self._write_error(
                message, INVALID_PARAMS_ERROR, "tools/call requires a string tool name"
            )
            return
        assert isinstance(params, dict)
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            self._write_error(
                message, INVALID_PARAMS_ERROR, "tools/call arguments must be an object"
            )
            return
        try:
            estimated_cost_usd = _extract_cost(params.get("_meta"))
        except ValueError:
            self._write_error(
                message,
                INVALID_PARAMS_ERROR,
                "params._meta.estimated_cost_usd must be a non-negative finite number",
            )
            return

        client_key: str | None = None
        if "id" in message:
            client_key = self._claim_client_id(message)
            if client_key is None:
                return

        async def forward() -> Mapping[str, Any] | None:
            if "id" not in message:
                await self._write_child_with_timeout(line)
                return None
            return await self._forward_request(message)

        try:
            response = await self.firewall.acall_with_arguments(
                tool_name,
                arguments,
                forward,
                estimated_cost_usd=estimated_cost_usd,
            )
        except FirewallError as exc:
            if isinstance(exc, ApprovalRequired):
                if self.hold_hint and not self._hold_hint_shown:
                    print(
                        f"agent-firewall: {self.hold_hint}",
                        file=sys.stderr,
                        flush=True,
                    )
                    self._hold_hint_shown = True
                text = "tool call requires approval but no approver is configured"
            else:
                text = "Tool call blocked by Agent Firewall"
            if "id" in message:
                self._write_client(
                    {
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "error": {
                            "code": POLICY_ERROR,
                            "message": text,
                            "data": exc.decision.as_dict(),
                        },
                    }
                )
            return
        except McpRequestTimeoutError:
            if "id" in message:
                self._write_client(self._timeout_response(message["id"]))
            return
        except McpChildUnavailableError:
            if "id" in message:
                self._write_client(self._child_unavailable_response(message["id"]))
            return
        except AuditWriteError as exc:
            self._write_error(
                message,
                INTERNAL_ERROR,
                ("tool ran or was attempted but its audit record could not be written")
                if exc.after_execution
                else "internal firewall error; call not executed",
            )
            return
        except Exception:
            self._write_error(
                message, INTERNAL_ERROR, "internal firewall error; call not executed"
            )
            return
        finally:
            if client_key is not None:
                self._client_pending.discard(client_key)

        if response is not None:
            self._write_client(response)

    def _write_error(
        self,
        message: Mapping[str, Any],
        code: int,
        text: str,
    ) -> None:
        if "id" not in message:
            return
        self._write_client(
            {
                "jsonrpc": "2.0",
                "id": message["id"],
                "error": {"code": code, "message": text},
            }
        )

    @staticmethod
    def _parse_error_response(text: str) -> Mapping[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": PARSE_ERROR, "message": text},
        }

    def _reject_batch(self, line: bytes) -> None:
        """Answer every batch element that carries an id; never forward it."""
        try:
            batch = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            return
        if not isinstance(batch, list):
            return
        errors = [
            {
                "jsonrpc": "2.0",
                "id": item["id"],
                "error": {
                    "code": -32600,
                    "message": "batch requests are not supported",
                },
            }
            for item in batch
            if isinstance(item, dict) and "id" in item
        ]
        if errors:
            payload = (
                json.dumps(errors, separators=(",", ":"), ensure_ascii=False) + "\n"
            ).encode("utf-8")
            self._write_client_bytes(payload)

    async def _passthrough_client_message(
        self,
        message: Mapping[str, Any],
        line: bytes,
    ) -> None:
        if "method" in message and "id" in message:
            client_key = self._claim_client_id(message)
            if client_key is None:
                return
            try:
                response = await self._forward_request(message)
                self._write_client(response)
            except McpRequestTimeoutError:
                self._write_client(self._timeout_response(message["id"]))
            except McpChildUnavailableError:
                self._write_client(self._child_unavailable_response(message["id"]))
            finally:
                self._client_pending.discard(client_key)
        else:
            try:
                await self._write_child_with_timeout(line)
            except (McpRequestTimeoutError, McpChildUnavailableError):
                pass

    def _claim_client_id(self, message: Mapping[str, Any]) -> str | None:
        """Atomically claim an id before policy reservation or child forwarding."""
        client_key = request_key(message["id"])
        if client_key in self._client_pending:
            self._write_client(
                {
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "error": {
                        "code": DUPLICATE_ID_ERROR,
                        "message": "Duplicate in-flight JSON-RPC id",
                    },
                }
            )
            return None
        # No await occurs between the membership test and insertion, making
        # this claim atomic within the proxy's asyncio event loop.
        self._client_pending.add(client_key)
        return client_key

    async def _forward_request(
        self,
        message: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        if self._child_failure is not None:
            raise McpChildUnavailableError(self._child_failure)
        self._request_sequence += 1
        internal_id = f"{self._internal_id_prefix}{self._request_sequence}"
        internal_key = request_key(internal_id)
        child_message = dict(message)
        child_message["id"] = internal_id
        future: asyncio.Future[Mapping[str, Any]] = (
            asyncio.get_running_loop().create_future()
        )
        self.pending[internal_key] = future
        try:
            loop = asyncio.get_running_loop()
            deadline = loop.time() + self.request_timeout
            try:
                await asyncio.wait_for(
                    self._write_child(encode_message(child_message)),
                    timeout=self.request_timeout,
                )
            except asyncio.TimeoutError as exc:
                await self._abort_child()
                raise McpRequestTimeoutError from exc
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise McpRequestTimeoutError
            try:
                response = await asyncio.wait_for(
                    asyncio.shield(future), timeout=remaining
                )
            except asyncio.TimeoutError as exc:
                raise McpRequestTimeoutError from exc
            return {**response, "id": message["id"]}
        finally:
            self.pending.pop(internal_key, None)

    @staticmethod
    def _timeout_response(request_id: Any) -> Mapping[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": REQUEST_TIMEOUT_ERROR,
                "message": "timed out waiting for wrapped MCP server",
            },
        }

    @staticmethod
    def _child_unavailable_response(request_id: Any) -> Mapping[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": CHILD_UNAVAILABLE_ERROR,
                "message": "wrapped MCP server is unavailable after a stalled write",
            },
        }

    async def _read_child(self) -> None:
        assert self.process is not None
        assert self.process.stdout is not None
        remainder = bytearray()
        try:
            while True:
                line, oversized, remainder = await _read_child_line(
                    self.process.stdout, self.max_line_bytes, remainder
                )
                if oversized:
                    continue
                if not line:
                    break
                try:
                    message = decode_message(line)
                except ValueError:
                    continue
                if message is None or "method" in message or "id" not in message:
                    self._write_client_bytes(line)
                    continue
                key = request_key(message["id"])
                future = self.pending.get(key)
                if future is not None and not future.done():
                    future.set_result(message)
                elif isinstance(message["id"], str) and message["id"].startswith(
                    self._internal_id_prefix
                ):
                    # Every proxied request uses a unique child-facing id. A
                    # response for one with no pending future is necessarily
                    # late and must not escape to the client.
                    continue
                else:
                    self._write_client_bytes(line)
        finally:
            error = McpChildUnavailableError(
                self._child_failure or "wrapped MCP server exited before responding"
            )
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(error)

    async def _write_child(self, line: bytes) -> None:
        assert self.process is not None
        assert self.process.stdin is not None
        if self.write_lock is None:
            self.write_lock = asyncio.Lock()
        async with self.write_lock:
            self.process.stdin.write(line)
            await self.process.stdin.drain()

    async def _write_child_with_timeout(self, line: bytes) -> None:
        if self._child_failure is not None:
            raise McpChildUnavailableError(self._child_failure)
        try:
            await asyncio.wait_for(
                self._write_child(line), timeout=self.request_timeout
            )
        except asyncio.TimeoutError as exc:
            await self._abort_child()
            raise McpRequestTimeoutError from exc

    async def _abort_child(self) -> None:
        """Stop a stalled child so a cancelled drain cannot corrupt framing."""
        self._child_failure = (
            "wrapped MCP server terminated after a stalled stdin write"
        )
        print(
            "agent-firewall: aborted wrapped MCP server after stalled write",
            file=sys.stderr,
            flush=True,
        )
        if self.process is None:
            return
        child_stdin = self.process.stdin
        if child_stdin is not None:
            child_stdin.close()
        if self.process.returncode is None:
            try:
                self.process.terminate()
            except ProcessLookupError:
                return
            try:
                await asyncio.wait_for(self.process.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                self.process.kill()
                await self.process.wait()
        if child_stdin is not None:
            try:
                await child_stdin.wait_closed()
            except (BrokenPipeError, ConnectionResetError):
                pass

    @staticmethod
    def _write_client(message: Mapping[str, Any]) -> None:
        try:
            McpStdioProxy._write_client_bytes(encode_message(message))
        except ValueError:
            fallback = {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "error": {
                    "code": PARSE_ERROR,
                    "message": "response too deeply nested to encode",
                },
            }
            try:
                McpStdioProxy._write_client_bytes(encode_message(fallback))
            except ValueError:
                pass

    @staticmethod
    def _write_client_bytes(line: bytes) -> None:
        try:
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()
        except OSError:
            # The client closed its side; the proxy keeps draining stdin so
            # the wrapped child shuts down cleanly.
            pass


async def run_mcp_proxy(
    policy_path: Path,
    command: Sequence[str],
    audit_path: Path | None = None,
    state_path: Path | None = None,
    approve_terminal: bool = False,
    approve_web: bool = False,
    approval_timeout: float = 300,
    request_timeout: float = 300,
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
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
        print(
            "agent-firewall: approvals come from the dashboard; start it with: "
            f"agent-firewall dashboard --policy {policy_path} "
            f"--state {state_path}" + (f" --audit {audit_path}" if audit_path else ""),
            file=sys.stderr,
            flush=True,
        )
        hold_hint = None
    elif approve_terminal:
        approver = TerminalApprover()
        hold_hint = None
    else:
        approver = None
        hold_hint = (
            "call held but no approver is configured; restart with "
            "--approve-terminal or --approve-web"
        )
    firewall = Firewall.from_policy_file(
        policy_path,
        approver=approver,
        audit_path=audit_path,
        state_path=state_path,
    )
    return await McpStdioProxy(
        firewall,
        command,
        request_timeout=request_timeout,
        max_line_bytes=max_line_bytes,
        hold_hint=hold_hint,
    ).run()


def _extract_cost(meta: Any) -> Decimal:
    """Read the optional per-call cost from ``params._meta``.

    An absent ``_meta``, a non-dict ``_meta``, or a ``_meta`` without an
    ``estimated_cost_usd`` key all mean zero cost. A present value must be a
    non-negative finite decimal within the supported per-call range; anything
    else raises ``ValueError`` so the caller can reject the call fail-closed
    instead of executing it with an ambiguous cost.
    """
    if not isinstance(meta, dict) or "estimated_cost_usd" not in meta:
        return Decimal("0")
    return money(meta["estimated_cost_usd"], max_value=MAX_CALL_COST_USD)
