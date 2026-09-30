from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from .exceptions import AuditWriteError
from .models import ArgumentAuditMode, Decision, ToolCall, Usage, bounded


class JsonlAuditLog:
    """Append-only audit log that deliberately excludes tool arguments."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = Lock()

    def record(
        self,
        event: str,
        call: ToolCall,
        usage: Usage,
        decision: Decision | None = None,
        error: str | None = None,
        argument_mode: ArgumentAuditMode = ArgumentAuditMode.NONE,
    ) -> None:
        entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "call_id": call.id,
            "tool": call.name,
            "estimated_cost_usd": str(call.estimated_cost_usd),
            "usage": {
                "tool_calls": usage.tool_calls,
                "estimated_cost_usd": str(usage.estimated_cost_usd),
            },
        }
        if decision is not None:
            entry.update(decision.as_dict())
        if error is not None:
            entry["error"] = error
        if argument_mode is ArgumentAuditMode.HASH:
            entry["call_fingerprint"] = call.fingerprint
        elif argument_mode is ArgumentAuditMode.REDACTED:
            entry["arguments"] = _redact(bounded(call.arguments))
        elif argument_mode is ArgumentAuditMode.FULL:
            entry["arguments"] = bounded(call.arguments)

        line = json.dumps(entry, separators=(",", ":"), sort_keys=True, default=repr)
        try:
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a+b") as handle:
                    handle.seek(0, os.SEEK_END)
                    if handle.tell():
                        handle.seek(-1, os.SEEK_END)
                        if handle.read(1) != b"\n":
                            raise AuditWriteError(
                                "audit log has an incomplete final record at "
                                f"{self.path}; "
                                "preserve it and configure a new audit path"
                            )
                    handle.write((line + "\n").encode("utf-8"))
        except OSError as exc:
            raise AuditWriteError(
                f"could not append firewall audit record to {self.path}"
            ) from exc


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _redact(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    return "[REDACTED]"
