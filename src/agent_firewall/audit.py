from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from .models import ArgumentAuditMode, Decision, ToolCall, Usage


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
            entry["arguments"] = _redact(call.arguments)
        elif argument_mode is ArgumentAuditMode.FULL:
            entry["arguments"] = call.arguments

        line = json.dumps(entry, separators=(",", ":"), sort_keys=True, default=repr)
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _redact(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    return "[REDACTED]"
