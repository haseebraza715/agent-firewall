from __future__ import annotations

from .models import Decision, ToolCall


class FirewallError(RuntimeError):
    def __init__(self, message: str, call: ToolCall, decision: Decision) -> None:
        super().__init__(message)
        self.call = call
        self.decision = decision


class ToolCallBlocked(FirewallError):
    pass


class ApprovalRequired(FirewallError):
    pass

