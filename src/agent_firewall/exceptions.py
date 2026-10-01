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


class StorageError(RuntimeError):
    """A firewall security record could not be read or written safely."""


class AuditWriteError(StorageError):
    """The append-only audit record could not be persisted (fail closed).

    ``after_execution`` is True when the write failed for a terminal event,
    meaning the call was already attempted: the tool either ran or its
    outcome is unknown. False means execution never started.
    """

    def __init__(
        self,
        message: str = "audit record could not be written",
        *,
        after_execution: bool = False,
    ) -> None:
        super().__init__(message)
        self.after_execution = after_execution
