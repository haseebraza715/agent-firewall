from __future__ import annotations

import inspect
from functools import wraps
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping, Optional, Union

from .audit import JsonlAuditLog
from .exceptions import ApprovalRequired, ToolCallBlocked
from .models import Decision, DecisionKind, ToolCall, Usage
from .policy import Policy
from .state import MemoryStateStore, SQLiteStateStore, StateStore

ApproverResult = Union[bool, Awaitable[bool]]
Approver = Callable[[ToolCall, Decision], ApproverResult]


class Firewall:
    def __init__(
        self,
        policy: Policy,
        approver: Optional[Approver] = None,
        audit_log: Optional[JsonlAuditLog] = None,
        state_store: Optional[StateStore] = None,
    ) -> None:
        self.policy = policy
        self.approver = approver
        self.audit_log = audit_log
        self.state_store = state_store or MemoryStateStore()

    @classmethod
    def from_policy_file(
        cls,
        policy_path: Path,
        approver: Optional[Approver] = None,
        audit_path: Optional[Path] = None,
        state_path: Optional[Path] = None,
    ) -> "Firewall":
        audit_log = JsonlAuditLog(audit_path) if audit_path else None
        state_store = SQLiteStateStore(state_path) if state_path else None
        return cls(
            Policy.load(policy_path),
            approver=approver,
            audit_log=audit_log,
            state_store=state_store,
        )

    @property
    def usage(self) -> Usage:
        return self.state_store.usage()

    def check(
        self,
        tool_name: str,
        arguments: Optional[Mapping[str, Any]] = None,
        estimated_cost_usd: Any = 0,
    ) -> Decision:
        call = ToolCall.create(tool_name, arguments, estimated_cost_usd)
        return self.policy.evaluate(call, self.usage)

    def call(
        self,
        tool_name: str,
        tool: Callable[..., Any],
        *args: Any,
        estimated_cost_usd: Any = 0,
        **kwargs: Any
    ) -> Any:
        call = ToolCall.create(
            tool_name,
            _call_arguments(args, kwargs),
            estimated_cost_usd,
        )
        decision = self._authorize(call)
        if decision.kind is DecisionKind.REQUIRE_APPROVAL:
            self._approve_sync(call, decision)

        try:
            result = tool(*args, **kwargs)
        except Exception as exc:
            self._audit("failed", call, decision, type(exc).__name__)
            raise
        self._audit("executed", call, decision)
        return result

    async def acall(
        self,
        tool_name: str,
        tool: Callable[..., Any],
        *args: Any,
        estimated_cost_usd: Any = 0,
        **kwargs: Any
    ) -> Any:
        call = ToolCall.create(
            tool_name,
            _call_arguments(args, kwargs),
            estimated_cost_usd,
        )
        decision = self._authorize(call)
        if decision.kind is DecisionKind.REQUIRE_APPROVAL:
            await self._approve_async(call, decision)

        try:
            result = tool(*args, **kwargs)
            if inspect.isawaitable(result):
                result = await result
        except Exception as exc:
            self._audit("failed", call, decision, type(exc).__name__)
            raise
        self._audit("executed", call, decision)
        return result

    def wrap(
        self,
        tool_name: str,
        tool: Callable[..., Any],
        estimated_cost_usd: Any = 0,
    ) -> Callable[..., Any]:
        if inspect.iscoroutinefunction(tool):

            @wraps(tool)
            async def async_guarded(*args: Any, **kwargs: Any) -> Any:
                return await self.acall(
                    tool_name,
                    tool,
                    *args,
                    estimated_cost_usd=estimated_cost_usd,
                    **kwargs
                )

            return async_guarded

        @wraps(tool)
        def guarded(*args: Any, **kwargs: Any) -> Any:
            return self.call(
                tool_name,
                tool,
                *args,
                estimated_cost_usd=estimated_cost_usd,
                **kwargs
            )

        return guarded

    def _authorize(self, call: ToolCall) -> Decision:
        result = self.state_store.evaluate_and_reserve(self.policy, call)
        decision = result.decision
        usage = result.usage

        if decision.kind is DecisionKind.BLOCK:
            self._audit("blocked", call, decision, usage=usage)
            raise ToolCallBlocked(decision.reason, call, decision)
        if decision.kind is DecisionKind.REQUIRE_APPROVAL:
            self._audit("approval_requested", call, decision, usage=usage)
        else:
            self._audit("allowed", call, decision, usage=usage)
        return decision

    def _approve_sync(self, call: ToolCall, decision: Decision) -> None:
        if self.approver is None:
            raise ApprovalRequired(decision.reason, call, decision)
        approved = self.approver(call, decision)
        if inspect.isawaitable(approved):
            close = getattr(approved, "close", None)
            if close is not None:
                close()
            raise TypeError("async approver requires Firewall.acall")
        self._finish_approval(call, decision, bool(approved))

    async def _approve_async(self, call: ToolCall, decision: Decision) -> None:
        if self.approver is None:
            raise ApprovalRequired(decision.reason, call, decision)
        approved = self.approver(call, decision)
        if inspect.isawaitable(approved):
            approved = await approved
        self._finish_approval(call, decision, bool(approved))

    def _finish_approval(
        self,
        call: ToolCall,
        decision: Decision,
        approved: bool,
    ) -> None:
        if not approved:
            denied = Decision(
                DecisionKind.BLOCK,
                "human approval denied",
                "approval_denied",
                decision.rule_index,
            )
            self._audit("approval_denied", call, denied)
            raise ToolCallBlocked(denied.reason, call, denied)

        result = self.state_store.evaluate_and_reserve(
            self.policy,
            call,
            approved=True,
        )
        current = result.decision
        usage = result.usage

        if current.kind is DecisionKind.BLOCK:
            self._audit("blocked", call, current, usage=usage)
            raise ToolCallBlocked(current.reason, call, current)
        self._audit("approval_granted", call, decision, usage=usage)

    def _audit(
        self,
        event: str,
        call: ToolCall,
        decision: Decision,
        error: Optional[str] = None,
        usage: Optional[Usage] = None,
    ) -> None:
        if self.audit_log is not None:
            self.audit_log.record(
                event,
                call,
                usage or self.usage,
                decision=decision,
                error=error,
                argument_mode=self.policy.audit_arguments,
            )


def _call_arguments(args: Any, kwargs: Any) -> Mapping[str, Any]:
    arguments = dict(kwargs)
    if args:
        arguments["_args"] = list(args)
    return arguments
