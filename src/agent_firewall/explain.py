"""Policy explain: why a call received the decision it did.

``explain_call`` runs the same primitives as ``Policy.evaluate`` — the budget
check first, then each rule in order — and records the tool and argument match
result for every rule. The final decision is ``Policy.evaluate`` itself, so it
is byte-for-byte the runtime decision.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .models import Decision, ToolCall, Usage
from .policy import Policy, rule_arguments_match, rule_tool_matches


@dataclass(frozen=True)
class BudgetCheck:
    name: str
    current: str
    limit: str | None
    triggered: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "current": self.current,
            "limit": self.limit,
            "triggered": self.triggered,
        }


@dataclass(frozen=True)
class BudgetExplanation:
    checks: tuple[BudgetCheck, ...]
    triggered: bool
    message: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "checks": [check.as_dict() for check in self.checks],
            "triggered": self.triggered,
            "message": self.message,
        }


@dataclass(frozen=True)
class RuleExplanation:
    index: int
    tool: str
    decision: str
    reason: str
    arguments: Any
    tool_matched: bool
    arguments_matched: bool
    matched: bool
    selected: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "tool": self.tool,
            "decision": self.decision,
            "reason": self.reason,
            "arguments": self.arguments,
            "tool_matched": self.tool_matched,
            "arguments_matched": self.arguments_matched,
            "matched": self.matched,
            "selected": self.selected,
        }


@dataclass(frozen=True)
class CallExplanation:
    call: ToolCall
    budget: BudgetExplanation
    rules: tuple[RuleExplanation, ...]
    decision: Decision

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": self.call.name,
            "arguments": self.call.arguments,
            "estimated_cost_usd": str(self.call.estimated_cost_usd),
            "budget": self.budget.as_dict(),
            "rules": [rule.as_dict() for rule in self.rules],
            "decision": self.decision.as_dict(),
        }


def explain_call(policy: Policy, call: ToolCall, usage: Usage) -> CallExplanation:
    budget_decision = policy.budget_decision(call, usage)
    budget = _explain_budget(policy, call, usage, budget_decision)
    decision = policy.evaluate(call, usage)

    rules: list[RuleExplanation] = []
    for index, rule in enumerate(policy.rules):
        tool_matched = rule_tool_matches(rule, call)
        arguments_matched = rule_arguments_match(rule, call)
        rules.append(
            RuleExplanation(
                index=index,
                tool=rule.tool,
                decision=rule.decision.value,
                reason=rule.reason,
                arguments=rule.arguments,
                tool_matched=tool_matched,
                arguments_matched=arguments_matched,
                matched=tool_matched and arguments_matched,
                selected=(budget_decision is None and decision.rule_index == index),
            )
        )

    return CallExplanation(
        call=call,
        budget=budget,
        rules=tuple(rules),
        decision=decision,
    )


def _explain_budget(
    policy: Policy,
    call: ToolCall,
    usage: Usage,
    decision: Decision | None,
) -> BudgetExplanation:
    budget = policy.budget
    checks: list[BudgetCheck] = []
    if budget.max_calls is not None:
        checks.append(
            _budget_check("max_calls", usage.tool_calls, budget.max_calls, decision)
        )
    if budget.max_calls_per_tool is not None:
        checks.append(
            _budget_check(
                "max_calls_per_tool",
                usage.calls_by_tool.get(call.name, 0),
                budget.max_calls_per_tool,
                decision,
            )
        )
    if budget.max_identical_calls is not None:
        checks.append(
            _budget_check(
                "max_identical_calls",
                usage.calls_by_fingerprint.get(call.fingerprint, 0),
                budget.max_identical_calls,
                decision,
            )
        )
    if budget.max_cost_usd is not None:
        checks.append(
            _budget_check(
                "max_cost_usd",
                str(usage.estimated_cost_usd + call.estimated_cost_usd),
                str(budget.max_cost_usd),
                decision,
            )
        )
    return BudgetExplanation(
        checks=tuple(checks),
        triggered=decision is not None,
        message=decision.reason if decision is not None else None,
    )


def _budget_check(
    name: str,
    current: Any,
    limit: Any,
    decision: Decision | None,
) -> BudgetCheck:
    return BudgetCheck(
        name=name,
        current=str(current),
        limit=str(limit),
        triggered=decision is not None and decision.code == name,
    )


def render_text(explanation: CallExplanation) -> str:
    lines: list[str] = []
    lines.append(f"policy explain: {explanation.call.name}")
    lines.append(
        "arguments: "
        + json.dumps(
            dict(explanation.call.arguments),
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
    )
    lines.append(f"estimated cost: {explanation.call.estimated_cost_usd}")
    lines.append("")
    lines.append("budget:")
    if not explanation.budget.checks:
        lines.append("  no limits configured")
    for check in explanation.budget.checks:
        status = "EXHAUSTED" if check.triggered else "ok"
        limit = "unlimited" if check.limit is None else check.limit
        lines.append(f"  {check.name}: {check.current} of {limit} {status}")
    if explanation.budget.triggered:
        assert explanation.budget.message is not None
        lines.append(f"budget decision: {explanation.budget.message}")
    else:
        lines.append("budget decision: none (all budgets within limits)")
    lines.append("")
    lines.append("rules:")
    if not explanation.rules:
        lines.append("  (no rules)")
    for rule in explanation.rules:
        lines.append(
            f"  {rule.index}: {rule.decision} tool={rule.tool} "
            f"arguments={_arguments_text(rule.arguments)} "
            f"tool_match={'yes' if rule.tool_matched else 'no'} "
            f"argument_match={_argument_match_text(rule)} "
            f"matched={'yes' if rule.matched else 'no'} "
            f"selected={'yes' if rule.selected else 'no'}"
        )
    lines.append("")
    decision = explanation.decision
    if decision.rule_index is not None:
        lines.append(f"decision: {decision.kind.value} (rule {decision.rule_index})")
    else:
        lines.append(f"decision: {decision.kind.value}")
    lines.append(f"  {decision.reason}")
    return "\n".join(lines)


def _arguments_text(arguments: Any) -> str:
    if not arguments:
        return "(none)"
    return json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)


def _argument_match_text(rule: RuleExplanation) -> str:
    if not rule.arguments:
        return "n/a"
    return "yes" if rule.arguments_matched else "no"
