from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from . import matchers
from .models import ArgumentAuditMode, Decision, DecisionKind, ToolCall, Usage, money


class PolicyConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Budget:
    max_calls: int | None = None
    max_calls_per_tool: int | None = None
    max_identical_calls: int | None = None
    max_cost_usd: Decimal | None = None


@dataclass(frozen=True)
class Rule:
    tool: str
    decision: DecisionKind
    reason: str
    arguments: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Policy:
    default_decision: DecisionKind
    budget: Budget
    rules: list[Rule]
    audit_arguments: ArgumentAuditMode = ArgumentAuditMode.NONE

    @classmethod
    def load(cls, path: Path) -> Policy:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise PolicyConfigError(f"cannot read policy: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise PolicyConfigError(
                f"invalid JSON at line {exc.lineno}, column {exc.colno}"
            ) from exc
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> Policy:
        if not isinstance(raw, dict):
            raise PolicyConfigError("policy must be a JSON object")
        _reject_unknown(raw, ("default_decision", "budget", "rules", "audit_arguments"))

        default = _decision(raw.get("default_decision", "block"), "default_decision")
        budget = _budget(raw.get("budget", {}))
        audit_arguments = _audit_mode(raw.get("audit_arguments", "none"))
        rules_raw = raw.get("rules", [])
        if not isinstance(rules_raw, list):
            raise PolicyConfigError("rules must be a list")

        rules: list[Rule] = []
        for index, item in enumerate(rules_raw):
            if not isinstance(item, dict):
                raise PolicyConfigError(f"rules[{index}] must be an object")
            _reject_unknown(
                item,
                ("tool", "decision", "reason", "arguments"),
                f"rules[{index}]",
            )
            tool = item.get("tool")
            if not isinstance(tool, str) or not tool.strip():
                raise PolicyConfigError(
                    f"rules[{index}].tool must be a non-empty string"
                )
            reason = item.get("reason", "matched policy rule")
            if not isinstance(reason, str) or not reason.strip():
                raise PolicyConfigError(
                    f"rules[{index}].reason must be a non-empty string"
                )
            arguments = item.get("arguments", {})
            if not isinstance(arguments, dict):
                raise PolicyConfigError(f"rules[{index}].arguments must be an object")
            for key, pattern in arguments.items():
                if matchers.is_typed(pattern):
                    where = f"rules[{index}].arguments.{key}"
                    try:
                        matchers.compile(pattern, where)
                    except ValueError as exc:
                        raise PolicyConfigError(str(exc)) from exc
            rules.append(
                Rule(
                    tool=tool,
                    decision=_decision(
                        item.get("decision"), f"rules[{index}].decision"
                    ),
                    reason=reason,
                    arguments=dict(arguments),
                )
            )
        return cls(
            default_decision=default,
            budget=budget,
            rules=rules,
            audit_arguments=audit_arguments,
        )

    def evaluate(self, call: ToolCall, usage: Usage) -> Decision:
        budget_decision = self.budget_decision(call, usage)
        if budget_decision is not None:
            return budget_decision

        for index, rule in enumerate(self.rules):
            if rule_matches(rule, call):
                return Decision(
                    kind=rule.decision,
                    reason=rule.reason,
                    code="rule_match",
                    rule_index=index,
                )

        return Decision(
            kind=self.default_decision,
            reason="no policy rule matched",
            code="default",
        )

    def budget_decision(self, call: ToolCall, usage: Usage) -> Decision | None:
        if self.budget.max_calls is not None:
            if usage.tool_calls >= self.budget.max_calls:
                return Decision(
                    DecisionKind.BLOCK,
                    "run tool-call budget exhausted",
                    "max_calls",
                )

        if self.budget.max_calls_per_tool is not None:
            prior_calls = usage.calls_by_tool.get(call.name, 0)
            if prior_calls >= self.budget.max_calls_per_tool:
                return Decision(
                    DecisionKind.BLOCK,
                    "per-tool repetition budget exhausted",
                    "max_calls_per_tool",
                )

        if self.budget.max_identical_calls is not None:
            prior_calls = usage.calls_by_fingerprint.get(call.fingerprint, 0)
            if prior_calls >= self.budget.max_identical_calls:
                return Decision(
                    DecisionKind.BLOCK,
                    "identical tool-call budget exhausted",
                    "max_identical_calls",
                )

        if self.budget.max_cost_usd is not None:
            projected = usage.estimated_cost_usd + call.estimated_cost_usd
            if projected > self.budget.max_cost_usd:
                return Decision(
                    DecisionKind.BLOCK,
                    "estimated run cost would exceed budget",
                    "max_cost_usd",
                )
        return None


def _decision(value: Any, field: str) -> DecisionKind:
    try:
        return DecisionKind(value)
    except (TypeError, ValueError) as exc:
        allowed = ", ".join(item.value for item in DecisionKind)
        raise PolicyConfigError(f"{field} must be one of: {allowed}") from exc


def _audit_mode(value: Any) -> ArgumentAuditMode:
    try:
        return ArgumentAuditMode(value)
    except (TypeError, ValueError) as exc:
        allowed = ", ".join(item.value for item in ArgumentAuditMode)
        raise PolicyConfigError(f"audit_arguments must be one of: {allowed}") from exc


def _budget(raw: Any) -> Budget:
    if not isinstance(raw, dict):
        raise PolicyConfigError("budget must be an object")
    _reject_unknown(
        raw,
        ("max_calls", "max_calls_per_tool", "max_identical_calls", "max_cost_usd"),
        "budget",
    )
    return Budget(
        max_calls=_positive_int(raw.get("max_calls"), "budget.max_calls"),
        max_calls_per_tool=_positive_int(
            raw.get("max_calls_per_tool"), "budget.max_calls_per_tool"
        ),
        max_identical_calls=_positive_int(
            raw.get("max_identical_calls"), "budget.max_identical_calls"
        ),
        max_cost_usd=_optional_money(raw.get("max_cost_usd"), "budget.max_cost_usd"),
    )


def _positive_int(value: Any, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise PolicyConfigError(f"{field} must be a positive integer")
    return int(value)


def _reject_unknown(
    raw: Mapping[str, Any],
    allowed: tuple[str, ...],
    where: str = "policy",
) -> None:
    unknown = [key for key in raw if key not in allowed]
    if unknown:
        names = ", ".join(f"{where}.{key}" for key in sorted(unknown))
        raise PolicyConfigError(f"unknown policy key(s): {names}")


def _optional_money(value: Any, field: str) -> Decimal | None:
    if value is None:
        return None
    try:
        return money(value)
    except ValueError as exc:
        raise PolicyConfigError(f"{field}: {exc}") from exc


def rule_tool_matches(rule: Rule, call: ToolCall) -> bool:
    return fnmatchcase(call.name, rule.tool)


def rule_arguments_match(rule: Rule, call: ToolCall) -> bool:
    return _arguments_match(call.arguments, rule.arguments)


def rule_matches(rule: Rule, call: ToolCall) -> bool:
    return rule_tool_matches(rule, call) and rule_arguments_match(rule, call)


def _arguments_match(
    actual: Mapping[str, Any],
    expected: Mapping[str, Any],
) -> bool:
    for key, pattern in expected.items():
        if key not in actual:
            return False
        value = actual[key]
        if matchers.is_typed(pattern):
            if not matchers.match(pattern, value):
                return False
        elif isinstance(pattern, str):
            if not isinstance(value, str) or not fnmatchcase(value, pattern):
                return False
        elif value != pattern:
            return False
    return True
