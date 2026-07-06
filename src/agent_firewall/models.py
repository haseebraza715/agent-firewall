from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any, Dict, Mapping, Optional
from uuid import uuid4


class DecisionKind(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


def money(value: Any) -> Decimal:
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("cost must be a valid decimal number") from exc
    if not amount.is_finite() or amount < 0:
        raise ValueError("cost must be finite and non-negative")
    return amount


@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    estimated_cost_usd: Decimal = Decimal("0")
    id: str = field(default_factory=lambda: uuid4().hex)

    @classmethod
    def create(
        cls,
        name: str,
        arguments: Optional[Mapping[str, Any]] = None,
        estimated_cost_usd: Any = 0,
    ) -> "ToolCall":
        if not isinstance(name, str) or not name.strip():
            raise ValueError("tool name must be a non-empty string")
        return cls(
            name=name,
            arguments=dict(arguments or {}),
            estimated_cost_usd=money(estimated_cost_usd),
        )

    @property
    def fingerprint(self) -> str:
        payload = json.dumps(
            {"tool": self.name, "arguments": self.arguments},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=repr,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Decision:
    kind: DecisionKind
    reason: str
    code: str
    rule_index: Optional[int] = None

    def as_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "decision": self.kind.value,
            "reason": self.reason,
            "code": self.code,
        }
        if self.rule_index is not None:
            result["rule_index"] = self.rule_index
        return result


@dataclass
class Usage:
    tool_calls: int = 0
    estimated_cost_usd: Decimal = Decimal("0")
    calls_by_tool: Dict[str, int] = field(default_factory=dict)
    calls_by_fingerprint: Dict[str, int] = field(default_factory=dict)

    def record(self, call: ToolCall) -> None:
        self.tool_calls += 1
        self.estimated_cost_usd += call.estimated_cost_usd
        self.calls_by_tool[call.name] = self.calls_by_tool.get(call.name, 0) + 1
        fingerprint = call.fingerprint
        self.calls_by_fingerprint[fingerprint] = (
            self.calls_by_fingerprint.get(fingerprint, 0) + 1
        )

    def copy(self) -> "Usage":
        return Usage(
            tool_calls=self.tool_calls,
            estimated_cost_usd=self.estimated_cost_usd,
            calls_by_tool=dict(self.calls_by_tool),
            calls_by_fingerprint=dict(self.calls_by_fingerprint),
        )
