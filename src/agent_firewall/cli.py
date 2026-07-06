from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence

from .models import DecisionKind, ToolCall, Usage
from .policy import Policy, PolicyConfigError

EXIT_BY_DECISION = {
    DecisionKind.ALLOW: 0,
    DecisionKind.REQUIRE_APPROVAL: 3,
    DecisionKind.BLOCK: 4,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-firewall",
        description="Evaluate AI-agent tool calls before they execute.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    check = commands.add_parser("check", help="evaluate one proposed tool call")
    check.add_argument("--policy", type=Path, required=True)
    check.add_argument("--tool", required=True)
    check.add_argument("--arguments", default="{}", help="tool arguments as JSON")
    check.add_argument("--cost", default="0", help="estimated cost in USD")

    replay = commands.add_parser(
        "replay",
        help="replay complaint-derived scenarios against a policy",
    )
    replay.add_argument("--policy", type=Path, required=True)
    replay.add_argument("--scenarios", type=Path, required=True)
    return parser


def main(argv: Sequence[str] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "check":
            return _check(args)
        return _replay(args)
    except (OSError, PolicyConfigError, ValueError, json.JSONDecodeError) as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2


def _check(args: argparse.Namespace) -> int:
    arguments = json.loads(args.arguments)
    if not isinstance(arguments, dict):
        raise ValueError("--arguments must decode to a JSON object")

    policy = Policy.load(args.policy)
    call = ToolCall.create(args.tool, arguments, args.cost)
    decision = policy.evaluate(call, Usage())
    print(json.dumps(decision.as_dict(), sort_keys=True))
    return EXIT_BY_DECISION[decision.kind]


def _replay(args: argparse.Namespace) -> int:
    policy = Policy.load(args.policy)
    scenarios = json.loads(args.scenarios.read_text(encoding="utf-8"))
    if not isinstance(scenarios, list):
        raise ValueError("scenario file must contain a JSON list")

    failures = 0
    for scenario in scenarios:
        result = _run_scenario(policy, scenario)
        failures += int(not result["passed"])
        print(json.dumps(result, sort_keys=True))

    summary = {
        "passed": len(scenarios) - failures,
        "failed": failures,
        "total": len(scenarios),
    }
    print(json.dumps({"summary": summary}, sort_keys=True))
    return 1 if failures else 0


def _run_scenario(policy: Policy, scenario: Any) -> Dict[str, Any]:
    if not isinstance(scenario, dict):
        raise ValueError("each scenario must be a JSON object")
    scenario_id = scenario.get("id")
    calls = scenario.get("calls")
    expected = scenario.get("expected_decisions")
    if not isinstance(scenario_id, str) or not scenario_id:
        raise ValueError("scenario id must be a non-empty string")
    if not isinstance(calls, list) or not isinstance(expected, list):
        raise ValueError("{}: calls and expected_decisions must be lists".format(scenario_id))
    if len(calls) != len(expected):
        raise ValueError("{}: each call needs an expected decision".format(scenario_id))

    usage = Usage()
    actual: List[str] = []
    for index, raw_call in enumerate(calls):
        if not isinstance(raw_call, dict):
            raise ValueError("{}: calls[{}] must be an object".format(scenario_id, index))
        call = ToolCall.create(
            raw_call.get("tool"),
            raw_call.get("arguments"),
            raw_call.get("estimated_cost_usd", 0),
        )
        decision = policy.evaluate(call, usage)
        actual.append(decision.kind.value)
        if decision.kind is DecisionKind.ALLOW:
            usage.record(call)

    return {
        "id": scenario_id,
        "source_url": scenario.get("source_url"),
        "expected": expected,
        "actual": actual,
        "passed": actual == expected,
    }


if __name__ == "__main__":
    raise SystemExit(main())
