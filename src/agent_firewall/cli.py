from __future__ import annotations

import argparse
import asyncio
import json
import math
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import doctor as doctor_module
from . import explain as explain_module
from . import lint as lint_module
from ._version import __version__
from .benchmark import (
    HOLDOUT_LABELS,
    KIND_HOLDOUT,
    Thresholds,
    check_thresholds,
    verify_freeze,
    write_reports_with_metrics,
)
from .dashboard import Dashboard
from .exceptions import StorageError
from .mcp_proxy import run_mcp_proxy
from .models import Decision, DecisionKind, ToolCall, Usage
from .policy import Policy, PolicyConfigError

EXIT_BY_DECISION = {
    DecisionKind.ALLOW: 0,
    DecisionKind.REQUIRE_APPROVAL: 3,
    DecisionKind.BLOCK: 4,
}
EXIT_THRESHOLDS = 5


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-firewall",
        description="Evaluate AI-agent tool calls before they execute.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    check = commands.add_parser("check", help="evaluate one proposed tool call")
    check.add_argument("--policy", type=Path, required=True)
    check.add_argument("--tool", required=True)
    check.add_argument("--arguments", default="{}", help="tool arguments as JSON")
    check.add_argument("--cost", default="0", help="estimated cost in USD")
    check.add_argument(
        "--format",
        choices=("json", "text"),
        default="json",
        help="json for machine consumption (default), text for humans",
    )

    replay = commands.add_parser(
        "replay",
        help="replay complaint-derived scenarios against a policy",
    )
    replay.add_argument("--policy", type=Path, required=True)
    replay.add_argument("--scenarios", type=Path, required=True)
    replay.add_argument(
        "--format",
        choices=("json", "text"),
        default="json",
        help="json for machine consumption (default), text for humans",
    )

    benchmark = commands.add_parser(
        "benchmark",
        help="evaluate a policy against labeled cases and write reports",
    )
    benchmark.add_argument("--policy", type=Path, required=True)
    benchmark.add_argument("--cases", type=Path, required=True)
    benchmark.add_argument(
        "--output",
        type=Path,
        required=True,
        help="directory for report.json and report.md (created if missing)",
    )
    benchmark.add_argument(
        "--max-dangerous-allow-rate",
        type=_rate_threshold,
        default=None,
        metavar="0..1",
        help="fail the run when the dangerous-allow rate exceeds this value",
    )
    benchmark.add_argument(
        "--max-safe-friction-rate",
        type=_rate_threshold,
        default=None,
        metavar="0..1",
        help="fail the run when the safe-call friction rate exceeds this value",
    )
    benchmark.add_argument(
        "--min-intervention-recall",
        type=_rate_threshold,
        default=None,
        metavar="0..1",
        help="fail the run when unsafe intervention recall is below this value",
    )
    benchmark.add_argument(
        "--min-approval-accuracy",
        type=_rate_threshold,
        default=None,
        metavar="0..1",
        help="fail the run when approval accuracy is below this value",
    )
    benchmark.add_argument(
        "--min-exact-accuracy",
        type=_rate_threshold,
        default=None,
        metavar="0..1",
        help="fail the run when exact decision accuracy is below this value",
    )
    benchmark.add_argument(
        "--freeze",
        type=Path,
        default=None,
        metavar="MANIFEST",
        help=(
            "policy freeze manifest; when given, the policy and case hashes are "
            "verified against it before an internal evaluation report is written"
        ),
    )

    policy = commands.add_parser(
        "policy",
        help="inspect and analyze a policy file",
    )
    policy_sub = policy.add_subparsers(dest="policy_command", required=True)
    lint = policy_sub.add_parser("lint", help="lint a policy for common problems")
    lint.add_argument("--policy", type=Path, required=True)
    lint.add_argument(
        "--format",
        choices=("json", "text"),
        default="text",
        help="text for humans (default) or json for machines",
    )
    explain = policy_sub.add_parser(
        "explain",
        help="explain the runtime decision for one proposed tool call",
    )
    explain.add_argument("--policy", type=Path, required=True)
    explain.add_argument("--tool", required=True)
    explain.add_argument("--arguments", default="{}", help="tool arguments as JSON")
    explain.add_argument("--cost", default="0", help="estimated cost in USD")
    explain.add_argument(
        "--format",
        choices=("json", "text"),
        default="text",
        help="text for humans (default) or json for machines",
    )

    doctor = commands.add_parser(
        "doctor",
        help="check the firewall environment and a policy",
    )
    doctor.add_argument("--policy", type=Path, required=True)
    doctor.add_argument(
        "--state",
        type=Path,
        help="state database path whose parent is checked for writability",
    )
    doctor.add_argument(
        "--audit",
        type=Path,
        help="audit log path whose parent is checked for writability",
    )
    doctor.add_argument(
        "--mcp",
        nargs="+",
        metavar="CMD",
        help="MCP child command to check for availability, e.g. --mcp python server.py",
    )
    doctor.add_argument(
        "--format",
        choices=("json", "text"),
        default="text",
        help="text for humans (default) or json for machines",
    )

    mcp = commands.add_parser("mcp", help="guard a local MCP stdio server")
    mcp.add_argument("--policy", type=Path, required=True)
    mcp.add_argument("--audit", type=Path)
    mcp.add_argument("--state", type=Path)
    approval = mcp.add_mutually_exclusive_group()
    approval.add_argument(
        "--approve-terminal",
        action="store_true",
        help="prompt on the controlling terminal for approval-gated calls",
    )
    approval.add_argument(
        "--approve-web",
        action="store_true",
        help="wait for decisions from the localhost dashboard",
    )
    mcp.add_argument(
        "--approval-timeout",
        type=_finite_positive_float,
        default=300,
        metavar="SECONDS",
        help="deny held calls still undecided after this many seconds",
    )
    mcp.add_argument(
        "--request-timeout",
        type=_finite_positive_float,
        default=300,
        metavar="SECONDS",
        help="fail closed when the wrapped MCP server takes longer than this",
    )
    mcp.add_argument(
        "--max-line-bytes",
        type=_positive_int,
        default=64 * 1024 * 1024,
        metavar="BYTES",
        help="reject JSON-RPC lines larger than this (default 67108864)",
    )
    mcp.add_argument("server_command", nargs=argparse.REMAINDER)

    dashboard = commands.add_parser(
        "dashboard",
        help="run the local audit and approval dashboard",
    )
    dashboard.add_argument("--policy", type=Path, required=True)
    dashboard.add_argument("--audit", type=Path, required=True)
    dashboard.add_argument("--state", type=Path, required=True)
    dashboard.add_argument("--host", default="127.0.0.1")
    dashboard.add_argument("--port", type=_port, default=8787)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "check":
            return _check(args)
        if args.command == "dashboard":
            return _dashboard(args)
        if args.command == "mcp":
            return asyncio.run(
                run_mcp_proxy(
                    args.policy,
                    args.server_command,
                    audit_path=args.audit,
                    state_path=args.state,
                    approve_terminal=args.approve_terminal,
                    approve_web=args.approve_web,
                    approval_timeout=args.approval_timeout,
                    request_timeout=args.request_timeout,
                    max_line_bytes=args.max_line_bytes,
                )
            )
        if args.command == "benchmark":
            return _benchmark(args)
        if args.command == "policy":
            if args.policy_command == "lint":
                return _policy_lint(args)
            return _policy_explain(args)
        if args.command == "doctor":
            return _doctor(args)
        return _replay(args)
    except (
        OSError,
        PolicyConfigError,
        StorageError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _check(args: argparse.Namespace) -> int:
    arguments = _parse_json_object(args.arguments, "--arguments")
    policy = Policy.load(args.policy)
    call = ToolCall.create(args.tool, arguments, args.cost)
    decision = policy.evaluate(call, Usage())
    if args.format == "text":
        print(_format_decision(call.name, decision))
    else:
        print(json.dumps(decision.as_dict(), sort_keys=True))
    return EXIT_BY_DECISION[decision.kind]


def _replay(args: argparse.Namespace) -> int:
    policy = Policy.load(args.policy)
    try:
        scenarios = json.loads(args.scenarios.read_text(encoding="utf-8"))
    except RecursionError as exc:
        raise ValueError("scenario file is nested too deeply") from exc
    if not isinstance(scenarios, list):
        raise ValueError("scenario file must contain a JSON list")

    as_text = args.format == "text"
    failures = 0
    for scenario in scenarios:
        result = _run_scenario(policy, scenario)
        failures += int(not result["passed"])
        if as_text:
            print(_format_scenario(result))
        else:
            print(json.dumps(result, sort_keys=True))

    summary = {
        "passed": len(scenarios) - failures,
        "failed": failures,
        "total": len(scenarios),
    }
    if as_text:
        print(
            f"{summary['passed']} caught, {summary['failed']} missed "
            f"of {summary['total']} scenarios"
        )
    else:
        print(json.dumps({"summary": summary}, sort_keys=True))
    return 1 if failures else 0


def _benchmark(args: argparse.Namespace) -> int:
    if args.freeze is not None:
        manifest = verify_freeze(args.freeze, args.policy, args.cases)
        json_path, markdown_path, metrics = write_reports_with_metrics(
            args.policy,
            args.cases,
            args.output,
            kind=KIND_HOLDOUT,
            labels=HOLDOUT_LABELS,
            frozen_policy_sha256=manifest["policy_sha256"],
        )
    else:
        json_path, markdown_path, metrics = write_reports_with_metrics(
            args.policy, args.cases, args.output
        )
    print(f"wrote {json_path}")
    print(f"wrote {markdown_path}")
    thresholds = Thresholds(
        max_dangerous_allow_rate=args.max_dangerous_allow_rate,
        max_safe_friction_rate=args.max_safe_friction_rate,
        min_intervention_recall=args.min_intervention_recall,
        min_approval_accuracy=args.min_approval_accuracy,
        min_exact_accuracy=args.min_exact_accuracy,
    )
    if not thresholds.any_set:
        return 0
    failures = check_thresholds(metrics, thresholds)
    for failure in failures:
        print(f"threshold failed: {failure}")
    if failures:
        print(f"{len(failures)} threshold(s) failed")
        return EXIT_THRESHOLDS
    return 0


def _policy_lint(args: argparse.Namespace) -> int:
    policy = Policy.load(args.policy)
    findings = lint_module.lint_policy(policy)
    if args.format == "text":
        print(lint_module.render_text(str(args.policy), findings))
    else:
        print(
            json.dumps(lint_module.to_dict(str(args.policy), findings), sort_keys=True)
        )
    errors = sum(finding.severity == "error" for finding in findings)
    return 1 if errors else 0


def _policy_explain(args: argparse.Namespace) -> int:
    arguments = _parse_json_object(args.arguments, "--arguments")
    policy = Policy.load(args.policy)
    call = ToolCall.create(args.tool, arguments, args.cost)
    explanation = explain_module.explain_call(policy, call, Usage())
    if args.format == "text":
        print(explain_module.render_text(explanation))
    else:
        print(json.dumps(explanation.as_dict(), sort_keys=True))
    return EXIT_BY_DECISION[explanation.decision.kind]


def _doctor(args: argparse.Namespace) -> int:
    checks = doctor_module.run_checks(
        args.policy,
        state_path=args.state,
        audit_path=args.audit,
        mcp_command=args.mcp,
    )
    if args.format == "text":
        print(doctor_module.render_text(checks))
    else:
        print(json.dumps(doctor_module.to_dict(checks), sort_keys=True))
    return 0 if all(check.ok for check in checks) else 1


def _rate_threshold(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{value!r} is not a number") from exc
    if not 0.0 <= number <= 1.0:
        raise argparse.ArgumentTypeError("threshold must be between 0 and 1 inclusive")
    return number


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("value must be a positive integer")
    return number


def _parse_json_object(text: str, flag: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except RecursionError as exc:
        raise ValueError(f"{flag} is nested too deeply") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{flag} must decode to a JSON object")
    return value


def _finite_positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{value!r} is not a number") from exc
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be a finite positive number")
    return number


def _port(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer") from exc
    if not 0 <= number <= 65535:
        raise argparse.ArgumentTypeError("port must be between 0 and 65535")
    return number


def _format_decision(tool: str, decision: Decision) -> str:
    rule = "" if decision.rule_index is None else f" (rule {decision.rule_index})"
    return f"{decision.kind.value:<16}  {tool}\n{'':18}{decision.reason}{rule}"


def _format_scenario(result: dict[str, Any]) -> str:
    status = "CAUGHT" if result["passed"] else "MISSED"
    title = result.get("title") or result["id"]
    trail = ", ".join(result["actual"])
    source = _short_source(result.get("source_url"))
    return f"{status}  {title}\n{'':8}{trail}  {source}"


def _short_source(url: str | None) -> str:
    """Shorten a GitHub issue URL to owner/repo#number where possible."""
    if not url:
        return "no upstream report"
    for prefix in ("https://", "http://"):
        url = url.removeprefix(prefix)
    url = url.removeprefix("github.com/")
    match = re.fullmatch(r"([^/]+/[^/]+)/(?:issues|discussions|pull)/(\d+)", url)
    return f"{match.group(1)}#{match.group(2)}" if match else url


def _dashboard(args: argparse.Namespace) -> int:
    dashboard = Dashboard(
        args.policy,
        args.audit,
        args.state,
        host=args.host,
        port=args.port,
    )
    try:
        dashboard.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        dashboard.server.server_close()
    return 0


def _run_scenario(policy: Policy, scenario: Any) -> dict[str, Any]:
    if not isinstance(scenario, dict):
        raise ValueError("each scenario must be a JSON object")
    scenario_id = scenario.get("id")
    calls = scenario.get("calls")
    expected = scenario.get("expected_decisions")
    if not isinstance(scenario_id, str) or not scenario_id:
        raise ValueError("scenario id must be a non-empty string")
    if not isinstance(calls, list) or not isinstance(expected, list):
        raise ValueError(f"{scenario_id}: calls and expected_decisions must be lists")
    if len(calls) != len(expected):
        raise ValueError(f"{scenario_id}: each call needs an expected decision")
    title = scenario.get("title")
    if title is not None and not isinstance(title, str):
        raise ValueError(f"{scenario_id}: title must be a string")
    source_url = scenario.get("source_url")
    if source_url is not None and not isinstance(source_url, str):
        raise ValueError(f"{scenario_id}: source_url must be a string")

    usage = Usage()
    actual: list[str] = []
    for index, raw_call in enumerate(calls):
        if not isinstance(raw_call, dict):
            raise ValueError(f"{scenario_id}: calls[{index}] must be an object")
        raw_arguments = raw_call.get("arguments")
        if raw_arguments is not None and not isinstance(raw_arguments, dict):
            raise ValueError(
                f"{scenario_id}: calls[{index}]: arguments must be an object"
            )
        try:
            call = ToolCall.create(
                raw_call.get("tool"),
                raw_arguments,
                raw_call.get("estimated_cost_usd", 0),
            )
        except ValueError as exc:
            raise ValueError(f"{scenario_id}: calls[{index}]: {exc}") from exc
        decision = policy.evaluate(call, usage)
        actual.append(decision.kind.value)
        if decision.kind is DecisionKind.ALLOW:
            usage.record(call)

    return {
        "id": scenario_id,
        "title": scenario.get("title"),
        "source_url": scenario.get("source_url"),
        "expected": expected,
        "actual": actual,
        "passed": actual == expected,
    }


if __name__ == "__main__":
    raise SystemExit(main())
