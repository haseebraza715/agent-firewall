"""Static policy linting.

``lint_policy`` walks a loaded policy and reports common problems that make
enforcement weaker or rules unreachable. Findings are either ``error`` (the
policy should be fixed) or ``warning`` (a smell worth a look). ``error``
findings drive a nonzero exit from the CLI; ``warning`` findings do not.

The shadowing checks are heuristic: glob containment is approximated with
trailing-wildcard prefix rules, never by resolving the filesystem or DNS.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any

from .models import DecisionKind
from .policy import Policy

SCHEME_URL_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://")


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    message: str
    rule_index: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "code": self.code,
            "rule_index": self.rule_index,
            "message": self.message,
        }


def lint_policy(policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    _check_default(policy, findings)
    _check_budget(policy, findings)
    for index, rule in enumerate(policy.rules):
        _check_rule(rule, index, findings)
    _check_shadowed_equivalents(policy.rules, findings)
    _check_approval_shadowing(policy.rules, findings)
    return findings


def _check_default(policy: Policy, findings: list[Finding]) -> None:
    if policy.default_decision is DecisionKind.ALLOW:
        findings.append(
            Finding(
                "error",
                "permissive_default",
                'default_decision is "allow"; unknown tool calls are not blocked',
            )
        )


def _check_budget(policy: Policy, findings: list[Finding]) -> None:
    budget = policy.budget
    if all(
        value is None
        for value in (
            budget.max_calls,
            budget.max_calls_per_tool,
            budget.max_identical_calls,
            budget.max_cost_usd,
        )
    ):
        findings.append(
            Finding(
                "error",
                "no_budgets",
                "budget defines no limits; nothing caps runaway tool calls",
            )
        )


def _check_rule(rule: Any, index: int, findings: list[Finding]) -> None:
    if (
        rule.decision is DecisionKind.ALLOW
        and not rule.arguments
        and not _matches_everything(rule.tool)
        and _is_broad_tool(rule.tool)
    ):
        findings.append(
            Finding(
                "warning",
                "empty_arguments",
                "allow rule has no argument constraints and its tool pattern "
                "matches many tool names",
                rule_index=index,
            )
        )
    if rule.decision is DecisionKind.ALLOW and _matches_everything(rule.tool):
        findings.append(
            Finding(
                "warning",
                "broad_allow_all",
                f"tool pattern {rule.tool!r} matches every tool call",
                rule_index=index,
            )
        )
    for key, pattern in rule.arguments.items():
        if _url_glob_lookalike(pattern):
            findings.append(
                Finding(
                    "warning",
                    "url_glob_lookalike",
                    f"argument {key!r} is a URL-shaped string glob; use the "
                    "url typed matcher so the scheme, host, and path are "
                    "parsed instead of globbed",
                    rule_index=index,
                )
            )


def _check_shadowed_equivalents(rules: list[Any], findings: list[Finding]) -> None:
    for later in range(1, len(rules)):
        for earlier in range(later):
            if _equivalent(rules[earlier], rules[later]):
                findings.append(
                    Finding(
                        "error",
                        "shadowed_equivalent",
                        "rule is unreachable: an earlier rule with the same "
                        "tool pattern and arguments always matches first",
                        rule_index=later,
                    )
                )
                break


def _check_approval_shadowing(rules: list[Any], findings: list[Finding]) -> None:
    for later in range(1, len(rules)):
        approval = rules[later]
        if approval.decision is not DecisionKind.REQUIRE_APPROVAL:
            continue
        for earlier in range(later):
            allow_rule = rules[earlier]
            if (
                allow_rule.decision is DecisionKind.ALLOW
                and not allow_rule.arguments
                and _glob_covers(allow_rule.tool, approval.tool)
            ):
                findings.append(
                    Finding(
                        "error",
                        "approval_shadowed_by_allow",
                        "approval rule is unreachable: an earlier allow rule "
                        "with no argument constraints matches every tool this "
                        "rule matches",
                        rule_index=later,
                    )
                )
                break


def _equivalent(first: Any, second: Any) -> bool:
    if first.tool != second.tool:
        return False
    return _arguments_key(first.arguments) == _arguments_key(second.arguments)


def _arguments_key(arguments: Any) -> str:
    return json.dumps(arguments, sort_keys=True, separators=(",", ":"))


def _matches_everything(tool: str) -> bool:
    return tool in ("*", "**")


def _is_broad_tool(tool: str) -> bool:
    return any(char in tool for char in ("*", "?", "["))


def _url_glob_lookalike(pattern: Any) -> bool:
    return isinstance(pattern, str) and SCHEME_URL_RE.search(pattern) is not None


def _glob_covers(broad: str, specific: str) -> bool:
    """Heuristic: does every tool matching ``specific`` also match ``broad``?

    Only trailing-wildcard broad patterns are approximated. Anything more
    complex is left unclassified rather than risking a false positive.
    """
    if broad == "*" or broad == specific:
        return True
    if "*" in broad:
        if broad.endswith("*") and specific.startswith(broad[:-1]):
            return True
        return False
    return fnmatchcase(specific, broad) and "*" not in specific


def render_text(policy_path: str, findings: list[Finding]) -> str:
    if not findings:
        return f"policy lint: {policy_path}: no findings"
    errors = sum(finding.severity == "error" for finding in findings)
    warnings = sum(finding.severity == "warning" for finding in findings)
    lines = [f"policy lint: {policy_path}: {len(findings)} finding(s)"]
    for finding in findings:
        location = (
            f"rule {finding.rule_index}: " if finding.rule_index is not None else ""
        )
        lines.append(f"{finding.severity}: {finding.code}: {location}{finding.message}")
    lines.append(f"{errors} error(s), {warnings} warning(s)")
    return "\n".join(lines)


def to_dict(policy_path: str, findings: list[Finding]) -> dict[str, Any]:
    errors = sum(finding.severity == "error" for finding in findings)
    warnings = sum(finding.severity == "warning" for finding in findings)
    return {
        "policy": policy_path,
        "findings": [finding.as_dict() for finding in findings],
        "error_count": errors,
        "warning_count": warnings,
    }
