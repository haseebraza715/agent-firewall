"""Deterministic benchmark evaluation for Agent Firewall policies.

The benchmark reuses the same ``Policy``, ``ToolCall``, and ``Usage``
primitives as the runtime and the replay command. A case is a sequence of
tool calls with one expected decision per call; the calls inside a case share
a single ``Usage`` so budget behaviour stays sequential, and each case starts
from a fresh ``Usage`` exactly like ``replay`` does.

Reports are byte-stable for the same code and inputs. They contain no
timestamps, keys are sorted, floats are rounded to a fixed precision, and the
policy and case files are reported as SHA-256 hashes.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import DecisionKind, ToolCall, Usage
from .policy import Policy

ORDER = ("allow", "require_approval", "block")

PROVENANCE_RECONSTRUCTED = "reconstructed-public-report"
PROVENANCE_SYNTHETIC = "synthetic"
PROVENANCE_INTERNAL_CONTROL = "internal-control"
VALID_PROVENANCE = frozenset(
    (PROVENANCE_RECONSTRUCTED, PROVENANCE_SYNTHETIC, PROVENANCE_INTERNAL_CONTROL)
)

KIND_DEVELOPMENT = "development-benchmark"
KIND_HOLDOUT = "internal-evaluation-benchmark"

FREEZE_LABEL = (
    "internally curated and internally labeled; hash-pinned against later drift; "
    "not a blind holdout, independent, or externally validated"
)

HOLDOUT_LABELS: dict[str, Any] = {
    "internal": True,
    "separate_evaluation_split": True,
    "internally_curated_and_labeled": True,
    "hash_pinned_against_later_drift": True,
    "blind_holdout": False,
}


class BenchmarkConfigError(ValueError):
    pass


@dataclass(frozen=True)
class BenchmarkCase:
    id: str
    category: str
    provenance: str
    source_url: str | None
    title: str | None
    calls: tuple[ToolCall, ...]
    expected: tuple[DecisionKind, ...]


@dataclass(frozen=True)
class CallOutcome:
    expected: DecisionKind
    actual: DecisionKind


@dataclass(frozen=True)
class CaseOutcome:
    id: str
    category: str
    provenance: str
    source_url: str | None
    title: str | None
    calls: tuple[CallOutcome, ...]
    passed: bool


@dataclass(frozen=True)
class Metrics:
    calls: int
    exact_decision_accuracy: float
    expected_counts: dict[str, int]
    predicted_counts: dict[str, int]
    confusion: tuple[
        tuple[int, int, int],
        tuple[int, int, int],
        tuple[int, int, int],
    ]
    intervention_recall: float | None
    dangerous_allow_rate: float | None
    safe_friction_rate: float | None
    approval_accuracy: float | None


@dataclass(frozen=True)
class Thresholds:
    max_dangerous_allow_rate: float | None = None
    max_safe_friction_rate: float | None = None
    min_intervention_recall: float | None = None
    min_approval_accuracy: float | None = None
    min_exact_accuracy: float | None = None

    @property
    def any_set(self) -> bool:
        return any(
            value is not None
            for value in (
                self.max_dangerous_allow_rate,
                self.max_safe_friction_rate,
                self.min_intervention_recall,
                self.min_approval_accuracy,
                self.min_exact_accuracy,
            )
        )


def check_thresholds(metrics: Metrics, thresholds: Thresholds) -> list[str]:
    """Return a message for every threshold the run does not meet.

    A ``max_*`` rate that is ``None`` means there were no calls of that class,
    so the maximum is trivially satisfied. A ``min_*`` metric that is ``None``
    means the metric could not be demonstrated and the threshold fails.
    """
    failures: list[str] = []
    _check_max(
        failures,
        "dangerous_allow_rate",
        metrics.dangerous_allow_rate,
        thresholds.max_dangerous_allow_rate,
    )
    _check_max(
        failures,
        "safe_friction_rate",
        metrics.safe_friction_rate,
        thresholds.max_safe_friction_rate,
    )
    _check_min(
        failures,
        "intervention_recall",
        metrics.intervention_recall,
        thresholds.min_intervention_recall,
    )
    _check_min(
        failures,
        "approval_accuracy",
        metrics.approval_accuracy,
        thresholds.min_approval_accuracy,
    )
    _check_min(
        failures,
        "exact_decision_accuracy",
        metrics.exact_decision_accuracy,
        thresholds.min_exact_accuracy,
    )
    return failures


def _check_max(
    failures: list[str],
    name: str,
    value: float | None,
    threshold: float | None,
) -> None:
    if threshold is None or value is None or value <= threshold:
        return
    failures.append(f"{name} {value:.4f} exceeds max {threshold:.4f}")


def _check_min(
    failures: list[str],
    name: str,
    value: float | None,
    threshold: float | None,
) -> None:
    if threshold is None:
        return
    if value is None:
        failures.append(
            f"{name} n/a (no calls of this class) below min {threshold:.4f}"
        )
    elif value < threshold:
        failures.append(f"{name} {value:.4f} below min {threshold:.4f}")


def load_cases(path: Path) -> list[BenchmarkCase]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise BenchmarkConfigError(f"cannot read benchmark cases: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise BenchmarkConfigError(
            f"invalid JSON in benchmark cases at line {exc.lineno}, column {exc.colno}"
        ) from exc
    if not isinstance(raw, list):
        raise BenchmarkConfigError("benchmark cases must be a JSON list")
    if not raw:
        raise BenchmarkConfigError("benchmark cases must not be empty")

    cases: list[BenchmarkCase] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        cases.append(_parse_case(item, index, seen))
    return cases


def run_benchmark(policy: Policy, cases: list[BenchmarkCase]) -> list[CaseOutcome]:
    outcomes: list[CaseOutcome] = []
    for case in cases:
        usage = Usage()
        call_outcomes: list[CallOutcome] = []
        for call, expected in zip(case.calls, case.expected):
            decision = policy.evaluate(call, usage)
            call_outcomes.append(CallOutcome(expected, decision.kind))
            if decision.kind is DecisionKind.ALLOW:
                usage.record(call)
        outcomes.append(
            CaseOutcome(
                id=case.id,
                category=case.category,
                provenance=case.provenance,
                source_url=case.source_url,
                title=case.title,
                calls=tuple(call_outcomes),
                passed=all(
                    outcome.expected is outcome.actual for outcome in call_outcomes
                ),
            )
        )
    return outcomes


def compute_metrics(outcomes: list[CaseOutcome]) -> Metrics:
    cells: dict[str, dict[str, int]] = {
        expected: {predicted: 0 for predicted in ORDER} for expected in ORDER
    }
    expected_counts = {value: 0 for value in ORDER}
    predicted_counts = {value: 0 for value in ORDER}
    correct = 0
    calls = 0
    for case in outcomes:
        for outcome in case.calls:
            expected = outcome.expected.value
            actual = outcome.actual.value
            cells[expected][actual] += 1
            expected_counts[expected] += 1
            predicted_counts[actual] += 1
            calls += 1
            if expected == actual:
                correct += 1

    unsafe = expected_counts["require_approval"] + expected_counts["block"]
    intervened_unsafe = (
        cells["require_approval"]["require_approval"]
        + cells["require_approval"]["block"]
        + cells["block"]["require_approval"]
        + cells["block"]["block"]
    )

    if calls == 0:
        raise BenchmarkConfigError("cannot score a benchmark with no calls")

    confusion = (
        (
            cells["allow"]["allow"],
            cells["allow"]["require_approval"],
            cells["allow"]["block"],
        ),
        (
            cells["require_approval"]["allow"],
            cells["require_approval"]["require_approval"],
            cells["require_approval"]["block"],
        ),
        (
            cells["block"]["allow"],
            cells["block"]["require_approval"],
            cells["block"]["block"],
        ),
    )

    return Metrics(
        calls=calls,
        exact_decision_accuracy=round(correct / calls, 4),
        expected_counts=expected_counts,
        predicted_counts=predicted_counts,
        confusion=confusion,
        intervention_recall=_rate(intervened_unsafe, unsafe),
        dangerous_allow_rate=_rate(cells["block"]["allow"], expected_counts["block"]),
        safe_friction_rate=_rate(
            cells["allow"]["require_approval"] + cells["allow"]["block"],
            expected_counts["allow"],
        ),
        approval_accuracy=_rate(
            cells["require_approval"]["require_approval"],
            expected_counts["require_approval"],
        ),
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_freeze(
    manifest_path: Path,
    policy_path: Path,
    dev_cases_path: Path,
    holdout_cases_path: Path,
) -> None:
    """Record the policy and both case sets as SHA-256 hashes.

    The manifest prevents later policy or evaluation-case changes from silently
    replacing the published inputs. It does not prove when the inputs were first
    evaluated or turn an internally authored split into a blind holdout.
    """
    manifest = {
        "schema_version": 1,
        "kind": "policy-freeze",
        "label": FREEZE_LABEL,
        "policy_sha256": sha256_file(policy_path),
        "dev_cases_sha256": sha256_file(dev_cases_path),
        "holdout_cases_sha256": sha256_file(holdout_cases_path),
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def load_freeze(manifest_path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise BenchmarkConfigError(f"cannot read policy freeze: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise BenchmarkConfigError(
            f"invalid JSON in policy freeze at line {exc.lineno}, column {exc.colno}"
        ) from exc
    if not isinstance(raw, dict):
        raise BenchmarkConfigError("policy freeze must be a JSON object")
    if raw.get("kind") != "policy-freeze":
        raise BenchmarkConfigError("policy freeze must declare kind 'policy-freeze'")
    _reject_unknown(
        raw,
        (
            "schema_version",
            "kind",
            "label",
            "policy_sha256",
            "dev_cases_sha256",
            "holdout_cases_sha256",
        ),
        "freeze",
    )
    for key in ("policy_sha256", "dev_cases_sha256", "holdout_cases_sha256"):
        value = raw.get(key)
        if not isinstance(value, str) or not value:
            raise BenchmarkConfigError(f"freeze.{key} must be a non-empty string")
    return raw


def verify_freeze(
    manifest_path: Path, policy_path: Path, cases_path: Path
) -> dict[str, Any]:
    """Check the current policy and evaluation cases against the hash manifest.

    Raises ``BenchmarkConfigError`` when either hash has moved since the manifest
    was written, preventing later drift in the published inputs.
    """
    manifest = load_freeze(manifest_path)
    failures: list[str] = []
    policy_actual = sha256_file(policy_path)
    if manifest["policy_sha256"] != policy_actual:
        failures.append(
            f"policy differs from the frozen manifest: frozen "
            f"{manifest['policy_sha256'][:12]}..., actual {policy_actual[:12]}..."
        )
    cases_actual = sha256_file(cases_path)
    if manifest["holdout_cases_sha256"] != cases_actual:
        failures.append(
            f"evaluation cases differ from the frozen manifest: frozen "
            f"{manifest['holdout_cases_sha256'][:12]}..., "
            f"actual {cases_actual[:12]}..."
        )
    if failures:
        raise BenchmarkConfigError(
            "policy freeze verification failed: " + "; ".join(failures)
        )
    return manifest


def build_report(
    policy_path: Path,
    cases_path: Path,
    *,
    kind: str = KIND_DEVELOPMENT,
    labels: Mapping[str, Any] | None = None,
    frozen_policy_sha256: str | None = None,
) -> dict[str, Any]:
    policy, cases, outcomes, totals = _evaluate(policy_path, cases_path)
    return _assemble_report(
        policy_path,
        cases_path,
        outcomes,
        totals,
        kind=kind,
        labels=labels,
        frozen_policy_sha256=frozen_policy_sha256,
    )


def build_report_with_metrics(
    policy_path: Path,
    cases_path: Path,
    *,
    kind: str = KIND_DEVELOPMENT,
    labels: Mapping[str, Any] | None = None,
    frozen_policy_sha256: str | None = None,
) -> tuple[dict[str, Any], Metrics]:
    policy, cases, outcomes, totals = _evaluate(policy_path, cases_path)
    return (
        _assemble_report(
            policy_path,
            cases_path,
            outcomes,
            totals,
            kind=kind,
            labels=labels,
            frozen_policy_sha256=frozen_policy_sha256,
        ),
        totals,
    )


def _evaluate(
    policy_path: Path,
    cases_path: Path,
) -> tuple[Policy, list[BenchmarkCase], list[CaseOutcome], Metrics]:
    policy = Policy.load(policy_path)
    cases = load_cases(cases_path)
    outcomes = run_benchmark(policy, cases)
    totals = compute_metrics(outcomes)
    return policy, cases, outcomes, totals


def _assemble_report(
    policy_path: Path,
    cases_path: Path,
    outcomes: list[CaseOutcome],
    totals: Metrics,
    *,
    kind: str = KIND_DEVELOPMENT,
    labels: Mapping[str, Any] | None = None,
    frozen_policy_sha256: str | None = None,
) -> dict[str, Any]:
    provenance_counts: dict[str, int] = {}
    for case in outcomes:
        provenance_counts[case.provenance] = (
            provenance_counts.get(case.provenance, 0) + 1
        )

    per_category: dict[str, Any] = {}
    for category in sorted({case.category for case in outcomes}):
        cat_outcomes = [case for case in outcomes if case.category == category]
        cat_totals = compute_metrics(cat_outcomes)
        per_category[category] = {
            "cases": len(cat_outcomes),
            "calls": cat_totals.calls,
            "exact_decision_accuracy": cat_totals.exact_decision_accuracy,
            "unsafe_intervention_recall": cat_totals.intervention_recall,
            "dangerous_allow_rate": cat_totals.dangerous_allow_rate,
            "safe_call_friction_rate": cat_totals.safe_friction_rate,
            "approval_accuracy": cat_totals.approval_accuracy,
        }

    if labels is None:
        labels = {
            "internal": True,
            "development_benchmark": True,
            "selected_replay_coverage": True,
        }

    report: dict[str, Any] = {
        "schema_version": 1,
        "kind": kind,
        "labels": dict(labels),
        "policy_sha256": sha256_file(policy_path),
        "cases_sha256": sha256_file(cases_path),
        "totals": {
            "cases": len(outcomes),
            "calls": totals.calls,
            "exact_decision_accuracy": totals.exact_decision_accuracy,
            "unsafe_intervention_recall": totals.intervention_recall,
            "dangerous_allow_rate": totals.dangerous_allow_rate,
            "safe_call_friction_rate": totals.safe_friction_rate,
            "approval_accuracy": totals.approval_accuracy,
            "expected_counts": totals.expected_counts,
            "predicted_counts": totals.predicted_counts,
            "provenance_counts": provenance_counts,
        },
        "confusion_matrix": {
            "expected": list(ORDER),
            "predicted": list(ORDER),
            "counts": [
                [totals.confusion[row][column] for column in range(3)]
                for row in range(3)
            ],
        },
        "per_category": per_category,
        "cases": [
            {
                "id": case.id,
                "title": case.title,
                "category": case.category,
                "provenance": case.provenance,
                "source_url": case.source_url,
                "expected": [outcome.expected.value for outcome in case.calls],
                "actual": [outcome.actual.value for outcome in case.calls],
                "passed": case.passed,
            }
            for case in outcomes
        ],
    }
    if frozen_policy_sha256 is not None:
        report["frozen_policy_sha256"] = frozen_policy_sha256
    return report


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(
        report,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def render_markdown(report: dict[str, Any]) -> str:
    totals = report["totals"]
    holdout = report["kind"] == KIND_HOLDOUT
    lines: list[str] = []
    if holdout:
        lines.append("# Frozen internal evaluation report")
        lines.append("")
        lines.append(
            "Separate internal evaluation split: the manifest pins the exact "
            "policy and cases used and rejects later drift. The cases were "
            "authored with access to the policy, and the initial results were "
            "inspected before the manifest was written. This is not a blind "
            "holdout, independent, or externally validated evaluation, and it "
            "does not measure unseen real-world safety."
        )
    else:
        lines.append("# Development benchmark report")
        lines.append("")
        lines.append(
            "Internal development benchmark: selected replay coverage over "
            "reconstructed incident scenarios and paired safe controls. Not an "
            "external, independent, or held-out safety evaluation."
        )
    lines.append("")
    lines.append(f"- schema_version: {report['schema_version']}")
    lines.append(f"- kind: {report['kind']}")
    if holdout:
        lines.append(f"- frozen policy sha256: `{report['frozen_policy_sha256']}`")
    lines.append(f"- cases: {totals['cases']}")
    lines.append(f"- calls: {totals['calls']}")
    lines.append(f"- policy sha256: `{report['policy_sha256']}`")
    lines.append(f"- cases sha256: `{report['cases_sha256']}`")
    lines.append("")
    lines.append("## Headline metrics")
    lines.append("")
    lines.append("| metric | value |")
    lines.append("|---|---|")
    for name, key in (
        ("exact decision accuracy", "exact_decision_accuracy"),
        ("unsafe intervention recall", "unsafe_intervention_recall"),
        ("dangerous-allow rate", "dangerous_allow_rate"),
        ("safe-call friction rate", "safe_call_friction_rate"),
        ("approval accuracy", "approval_accuracy"),
    ):
        lines.append(f"| {name} | {_rate_text(totals[key])} |")
    lines.append("")
    lines.append("## Confusion matrix (expected rows, predicted columns)")
    lines.append("")
    matrix = report["confusion_matrix"]
    labels = matrix["expected"]
    lines.append("| expected \\ predicted | " + " | ".join(labels) + " |")
    lines.append("|" + "---|" * (len(labels) + 1))
    for row, label in zip(matrix["counts"], labels):
        cells = " | ".join(str(value) for value in row)
        lines.append(f"| {label} | {cells} |")
    lines.append("")
    lines.append("## Per-category results")
    lines.append("")
    lines.append(
        "| category | cases | calls | exact | intervention | dangerous-allow "
        "| friction | approval |"
    )
    lines.append("|---|---|---|---|---|---|---|---|")
    for category in sorted(report["per_category"]):
        result = report["per_category"][category]
        lines.append(
            f"| {category} | {result['cases']} | {result['calls']} | "
            f"{_rate_text(result['exact_decision_accuracy'])} | "
            f"{_rate_text(result['unsafe_intervention_recall'])} | "
            f"{_rate_text(result['dangerous_allow_rate'])} | "
            f"{_rate_text(result['safe_call_friction_rate'])} | "
            f"{_rate_text(result['approval_accuracy'])} |"
        )
    lines.append("")
    lines.append("## Cases")
    lines.append("")
    lines.append("| id | category | provenance | expected | actual | passed |")
    lines.append("|---|---|---|---|---|---|")
    for case in report["cases"]:
        lines.append(
            f"| {case['id']} | {case['category']} | {case['provenance']} | "
            f"{', '.join(case['expected'])} | {', '.join(case['actual'])} | "
            f"{case['passed']} |"
        )
    lines.append("")
    return "\n".join(lines)


def write_reports(
    policy_path: Path,
    cases_path: Path,
    output_dir: Path,
) -> tuple[Path, Path]:
    json_path, markdown_path, _ = write_reports_with_metrics(
        policy_path, cases_path, output_dir
    )
    return json_path, markdown_path


def write_reports_with_metrics(
    policy_path: Path,
    cases_path: Path,
    output_dir: Path,
    *,
    kind: str = KIND_DEVELOPMENT,
    labels: Mapping[str, Any] | None = None,
    frozen_policy_sha256: str | None = None,
) -> tuple[Path, Path, Metrics]:
    report, metrics = build_report_with_metrics(
        policy_path,
        cases_path,
        kind=kind,
        labels=labels,
        frozen_policy_sha256=frozen_policy_sha256,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "report.json"
    markdown_path = output_dir / "report.md"
    json_path.write_text(render_json(report) + "\n", encoding="utf-8")
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, markdown_path, metrics


def _parse_case(item: Any, index: int, seen: set[str]) -> BenchmarkCase:
    where = f"cases[{index}]"
    if not isinstance(item, dict):
        raise BenchmarkConfigError(f"{where} must be an object")
    _reject_unknown(
        item,
        (
            "id",
            "category",
            "provenance",
            "source_url",
            "title",
            "calls",
            "expected_decisions",
        ),
        where,
    )

    case_id = item.get("id")
    if not isinstance(case_id, str) or not case_id:
        raise BenchmarkConfigError(f"{where}.id must be a non-empty string")
    if case_id in seen:
        raise BenchmarkConfigError(f"{where}.id duplicates {case_id!r}")
    seen.add(case_id)

    category = item.get("category")
    if not isinstance(category, str) or not category.strip():
        raise BenchmarkConfigError(f"{where}.category must be a non-empty string")

    provenance = item.get("provenance")
    if provenance not in VALID_PROVENANCE:
        allowed = ", ".join(sorted(VALID_PROVENANCE))
        raise BenchmarkConfigError(f"{where}.provenance must be one of: {allowed}")

    source_url = item.get("source_url")
    if source_url is not None and not isinstance(source_url, str):
        raise BenchmarkConfigError(f"{where}.source_url must be a string or null")
    if provenance == PROVENANCE_RECONSTRUCTED and not source_url:
        raise BenchmarkConfigError(
            f"{where}.source_url is required for reconstructed public reports"
        )

    title = item.get("title")
    if title is not None and not isinstance(title, str):
        raise BenchmarkConfigError(f"{where}.title must be a string or null")

    calls_raw = item.get("calls")
    expected_raw = item.get("expected_decisions")
    if not isinstance(calls_raw, list) or not isinstance(expected_raw, list):
        raise BenchmarkConfigError(
            f"{where}: calls and expected_decisions must be lists"
        )
    if not calls_raw:
        raise BenchmarkConfigError(f"{where}: at least one call is required")
    if len(calls_raw) != len(expected_raw):
        raise BenchmarkConfigError(f"{where}: each call needs an expected decision")

    calls: list[ToolCall] = []
    expected: list[DecisionKind] = []
    for call_index, raw_call in enumerate(calls_raw):
        call_where = f"{where}.calls[{call_index}]"
        if not isinstance(raw_call, dict):
            raise BenchmarkConfigError(f"{call_where} must be an object")
        _reject_unknown(
            raw_call,
            ("tool", "arguments", "estimated_cost_usd"),
            call_where,
        )
        arguments = raw_call.get("arguments")
        if arguments is not None and not isinstance(arguments, dict):
            raise BenchmarkConfigError(
                f"{call_where}.arguments must be an object or null"
            )
        try:
            calls.append(
                ToolCall.create(
                    raw_call.get("tool"),
                    arguments,
                    raw_call.get("estimated_cost_usd", 0),
                )
            )
        except ValueError as exc:
            raise BenchmarkConfigError(f"{call_where}: {exc}") from exc
        expected.append(
            _decision_kind(
                expected_raw[call_index], f"{where}.expected_decisions[{call_index}]"
            )
        )

    return BenchmarkCase(
        id=case_id,
        category=category,
        provenance=provenance,
        source_url=source_url,
        title=title,
        calls=tuple(calls),
        expected=tuple(expected),
    )


def _decision_kind(value: Any, where: str) -> DecisionKind:
    try:
        return DecisionKind(value)
    except (TypeError, ValueError) as exc:
        allowed = ", ".join(item.value for item in DecisionKind)
        raise BenchmarkConfigError(f"{where} must be one of: {allowed}") from exc


def _reject_unknown(
    raw: dict[str, Any],
    allowed: tuple[str, ...],
    where: str,
) -> None:
    unknown = [key for key in raw if key not in allowed]
    if unknown:
        names = ", ".join(f"{where}.{key}" for key in sorted(unknown))
        raise BenchmarkConfigError(f"unknown benchmark case key(s): {names}")


def _rate(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 4)


def _rate_text(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.4f}"
