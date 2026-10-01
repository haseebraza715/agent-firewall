import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from agent_firewall import DecisionKind, Policy
from agent_firewall.benchmark import (
    FREEZE_LABEL,
    HOLDOUT_LABELS,
    KIND_HOLDOUT,
    BenchmarkConfigError,
    CallOutcome,
    CaseOutcome,
    Metrics,
    Thresholds,
    build_report,
    build_report_with_metrics,
    check_thresholds,
    compute_metrics,
    load_cases,
    load_freeze,
    render_json,
    render_markdown,
    run_benchmark,
    verify_freeze,
    write_freeze,
    write_reports,
    write_reports_with_metrics,
)
from agent_firewall.cli import main

ROOT = Path(__file__).resolve().parents[1]
V1 = ROOT / "benchmarks" / "v1"
V1_POLICY = V1 / "policy.json"
V1_CASES = V1 / "cases.json"
V1_HOLDOUT_CASES = V1 / "holdout" / "cases.json"
V1_FREEZE = V1 / "freeze.json"
V1_HOLDOUT_REPORTS = V1 / "holdout" / "reports"


def _case(expected, actual, case_id="c", category="cat"):
    calls = tuple(
        CallOutcome(DecisionKind(e), DecisionKind(a)) for e, a in zip(expected, actual)
    )
    return CaseOutcome(
        id=case_id,
        category=category,
        provenance="internal-control",
        source_url=None,
        title=None,
        calls=calls,
        passed=all(o.expected is o.actual for o in calls),
    )


def _write(root, name, text):
    path = Path(root) / name
    path.write_text(text, encoding="utf-8")
    return path


class BenchmarkParsingTests(unittest.TestCase):
    def test_valid_cases_load_all_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = _write(
                directory,
                "cases.json",
                json.dumps(
                    [
                        {
                            "id": "case-a",
                            "title": "A case",
                            "category": "loop",
                            "provenance": "reconstructed-public-report",
                            "source_url": "https://github.com/x/y/issues/1",
                            "calls": [{"tool": "search.web", "arguments": {"q": "x"}}],
                            "expected_decisions": ["block"],
                        }
                    ]
                ),
            )

            cases = load_cases(path)

        self.assertEqual(len(cases), 1)
        case = cases[0]
        self.assertEqual(case.id, "case-a")
        self.assertEqual(case.title, "A case")
        self.assertEqual(case.category, "loop")
        self.assertEqual(case.provenance, "reconstructed-public-report")
        self.assertEqual(case.source_url, "https://github.com/x/y/issues/1")
        self.assertEqual(case.calls[0].name, "search.web")
        self.assertEqual(case.calls[0].arguments, {"q": "x"})
        self.assertEqual(case.expected, (DecisionKind.BLOCK,))

    def test_default_estimated_cost_and_null_fields_are_optional(self):
        with tempfile.TemporaryDirectory() as directory:
            path = _write(
                directory,
                "cases.json",
                json.dumps(
                    [
                        {
                            "id": "case-a",
                            "category": "loop",
                            "provenance": "synthetic",
                            "calls": [{"tool": "search.web"}],
                            "expected_decisions": ["allow"],
                        }
                    ]
                ),
            )

            case = load_cases(path)[0]

        self.assertIsNone(case.title)
        self.assertIsNone(case.source_url)
        self.assertEqual(case.calls[0].estimated_cost_usd.as_tuple(), (0, (0,), 0))

    def test_duplicate_ids_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = _write(
                directory,
                "cases.json",
                json.dumps(
                    [
                        {
                            "id": "dup",
                            "category": "c",
                            "provenance": "synthetic",
                            "calls": [{"tool": "a"}],
                            "expected_decisions": ["allow"],
                        },
                        {
                            "id": "dup",
                            "category": "c",
                            "provenance": "synthetic",
                            "calls": [{"tool": "a"}],
                            "expected_decisions": ["allow"],
                        },
                    ]
                ),
            )

            with self.assertRaisesRegex(BenchmarkConfigError, "duplicates"):
                load_cases(path)


class MalformedCaseTests(unittest.TestCase):
    def _load_raises(self, payload, pattern):
        with tempfile.TemporaryDirectory() as directory:
            path = _write(directory, "cases.json", json.dumps(payload))
            with self.assertRaisesRegex(BenchmarkConfigError, pattern):
                load_cases(path)

    def test_non_list_file_is_rejected(self):
        self._load_raises({"nope": 1}, "must be a JSON list")

    def test_empty_list_is_rejected(self):
        self._load_raises([], "must not be empty")

    def test_non_object_case_is_rejected(self):
        self._load_raises(["nope"], r"cases\[0\] must be an object")

    def test_missing_id_is_rejected(self):
        self._load_raises(
            [
                {
                    "category": "c",
                    "provenance": "synthetic",
                    "calls": [{"tool": "a"}],
                    "expected_decisions": ["allow"],
                }
            ],
            r"cases\[0\].id must be a non-empty string",
        )

    def test_missing_category_is_rejected(self):
        self._load_raises(
            [
                {
                    "id": "x",
                    "provenance": "synthetic",
                    "calls": [{"tool": "a"}],
                    "expected_decisions": ["allow"],
                }
            ],
            r"cases\[0\].category",
        )

    def test_invalid_provenance_is_rejected(self):
        self._load_raises(
            [
                {
                    "id": "x",
                    "category": "c",
                    "provenance": "external",
                    "calls": [{"tool": "a"}],
                    "expected_decisions": ["allow"],
                }
            ],
            r"cases\[0\].provenance must be one of",
        )

    def test_reconstructed_report_requires_source_url(self):
        self._load_raises(
            [
                {
                    "id": "x",
                    "category": "c",
                    "provenance": "reconstructed-public-report",
                    "calls": [{"tool": "a"}],
                    "expected_decisions": ["block"],
                }
            ],
            r"cases\[0\].source_url is required",
        )

    def test_mismatched_call_and_expected_lengths_are_rejected(self):
        self._load_raises(
            [
                {
                    "id": "x",
                    "category": "c",
                    "provenance": "synthetic",
                    "calls": [{"tool": "a"}, {"tool": "b"}],
                    "expected_decisions": ["allow"],
                }
            ],
            "each call needs an expected decision",
        )

    def test_invalid_expected_decision_is_rejected(self):
        self._load_raises(
            [
                {
                    "id": "x",
                    "category": "c",
                    "provenance": "synthetic",
                    "calls": [{"tool": "a"}],
                    "expected_decisions": ["maybe"],
                }
            ],
            r"expected_decisions\[0\] must be one of",
        )

    def test_invalid_tool_is_rejected(self):
        self._load_raises(
            [
                {
                    "id": "x",
                    "category": "c",
                    "provenance": "synthetic",
                    "calls": [{"tool": ""}],
                    "expected_decisions": ["allow"],
                }
            ],
            r"calls\[0\]: tool name must be a non-empty string",
        )

    def test_non_object_arguments_are_rejected(self):
        self._load_raises(
            [
                {
                    "id": "x",
                    "category": "c",
                    "provenance": "synthetic",
                    "calls": [{"tool": "a", "arguments": ["not", "an", "object"]}],
                    "expected_decisions": ["allow"],
                }
            ],
            r"calls\[0\].arguments must be an object or null",
        )

    def test_unknown_case_key_is_rejected(self):
        self._load_raises(
            [
                {
                    "id": "x",
                    "category": "c",
                    "provenance": "synthetic",
                    "calls": [{"tool": "a"}],
                    "expected_decisions": ["allow"],
                    "expected": "allow",
                }
            ],
            r"unknown benchmark case key\(s\): cases\[0\].expected",
        )

    def test_unknown_call_key_is_rejected(self):
        self._load_raises(
            [
                {
                    "id": "x",
                    "category": "c",
                    "provenance": "synthetic",
                    "calls": [{"tool": "a", "name": "a"}],
                    "expected_decisions": ["allow"],
                }
            ],
            r"unknown benchmark case key\(s\): cases\[0\].calls\[0\].name",
        )

    def test_invalid_json_reports_location(self):
        with tempfile.TemporaryDirectory() as directory:
            path = _write(directory, "cases.json", "[{")
            with self.assertRaisesRegex(BenchmarkConfigError, "line 1"):
                load_cases(path)

    def test_missing_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(BenchmarkConfigError, "cannot read"):
                load_cases(Path(directory) / "missing.json")


class BenchmarkMetricsTests(unittest.TestCase):
    def setUp(self):
        self.outcomes = [
            _case(
                [
                    "allow",
                    "allow",
                    "allow",
                    "require_approval",
                    "require_approval",
                    "block",
                    "block",
                ],
                [
                    "allow",
                    "require_approval",
                    "block",
                    "require_approval",
                    "block",
                    "allow",
                    "require_approval",
                ],
            )
        ]

    def test_exact_decision_accuracy(self):
        metrics = compute_metrics(self.outcomes)
        self.assertEqual(metrics.exact_decision_accuracy, round(2 / 7, 4))

    def test_confusion_matrix_separates_all_three_decisions(self):
        metrics = compute_metrics(self.outcomes)
        self.assertEqual(
            metrics.confusion,
            (
                (1, 1, 1),
                (0, 1, 1),
                (1, 1, 0),
            ),
        )

    def test_intervention_recall_and_specific_rates(self):
        metrics = compute_metrics(self.outcomes)
        self.assertEqual(metrics.intervention_recall, round(3 / 4, 4))
        self.assertEqual(metrics.dangerous_allow_rate, round(1 / 2, 4))
        self.assertEqual(metrics.safe_friction_rate, round(2 / 3, 4))
        self.assertEqual(metrics.approval_accuracy, round(1 / 2, 4))

    def test_counts_match_expected_and_predicted(self):
        metrics = compute_metrics(self.outcomes)
        self.assertEqual(
            metrics.expected_counts,
            {"allow": 3, "require_approval": 2, "block": 2},
        )
        self.assertEqual(
            metrics.predicted_counts,
            {"allow": 2, "require_approval": 3, "block": 2},
        )

    def test_perfect_run_has_zero_error_rates(self):
        metrics = compute_metrics(
            [
                _case(
                    ["allow", "require_approval", "block"],
                    ["allow", "require_approval", "block"],
                )
            ]
        )
        self.assertEqual(metrics.exact_decision_accuracy, 1.0)
        self.assertEqual(metrics.intervention_recall, 1.0)
        self.assertEqual(metrics.dangerous_allow_rate, 0.0)
        self.assertEqual(metrics.safe_friction_rate, 0.0)
        self.assertEqual(metrics.approval_accuracy, 1.0)

    def test_empty_denominators_report_none_not_zero(self):
        metrics = compute_metrics([_case(["allow"], ["allow"])])
        self.assertIsNone(metrics.intervention_recall)
        self.assertIsNone(metrics.dangerous_allow_rate)
        self.assertEqual(metrics.safe_friction_rate, 0.0)
        self.assertIsNone(metrics.approval_accuracy)

    def test_metrics_aggregate_across_cases(self):
        metrics = compute_metrics(
            [
                _case(["block"], ["allow"]),
                _case(["block"], ["block"]),
            ]
        )
        self.assertEqual(metrics.dangerous_allow_rate, round(1 / 2, 4))
        self.assertEqual(metrics.calls, 2)


class SequentialBudgetBehaviourTests(unittest.TestCase):
    def _policy(self):
        return Policy.from_dict(
            {
                "default_decision": "allow",
                "budget": {"max_identical_calls": 2, "max_calls": 10},
            }
        )

    def test_identical_call_cap_applies_within_a_case(self):
        with tempfile.TemporaryDirectory() as directory:
            path = _write(
                directory,
                "cases.json",
                json.dumps(
                    [
                        {
                            "id": "loop",
                            "category": "loop",
                            "provenance": "synthetic",
                            "calls": [
                                {"tool": "search", "arguments": {"q": "same"}},
                                {"tool": "search", "arguments": {"q": "same"}},
                                {"tool": "search", "arguments": {"q": "same"}},
                            ],
                            "expected_decisions": ["allow", "allow", "block"],
                        }
                    ]
                ),
            )
            cases = load_cases(path)

        outcome = run_benchmark(self._policy(), cases)[0]

        self.assertEqual(
            [o.actual.value for o in outcome.calls],
            ["allow", "allow", "block"],
        )
        self.assertTrue(outcome.passed)

    def test_each_case_starts_from_fresh_usage(self):
        def case(case_id):
            return {
                "id": case_id,
                "category": "loop",
                "provenance": "synthetic",
                "calls": [
                    {"tool": "search", "arguments": {"q": "same"}},
                    {"tool": "search", "arguments": {"q": "same"}},
                    {"tool": "search", "arguments": {"q": "same"}},
                ],
                "expected_decisions": ["allow", "allow", "block"],
            }

        with tempfile.TemporaryDirectory() as directory:
            path = _write(
                directory,
                "cases.json",
                json.dumps([case("loop-a"), case("loop-b")]),
            )
            cases = load_cases(path)

        outcomes = run_benchmark(self._policy(), cases)

        self.assertEqual(len(outcomes), 2)
        self.assertTrue(all(outcome.passed for outcome in outcomes))

    def test_replay_and_benchmark_share_evaluation_semantics(self):
        from agent_firewall.cli import _run_scenario

        policy = Policy.load(V1_POLICY)
        cases = load_cases(V1_CASES)
        outcomes = run_benchmark(policy, cases)

        for case, outcome in zip(cases, outcomes):
            replayed = _run_scenario(
                policy,
                {
                    "id": case.id,
                    "calls": [
                        {
                            "tool": call.name,
                            "arguments": dict(call.arguments),
                            "estimated_cost_usd": str(call.estimated_cost_usd),
                        }
                        for call in case.calls
                    ],
                    "expected_decisions": [d.value for d in case.expected],
                },
            )
            self.assertEqual(
                [o.actual.value for o in outcome.calls],
                replayed["actual"],
                case.id,
            )
            self.assertEqual(outcome.passed, replayed["passed"], case.id)


class DeterministicArtifactTests(unittest.TestCase):
    def test_render_json_and_markdown_are_stable_within_a_report(self):
        report = build_report(V1_POLICY, V1_CASES)
        self.assertEqual(render_json(report), render_json(report))
        self.assertEqual(render_markdown(report), render_markdown(report))

    def test_write_reports_produces_identical_bytes_across_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first"
            second = Path(directory) / "second"
            json_a, md_a = write_reports(V1_POLICY, V1_CASES, first)
            json_b, md_b = write_reports(V1_POLICY, V1_CASES, second)
            self.assertEqual(json_a.read_bytes(), json_b.read_bytes())
            self.assertEqual(md_a.read_bytes(), md_b.read_bytes())

    def test_reports_contain_no_timestamp(self):
        with tempfile.TemporaryDirectory() as directory:
            json_path, md_path = write_reports(V1_POLICY, V1_CASES, Path(directory))
            self.assertNotIn(b"timestamp", json_path.read_bytes())
            self.assertNotIn(b"timestamp", md_path.read_bytes())

    def test_reports_match_committed_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            json_path, md_path = write_reports(V1_POLICY, V1_CASES, Path(directory))
            json_bytes = json_path.read_bytes()
            md_bytes = md_path.read_bytes()
        self.assertEqual(json_bytes, (V1 / "reports" / "report.json").read_bytes())
        self.assertEqual(md_bytes, (V1 / "reports" / "report.md").read_bytes())


class BenchmarkHashTests(unittest.TestCase):
    def test_report_hashes_match_file_bytes(self):
        report = build_report(V1_POLICY, V1_CASES)
        self.assertEqual(
            report["policy_sha256"],
            hashlib.sha256(V1_POLICY.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            report["cases_sha256"],
            hashlib.sha256(V1_CASES.read_bytes()).hexdigest(),
        )

    def test_hash_changes_when_input_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            policy_a = _write(
                directory, "policy-a.json", '{"default_decision":"block"}'
            )
            policy_b = _write(
                directory, "policy-b.json", '{"default_decision":"allow"}'
            )
            cases = _write(
                directory,
                "cases.json",
                json.dumps(
                    [
                        {
                            "id": "x",
                            "category": "c",
                            "provenance": "synthetic",
                            "calls": [{"tool": "a"}],
                            "expected_decisions": ["allow"],
                        }
                    ]
                ),
            )
            first = build_report(policy_a, cases)
            second = build_report(policy_b, cases)

        self.assertNotEqual(first["policy_sha256"], second["policy_sha256"])
        self.assertEqual(first["cases_sha256"], second["cases_sha256"])


class ThresholdTests(unittest.TestCase):
    def _metrics(self):
        return Metrics(
            calls=4,
            exact_decision_accuracy=0.75,
            expected_counts={"allow": 4, "require_approval": 0, "block": 0},
            predicted_counts={"allow": 3, "require_approval": 0, "block": 1},
            confusion=((3, 0, 1), (0, 0, 0), (0, 0, 0)),
            intervention_recall=None,
            dangerous_allow_rate=None,
            safe_friction_rate=0.25,
            approval_accuracy=None,
        )

    def test_no_thresholds_means_no_failures(self):
        self.assertEqual(check_thresholds(self._metrics(), Thresholds()), [])

    def test_max_rates_fail_when_exceeded(self):
        failures = check_thresholds(
            self._metrics(), Thresholds(max_safe_friction_rate=0.1)
        )
        self.assertEqual(len(failures), 1)
        self.assertIn("safe_friction_rate", failures[0])
        self.assertIn("exceeds max", failures[0])

    def test_max_rates_pass_at_the_boundary(self):
        self.assertEqual(
            check_thresholds(self._metrics(), Thresholds(max_safe_friction_rate=0.25)),
            [],
        )

    def test_none_rate_satisfies_a_max_threshold(self):
        self.assertEqual(
            check_thresholds(self._metrics(), Thresholds(max_dangerous_allow_rate=0.0)),
            [],
        )

    def test_min_metrics_fail_when_below(self):
        failures = check_thresholds(self._metrics(), Thresholds(min_exact_accuracy=0.9))
        self.assertEqual(len(failures), 1)
        self.assertIn("exact_decision_accuracy", failures[0])
        self.assertIn("below min", failures[0])

    def test_none_min_metric_fails_the_threshold(self):
        failures = check_thresholds(
            self._metrics(), Thresholds(min_intervention_recall=0.9)
        )
        self.assertEqual(len(failures), 1)
        self.assertIn("intervention_recall", failures[0])
        self.assertIn("n/a", failures[0])

    def test_all_met_thresholds_report_nothing(self):
        metrics = Metrics(
            calls=1,
            exact_decision_accuracy=1.0,
            expected_counts={"allow": 1, "require_approval": 0, "block": 0},
            predicted_counts={"allow": 1, "require_approval": 0, "block": 0},
            confusion=((1, 0, 0), (0, 0, 0), (0, 0, 0)),
            intervention_recall=None,
            dangerous_allow_rate=None,
            safe_friction_rate=0.0,
            approval_accuracy=None,
        )
        failures = check_thresholds(
            metrics,
            Thresholds(
                max_dangerous_allow_rate=0.0,
                max_safe_friction_rate=0.05,
                min_intervention_recall=1.0,
                min_approval_accuracy=1.0,
                min_exact_accuracy=1.0,
            ),
        )
        self.assertEqual(
            failures,
            [
                "intervention_recall n/a (no calls of this class) below min 1.0000",
                "approval_accuracy n/a (no calls of this class) below min 1.0000",
            ],
        )

    def test_build_report_with_metrics_exposes_totals(self):
        report, metrics = build_report_with_metrics(V1_POLICY, V1_CASES)
        self.assertEqual(report["totals"]["exact_decision_accuracy"], 1.0)
        self.assertEqual(metrics.exact_decision_accuracy, 1.0)


class BenchmarkCliThresholdTests(unittest.TestCase):
    def test_passing_thresholds_exit_zero_and_keep_reports_stable(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "out"
            with redirect_stdout(io.StringIO()):
                status = main(
                    [
                        "benchmark",
                        "--policy",
                        str(V1_POLICY),
                        "--cases",
                        str(V1_CASES),
                        "--output",
                        str(output),
                        "--max-dangerous-allow-rate",
                        "0.1",
                        "--min-exact-accuracy",
                        "0.5",
                    ]
                )
            report = (output / "report.json").read_bytes()

            self.assertEqual(status, 0)
            self.assertEqual(report, (V1 / "reports" / "report.json").read_bytes())

    def test_failed_threshold_exits_with_distinct_code_and_prints_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = _write(root, "policy.json", '{"default_decision": "allow"}')
            cases = _write(
                root,
                "cases.json",
                json.dumps(
                    [
                        {
                            "id": "leaky",
                            "category": "cat",
                            "provenance": "synthetic",
                            "calls": [{"tool": "danger.tool"}],
                            "expected_decisions": ["block"],
                        }
                    ]
                ),
            )
            output = root / "out"
            captured = io.StringIO()
            with redirect_stdout(captured):
                status = main(
                    [
                        "benchmark",
                        "--policy",
                        str(policy),
                        "--cases",
                        str(cases),
                        "--output",
                        str(output),
                        "--max-dangerous-allow-rate",
                        "0.0",
                    ]
                )

            self.assertEqual(status, 5)
            self.assertIn("threshold failed: dangerous_allow_rate", captured.getvalue())

    def test_out_of_range_threshold_is_rejected(self):
        with self.assertRaises(SystemExit) as caught:
            main(
                [
                    "benchmark",
                    "--policy",
                    str(V1_POLICY),
                    "--cases",
                    str(V1_CASES),
                    "--output",
                    str(Path.cwd() / ".agent-tmp" / "never-written"),
                    "--min-exact-accuracy",
                    "1.5",
                ]
            )
        self.assertEqual(caught.exception.code, 2)


class V1IntegrationTests(unittest.TestCase):
    def test_v1_benchmark_is_all_pass_with_expected_counts(self):
        report = build_report(V1_POLICY, V1_CASES)
        totals = report["totals"]
        self.assertEqual(totals["cases"], 47)
        self.assertEqual(totals["calls"], 84)
        self.assertEqual(
            totals["expected_counts"],
            {"allow": 58, "require_approval": 10, "block": 16},
        )
        self.assertEqual(totals["exact_decision_accuracy"], 1.0)
        self.assertEqual(totals["unsafe_intervention_recall"], 1.0)
        self.assertEqual(totals["dangerous_allow_rate"], 0.0)
        self.assertEqual(totals["safe_call_friction_rate"], 0.0)
        self.assertEqual(totals["approval_accuracy"], 1.0)
        self.assertEqual(
            totals["provenance_counts"],
            {
                "reconstructed-public-report": 10,
                "synthetic": 16,
                "internal-control": 21,
            },
        )
        self.assertEqual(
            report["confusion_matrix"]["counts"], [[58, 0, 0], [0, 10, 0], [0, 0, 16]]
        )
        self.assertTrue(all(case["passed"] for case in report["cases"]))

    def test_v1_evaluation_covers_required_unsafe_and_safe_scenarios(self):
        cases = load_cases(V1_CASES)
        unsafe = [
            case
            for case in cases
            if any(decision is not DecisionKind.ALLOW for decision in case.expected)
        ]
        safe = [
            case
            for case in cases
            if all(decision is DecisionKind.ALLOW for decision in case.expected)
        ]
        self.assertGreaterEqual(len(unsafe), 20)
        self.assertGreaterEqual(len(safe), 20)
        self.assertGreaterEqual(len({case.category for case in cases}), 5)
        self.assertEqual(len(unsafe) + len(safe), len(cases))

    def test_v1_report_self_labels_as_internal_development(self):
        report = build_report(V1_POLICY, V1_CASES)
        self.assertEqual(report["kind"], "development-benchmark")
        self.assertTrue(report["labels"]["internal"])
        self.assertTrue(report["labels"]["development_benchmark"])
        self.assertTrue(report["labels"]["selected_replay_coverage"])


class BenchmarkCliTests(unittest.TestCase):
    def test_benchmark_command_writes_reports_and_exits_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "out"
            with redirect_stdout(io.StringIO()):
                status = main(
                    [
                        "benchmark",
                        "--policy",
                        str(V1_POLICY),
                        "--cases",
                        str(V1_CASES),
                        "--output",
                        str(output),
                    ]
                )

            self.assertEqual(status, 0)
            self.assertTrue((output / "report.json").exists())
            self.assertTrue((output / "report.md").exists())

    def test_benchmark_creates_nested_output_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "a" / "b" / "reports"
            with redirect_stdout(io.StringIO()):
                status = main(
                    [
                        "benchmark",
                        "--policy",
                        str(V1_POLICY),
                        "--cases",
                        str(V1_CASES),
                        "--output",
                        str(output),
                    ]
                )

            self.assertEqual(status, 0)
            self.assertTrue((output / "report.json").exists())

    def test_benchmark_malformed_cases_exit_with_invalid_input_code(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = _write(root, "policy.json", '{"default_decision": "block"}')
            cases = _write(root, "cases.json", '[{"id": "x"}]')
            output = root / "out"
            with redirect_stderr(io.StringIO()):
                status = main(
                    [
                        "benchmark",
                        "--policy",
                        str(policy),
                        "--cases",
                        str(cases),
                        "--output",
                        str(output),
                    ]
                )

            self.assertEqual(status, 2)
            self.assertFalse((output / "report.json").exists())
            self.assertFalse((output / "report.md").exists())

    def test_benchmark_missing_policy_exits_with_invalid_input_code(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = _write(
                root,
                "cases.json",
                json.dumps(
                    [
                        {
                            "id": "x",
                            "category": "c",
                            "provenance": "synthetic",
                            "calls": [{"tool": "a"}],
                            "expected_decisions": ["allow"],
                        }
                    ]
                ),
            )
            output = root / "out"
            with redirect_stderr(io.StringIO()):
                status = main(
                    [
                        "benchmark",
                        "--policy",
                        str(root / "missing.json"),
                        "--cases",
                        str(cases),
                        "--output",
                        str(output),
                    ]
                )

            self.assertEqual(status, 2)
            self.assertFalse((output / "report.json").exists())

    def test_benchmark_parser_requires_all_three_arguments(self):
        with self.assertRaises(SystemExit):
            main(["benchmark", "--policy", str(V1_POLICY)])


class FreezeTests(unittest.TestCase):
    def _fresh_dir(self):
        return tempfile.TemporaryDirectory()

    def test_write_freeze_records_hashes_and_label(self):
        with self._fresh_dir() as directory:
            root = Path(directory)
            policy = _write(root, "policy.json", '{"default_decision": "block"}')
            cases = _write(root, "cases.json", json.dumps([_minimal_case("a")]))
            holdout = _write(root, "holdout.json", json.dumps([_minimal_case("h")]))
            manifest_path = root / "freeze.json"

            write_freeze(manifest_path, policy, cases, holdout)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            policy_hash = hashlib.sha256(policy.read_bytes()).hexdigest()
            cases_hash = hashlib.sha256(cases.read_bytes()).hexdigest()
            holdout_hash = hashlib.sha256(holdout.read_bytes()).hexdigest()

        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["kind"], "policy-freeze")
        self.assertEqual(manifest["label"], FREEZE_LABEL)
        self.assertEqual(manifest["policy_sha256"], policy_hash)
        self.assertEqual(manifest["dev_cases_sha256"], cases_hash)
        self.assertEqual(manifest["holdout_cases_sha256"], holdout_hash)

    def test_load_freeze_rejects_non_freeze_kind(self):
        with self._fresh_dir() as directory:
            path = _write(
                directory, "freeze.json", '{"kind": "something-else", "label": "x"}'
            )
            with self.assertRaisesRegex(BenchmarkConfigError, "kind 'policy-freeze'"):
                load_freeze(path)

    def test_load_freeze_rejects_unknown_keys(self):
        with self._fresh_dir() as directory:
            path = _write(
                directory,
                "freeze.json",
                json.dumps(
                    {
                        "schema_version": 1,
                        "kind": "policy-freeze",
                        "label": "x",
                        "policy_sha256": "p",
                        "dev_cases_sha256": "d",
                        "holdout_cases_sha256": "h",
                        "nope": 1,
                    }
                ),
            )
            with self.assertRaisesRegex(BenchmarkConfigError, r"unknown.*freeze\.nope"):
                load_freeze(path)

    def test_load_freeze_requires_hash_values(self):
        for missing in ("policy_sha256", "dev_cases_sha256", "holdout_cases_sha256"):
            with self.subTest(missing=missing):
                payload = {
                    "schema_version": 1,
                    "kind": "policy-freeze",
                    "label": "x",
                    "policy_sha256": "p",
                    "dev_cases_sha256": "d",
                    "holdout_cases_sha256": "h",
                }
                del payload[missing]
                with self._fresh_dir() as directory:
                    path = _write(directory, "freeze.json", json.dumps(payload))
                    with self.assertRaisesRegex(
                        BenchmarkConfigError, f"freeze.{missing}"
                    ):
                        load_freeze(path)

    def test_load_freeze_rejects_non_object_and_invalid_json(self):
        with self._fresh_dir() as directory:
            not_object = _write(directory, "a.json", "[]")
            with self.assertRaisesRegex(BenchmarkConfigError, "JSON object"):
                load_freeze(not_object)
            invalid = _write(directory, "b.json", "{")
            with self.assertRaisesRegex(BenchmarkConfigError, "line 1"):
                load_freeze(invalid)
            with self.assertRaisesRegex(BenchmarkConfigError, "cannot read"):
                load_freeze(Path(directory) / "missing.json")

    def test_verify_freeze_passes_when_all_hashes_match(self):
        with self._fresh_dir() as directory:
            root = Path(directory)
            policy = _write(root, "policy.json", '{"default_decision": "block"}')
            holdout = _write(root, "holdout.json", json.dumps([_minimal_case("h")]))
            manifest_path = root / "freeze.json"
            write_freeze(manifest_path, policy, holdout, holdout)
            policy_hash = hashlib.sha256(policy.read_bytes()).hexdigest()

            manifest = verify_freeze(manifest_path, policy, holdout)

        self.assertEqual(manifest["kind"], "policy-freeze")
        self.assertEqual(manifest["policy_sha256"], policy_hash)

    def test_verify_freeze_rejects_changed_policy(self):
        with self._fresh_dir() as directory:
            root = Path(directory)
            policy = _write(root, "policy.json", '{"default_decision": "block"}')
            holdout = _write(root, "holdout.json", json.dumps([_minimal_case("h")]))
            manifest_path = root / "freeze.json"
            write_freeze(manifest_path, policy, holdout, holdout)

            policy.write_text('{"default_decision": "allow"}', encoding="utf-8")

            with self.assertRaisesRegex(
                BenchmarkConfigError, "policy differs from the frozen manifest"
            ):
                verify_freeze(manifest_path, policy, holdout)

    def test_verify_freeze_rejects_changed_holdout_cases(self):
        with self._fresh_dir() as directory:
            root = Path(directory)
            policy = _write(root, "policy.json", '{"default_decision": "block"}')
            holdout = _write(root, "holdout.json", json.dumps([_minimal_case("h")]))
            manifest_path = root / "freeze.json"
            write_freeze(manifest_path, policy, holdout, holdout)

            holdout.write_text(
                json.dumps([_minimal_case("h"), _minimal_case("h2")]),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                BenchmarkConfigError,
                "evaluation cases differ from the frozen manifest",
            ):
                verify_freeze(manifest_path, policy, holdout)

    def test_verify_freeze_reports_both_hashes_when_both_move(self):
        with self._fresh_dir() as directory:
            root = Path(directory)
            policy = _write(root, "policy.json", '{"default_decision": "block"}')
            holdout = _write(root, "holdout.json", json.dumps([_minimal_case("h")]))
            manifest_path = root / "freeze.json"
            write_freeze(manifest_path, policy, holdout, holdout)

            policy.write_text('{"default_decision": "allow"}', encoding="utf-8")
            holdout.write_text(json.dumps([_minimal_case("changed")]), encoding="utf-8")

            with self.assertRaises(BenchmarkConfigError) as caught:
                verify_freeze(manifest_path, policy, holdout)
            self.assertIn("policy differs", str(caught.exception))
            self.assertIn("evaluation cases differ", str(caught.exception))


class HoldoutReportTests(unittest.TestCase):
    def test_holdout_report_carries_holdout_labels_and_frozen_hash(self):
        report = build_report_with_metrics(
            V1_POLICY,
            V1_HOLDOUT_CASES,
            kind=KIND_HOLDOUT,
            labels=HOLDOUT_LABELS,
            frozen_policy_sha256="abc123",
        )[0]
        self.assertEqual(report["kind"], "internal-evaluation-benchmark")
        self.assertEqual(report["frozen_policy_sha256"], "abc123")
        for key in (
            "internal",
            "separate_evaluation_split",
            "internally_curated_and_labeled",
            "hash_pinned_against_later_drift",
        ):
            self.assertTrue(report["labels"][key])
        self.assertFalse(report["labels"]["blind_holdout"])

    def test_development_report_has_no_frozen_policy_field(self):
        report = build_report(V1_POLICY, V1_CASES)
        self.assertNotIn("frozen_policy_sha256", report)

    def test_holdout_markdown_mentions_internal_limitations(self):
        report = build_report_with_metrics(
            V1_POLICY,
            V1_HOLDOUT_CASES,
            kind=KIND_HOLDOUT,
            labels=HOLDOUT_LABELS,
            frozen_policy_sha256="abc123",
        )[0]
        text = render_markdown(report)
        self.assertIn("# Frozen internal evaluation report", text)
        self.assertIn("not a blind holdout", text)
        self.assertIn("frozen policy sha256", text)

    def test_holdout_reports_are_byte_stable_across_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, _, first = write_reports_with_metrics(
                V1_POLICY,
                V1_HOLDOUT_CASES,
                root / "a",
                kind=KIND_HOLDOUT,
                labels=HOLDOUT_LABELS,
                frozen_policy_sha256="abc123",
            )
            json_b, md_b, second = write_reports_with_metrics(
                V1_POLICY,
                V1_HOLDOUT_CASES,
                root / "b",
                kind=KIND_HOLDOUT,
                labels=HOLDOUT_LABELS,
                frozen_policy_sha256="abc123",
            )
            json_a = (root / "a" / "report.json").read_bytes()
            md_a = (root / "a" / "report.md").read_bytes()
            json_b_bytes = json_b.read_bytes()
            md_b_bytes = md_b.read_bytes()
        self.assertEqual(json_a, json_b_bytes)
        self.assertEqual(md_a, md_b_bytes)
        self.assertEqual(first.calls, second.calls)

    def test_holdout_report_matches_committed_holdout_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_reports_with_metrics(
                V1_POLICY,
                V1_HOLDOUT_CASES,
                root,
                kind=KIND_HOLDOUT,
                labels=HOLDOUT_LABELS,
                frozen_policy_sha256=_freeze_policy_hash(),
            )
            json_bytes = (root / "report.json").read_bytes()
            md_bytes = (root / "report.md").read_bytes()
        self.assertEqual(json_bytes, (V1_HOLDOUT_REPORTS / "report.json").read_bytes())
        self.assertEqual(md_bytes, (V1_HOLDOUT_REPORTS / "report.md").read_bytes())


class HoldoutCliTests(unittest.TestCase):
    def test_holdout_cli_writes_labeled_report_when_freeze_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "out"
            with redirect_stdout(io.StringIO()):
                status = main(
                    [
                        "benchmark",
                        "--policy",
                        str(V1_POLICY),
                        "--cases",
                        str(V1_HOLDOUT_CASES),
                        "--freeze",
                        str(V1_FREEZE),
                        "--output",
                        str(output),
                    ]
                )
            report = json.loads((output / "report.json").read_text(encoding="utf-8"))

            self.assertEqual(status, 0)
            self.assertEqual(report["kind"], "internal-evaluation-benchmark")
            self.assertTrue(report["labels"]["separate_evaluation_split"])
            self.assertFalse(report["labels"]["blind_holdout"])
            self.assertEqual(
                report["frozen_policy_sha256"],
                json.loads(V1_FREEZE.read_text(encoding="utf-8"))["policy_sha256"],
            )

    def test_holdout_cli_rejects_changed_policy_without_writing_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = _write(root, "policy.json", '{"default_decision": "block"}')
            holdout = _write(root, "holdout.json", json.dumps([_minimal_case("h")]))
            manifest_path = root / "freeze.json"
            write_freeze(manifest_path, policy, holdout, holdout)
            policy.write_text('{"default_decision": "allow"}', encoding="utf-8")
            output = root / "out"

            with redirect_stderr(io.StringIO()):
                status = main(
                    [
                        "benchmark",
                        "--policy",
                        str(policy),
                        "--cases",
                        str(holdout),
                        "--freeze",
                        str(manifest_path),
                        "--output",
                        str(output),
                    ]
                )

            self.assertEqual(status, 2)
            self.assertFalse((output / "report.json").exists())

    def test_holdout_cli_rejects_changed_holdout_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = _write(root, "policy.json", '{"default_decision": "block"}')
            holdout = _write(root, "holdout.json", json.dumps([_minimal_case("h")]))
            manifest_path = root / "freeze.json"
            write_freeze(manifest_path, policy, holdout, holdout)
            holdout.write_text(
                json.dumps([_minimal_case("h"), _minimal_case("h2")]),
                encoding="utf-8",
            )
            output = root / "out"

            with redirect_stderr(io.StringIO()):
                status = main(
                    [
                        "benchmark",
                        "--policy",
                        str(policy),
                        "--cases",
                        str(holdout),
                        "--freeze",
                        str(manifest_path),
                        "--output",
                        str(output),
                    ]
                )

            self.assertEqual(status, 2)
            self.assertFalse((output / "report.json").exists())


def _minimal_case(case_id):
    return {
        "id": case_id,
        "category": "cat",
        "provenance": "synthetic",
        "calls": [{"tool": "a.tool"}],
        "expected_decisions": ["allow"],
    }


def _freeze_policy_hash():
    return json.loads(V1_FREEZE.read_text(encoding="utf-8"))["policy_sha256"]


if __name__ == "__main__":
    unittest.main()
