"""Security hardening and edge-case tests.

Covers the SSRF-encoding bypasses in ``deny_private_networks``, type-strict
scalar matching, deep-JSON recursion handling, pathological payload sizes,
and policy loading edge cases.
"""

import json
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

from agent_firewall import (
    DecisionKind,
    Firewall,
    JsonlAuditLog,
    Policy,
    PolicyConfigError,
    ToolCall,
    Usage,
    matchers,
)
from agent_firewall.audit import _redact
from agent_firewall.benchmark import BenchmarkConfigError, load_cases
from agent_firewall.dashboard import read_events
from agent_firewall.exceptions import StorageError
from agent_firewall.explain import explain_call
from agent_firewall.jsonrpc import decode_message, encode_message
from agent_firewall.models import bounded
from agent_firewall.state import SQLiteStateStore


def _deep_json(depth):
    root = []
    node = root
    for _ in range(depth):
        child = []
        node.append(child)
        node = child
    node.append(1)
    return root


def _deep_line(depth):
    return b"[" * depth + b"1" + b"]" * depth + b"\n"


class PrivateNetworkBypassTests(unittest.TestCase):
    """Every legacy encoding that resolvers may accept must stay private."""

    def _pattern(self):
        matchers.compile({"operator": "url", "deny_private_networks": True}, "test")
        return {"operator": "url", "deny_private_networks": True}

    def test_loopback_encodings_are_all_denied(self):
        pattern = self._pattern()
        encodings = (
            "http://127.0.0.1/",
            "http://127.1/",
            "http://127.0.1/",
            "http://2130706433/",
            "http://0x7f000001/",
            "http://0177.0.0.1/",
            "http://127.000.000.001/",
            "http://[::1]/",
            "http://[0:0:0:0:0:0:0:1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[fe80::1%25eth0]/",
        )
        for url in encodings:
            with self.subTest(url=url):
                self.assertFalse(matchers.match(pattern, url), url)

    def test_private_ranges_are_denied(self):
        pattern = self._pattern()
        for address in (
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "0.0.0.0",
            "100.64.0.1",
        ):
            with self.subTest(address=address):
                self.assertFalse(matchers.match(pattern, f"http://{address}/"))

    def test_public_literals_still_match(self):
        pattern = self._pattern()
        self.assertTrue(matchers.match(pattern, "http://8.8.8.8/"))
        self.assertTrue(matchers.match(pattern, "http://[2606:4700::1111]/"))

    def test_dns_names_stay_unclassified(self):
        pattern = self._pattern()
        self.assertTrue(matchers.match(pattern, "http://example.com/"))
        self.assertTrue(matchers.match(pattern, "http://localhost.example/"))

    def test_oversized_decimal_tokens_classify_by_wraparound(self):
        pattern = self._pattern()
        self.assertFalse(matchers.match(pattern, "http://42949672960/"))
        self.assertTrue(matchers.match(pattern, "http://99999999999999/"))

    def test_private_network_rule_runs_through_policy(self):
        policy = Policy.from_dict(
            {
                "default_decision": "block",
                "rules": [
                    {
                        "tool": "url.fetch",
                        "arguments": {
                            "url": {"operator": "url", "deny_private_networks": True}
                        },
                        "decision": "allow",
                        "reason": "public network only",
                    }
                ],
            }
        )
        for url in (
            "http://127.1/x",
            "http://2130706433/x",
            "http://[::ffff:127.0.0.1]/",
        ):
            decision = policy.evaluate(
                ToolCall.create("url.fetch", {"url": url}), Usage()
            )
            self.assertEqual(decision.kind, DecisionKind.BLOCK, url)
            self.assertEqual(decision.code, "default", url)
        allowed = policy.evaluate(
            ToolCall.create("url.fetch", {"url": "http://example.com/"}), Usage()
        )
        self.assertEqual(allowed.kind, DecisionKind.ALLOW)
        self.assertEqual(allowed.code, "rule_match")


class StrictEqualityTests(unittest.TestCase):
    def _policy(self, pattern):
        return Policy.from_dict(
            {
                "default_decision": "block",
                "rules": [
                    {
                        "tool": "payment.charge",
                        "arguments": {"charge": pattern},
                        "decision": "allow",
                    }
                ],
            }
        )

    def evaluate(self, pattern, value):
        return self._policy(pattern).evaluate(
            ToolCall.create("payment.charge", {"charge": value}), Usage()
        )

    def test_int_does_not_match_bool(self):
        self.assertEqual(self.evaluate(1, True).kind, DecisionKind.BLOCK)
        self.assertEqual(self.evaluate(0, False).kind, DecisionKind.BLOCK)

    def test_int_does_not_match_float(self):
        self.assertEqual(self.evaluate(500, 500.0).kind, DecisionKind.BLOCK)
        self.assertEqual(self.evaluate(500.0, 500).kind, DecisionKind.BLOCK)

    def test_float_does_not_match_int(self):
        self.assertEqual(self.evaluate(1.5, 1).kind, DecisionKind.BLOCK)

    def test_none_matches_only_none(self):
        self.assertEqual(self.evaluate(None, None).kind, DecisionKind.ALLOW)
        self.assertEqual(self.evaluate(None, 0).kind, DecisionKind.BLOCK)

    def test_string_does_not_match_number(self):
        self.assertEqual(self.evaluate("500", 500).kind, DecisionKind.BLOCK)

    def test_nested_dict_is_strict_recursively(self):
        pattern = {"level": {"amount": 5, "meta": {"flag": 1}}}
        exact = self.evaluate(pattern, {"level": {"amount": 5, "meta": {"flag": 1}}})
        bool_flag = self.evaluate(
            pattern, {"level": {"amount": 5, "meta": {"flag": True}}}
        )
        float_amount = self.evaluate(
            pattern, {"level": {"amount": 5.0, "meta": {"flag": 1}}}
        )
        self.assertEqual(exact.kind, DecisionKind.ALLOW)
        self.assertEqual(bool_flag.kind, DecisionKind.BLOCK)
        self.assertEqual(float_amount.kind, DecisionKind.BLOCK)

    def test_nested_list_is_strict_recursively(self):
        pattern = {"values": [1, 2, 3]}
        self.assertEqual(
            self.evaluate(pattern, {"values": [1, 2, 3]}).kind, DecisionKind.ALLOW
        )
        self.assertEqual(
            self.evaluate(pattern, {"values": [1, 2, 3.0]}).kind, DecisionKind.BLOCK
        )
        self.assertEqual(
            self.evaluate(pattern, {"values": [1, 2]}).kind, DecisionKind.BLOCK
        )


class DeepJsonHardeningTests(unittest.TestCase):
    def test_decode_message_raises_value_error_for_deep_nesting(self):
        with self.assertRaisesRegex(ValueError, "nested too deeply"):
            decode_message(_deep_line(50000))

    def test_decode_message_still_returns_none_for_malformed(self):
        self.assertIsNone(decode_message(b"not json"))
        self.assertIsNone(decode_message(b"[1,2,3]"))
        self.assertIsNone(decode_message(b'"just a string"'))

    def test_encode_message_raises_value_error_for_deep_nesting(self):
        message = {"a": _deep_json(20000)}
        with self.assertRaisesRegex(ValueError, "nested too deeply"):
            encode_message(message)

    def test_fingerprint_of_deep_arguments_is_stable(self):
        first = ToolCall.create("search", {"nested": _deep_json(50000)})
        second = ToolCall.create("search", {"nested": _deep_json(50000)})
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(len(first.fingerprint), 64)

    def test_fingerprint_of_unicode_arguments_is_stable(self):
        first = ToolCall.create("t", {"text": "héllo \u00e9moji \U0001f600"})
        second = ToolCall.create("t", {"text": "héllo \u00e9moji \U0001f600"})
        self.assertEqual(first.fingerprint, second.fingerprint)

    def test_bounded_collapses_deep_subtrees(self):
        value = _deep_json(200)
        collapsed = bounded(value)
        payload = json.dumps(collapsed)
        self.assertIn("<deep>", payload)

    def test_bounded_preserves_shallow_values(self):
        value = {"a": [1, {"b": "x"}], "c": "y"}
        self.assertEqual(bounded(value), value)

    def test_redact_handles_deep_arguments(self):
        result = _redact(bounded(_deep_json(50000)))
        self.assertIsNotNone(result)

    def test_redact_shape_is_preserved(self):
        result = _redact({"outer": {"inner": ["a", {"x": 1}]}, "k": "v"})
        self.assertEqual(result["outer"]["inner"][0], "[REDACTED]")
        self.assertEqual(result["outer"]["inner"][1]["x"], "[REDACTED]")
        self.assertEqual(result["k"], "[REDACTED]")

    def test_audit_redacted_mode_handles_deep_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            policy = Policy.from_dict(
                {"default_decision": "allow", "audit_arguments": "redacted"}
            )
            firewall = Firewall(policy, audit_log=JsonlAuditLog(path))
            firewall.call(
                "demo.tool", lambda **kwargs: kwargs, payload=_deep_json(50000)
            )
            entry = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(entry["event"], "allowed")

    def test_audit_full_mode_handles_deep_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            policy = Policy.from_dict(
                {"default_decision": "allow", "audit_arguments": "full"}
            )
            firewall = Firewall(policy, audit_log=JsonlAuditLog(path))
            firewall.call(
                "demo.tool", lambda **kwargs: kwargs, payload=_deep_json(50000)
            )
            entry = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
            deepest = entry["arguments"]["payload"]
            for _ in range(64):
                deepest = deepest[0]
            self.assertEqual(deepest, "<deep>")

    def test_policy_load_rejects_deeply_nested_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_bytes(_deep_line(50000))
            with self.assertRaisesRegex(PolicyConfigError, "nested too deeply"):
                Policy.load(path)

    def test_policy_load_reports_json_error_location(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text('{"default_decision": }', encoding="utf-8")
            with self.assertRaisesRegex(PolicyConfigError, "line 1"):
                Policy.load(path)

    def test_policy_load_rejects_non_object(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text("[1, 2]", encoding="utf-8")
            with self.assertRaisesRegex(PolicyConfigError, "must be a JSON object"):
                Policy.load(path)

    def test_benchmark_cases_reject_deeply_nested_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cases.json"
            path.write_bytes(_deep_line(50000))
            with self.assertRaisesRegex(BenchmarkConfigError, "nested too deeply"):
                load_cases(path)

    def test_read_events_skips_deep_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            path.write_bytes(_deep_line(50000) + b'{"event": "allowed"}\n')
            events = read_events(path, limit=None)
            self.assertEqual([event["event"] for event in events], ["allowed"])

    def test_read_events_skips_malformed_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            path.write_text(
                '{"event": "ok"}\ngarbage\n{"event": "later"}\n', encoding="utf-8"
            )
            events = read_events(path, limit=None)
            self.assertEqual([event["event"] for event in events], ["ok", "later"])

    def test_read_events_respects_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            path.write_text(
                "\n".join(json.dumps({"event": str(i)}) for i in range(10)),
                encoding="utf-8",
            )
            events = read_events(path, limit=3)
            self.assertEqual([event["event"] for event in events], ["7", "8", "9"])


class PathOperatorStrictnessTests(unittest.TestCase):
    def test_operator_key_inside_path_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown typed matcher key"):
            matchers.compile(
                {"operator": "url", "path": {"equals": "/x", "operator": "prefix"}},
                "rule.arguments.url",
            )

    def test_two_path_operators_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "exactly one of"):
            matchers.compile(
                {"operator": "url", "path": {"prefix": "/a", "suffix": "/b"}},
                "x",
            )


class PolicyLoadingEdgeCaseTests(unittest.TestCase):
    def test_empty_policy_fails_closed(self):
        policy = Policy.from_dict({})
        self.assertEqual(policy.rules, [])
        self.assertEqual(policy.default_decision, DecisionKind.BLOCK)

    def test_explicit_empty_rules_still_fail_closed(self):
        policy = Policy.from_dict({"rules": [], "default_decision": "block"})
        decision = policy.evaluate(ToolCall.create("anything"), Usage())
        self.assertEqual(decision.kind, DecisionKind.BLOCK)
        self.assertEqual(decision.code, "default")

    def test_rule_with_empty_arguments_matches_any_arguments(self):
        policy = Policy.from_dict(
            {"rules": [{"tool": "demo.tool", "arguments": {}, "decision": "allow"}]}
        )
        for args in ({}, {"anything": 1}, {"nested": {"x": [1, 2]}}):
            decision = policy.evaluate(ToolCall.create("demo.tool", args), Usage())
            self.assertEqual(decision.kind, DecisionKind.ALLOW, args)

    def test_rule_without_arguments_key_matches_any_arguments(self):
        policy = Policy.from_dict(
            {"rules": [{"tool": "demo.tool", "decision": "allow"}]}
        )
        decision = policy.evaluate(
            ToolCall.create("demo.tool", {"anything": True}), Usage()
        )
        self.assertEqual(decision.kind, DecisionKind.ALLOW)

    def test_malformed_rule_shapes_are_rejected(self):
        bad_rules = (
            5,
            "rules",
            [None],
            [{"tool": "x"}],
            [{"tool": "x", "decision": "allow", "arguments": []}],
            [{"tool": 5, "decision": "allow"}],
            [{"tool": "x", "decision": "allow", "reason": ""}],
        )
        for rules in bad_rules:
            with self.subTest(rules=rules):
                with self.assertRaises(PolicyConfigError):
                    Policy.from_dict({"rules": rules})

    def test_malformed_budget_shapes_are_rejected(self):
        for budget in (
            "x",
            [],
            {"max_calls": 0},
            {"max_calls": -1},
            {"max_calls": 1.5},
            {"max_calls": True},
            {"max_cost_usd": "abc"},
        ):
            with self.subTest(budget=budget):
                with self.assertRaises(PolicyConfigError):
                    Policy.from_dict({"budget": budget})

    def test_invalid_decision_value_is_rejected_with_choices(self):
        with self.assertRaisesRegex(PolicyConfigError, "require_approval"):
            Policy.from_dict({"default_decision": "maybe"})

    def test_huge_budget_values_are_accepted(self):
        policy = Policy.from_dict(
            {"budget": {"max_calls": 10**12, "max_cost_usd": "1e999"}}
        )
        self.assertEqual(policy.budget.max_calls, 10**12)
        self.assertTrue(policy.budget.max_cost_usd.is_finite())


class MalformedPolicyFileTests(unittest.TestCase):
    def _write(self, text):
        directory = tempfile.mkdtemp()
        path = Path(directory) / "policy.json"
        path.write_text(text, encoding="utf-8")
        return path

    def test_not_json(self):
        with self.assertRaises(PolicyConfigError):
            Policy.load(self._write("not json at all"))

    def test_empty_file(self):
        with self.assertRaises(PolicyConfigError):
            Policy.load(self._write(""))

    def test_duplicate_keys_are_rejected(self):
        with self.assertRaises(PolicyConfigError):
            Policy.load(
                self._write(
                    '{"default_decision": "block", "default_decision": "allow"}'
                )
            )

    def test_bom_prefixed_policy(self):
        with self.assertRaises(PolicyConfigError):
            Policy.load(self._write('\ufeff{"default_decision": "block"}'))

    def test_unreadable_path(self):
        missing = Path(tempfile.mkdtemp()) / "missing.json"
        with self.assertRaises(PolicyConfigError):
            Policy.load(missing)

    def test_policy_path_is_a_directory(self):
        directory = Path(tempfile.mkdtemp())
        with self.assertRaises(PolicyConfigError):
            Policy.load(directory)


class ExplainMultiBudgetTests(unittest.TestCase):
    def test_all_exhausted_budgets_are_marked_triggered(self):
        policy = Policy.from_dict(
            {
                "default_decision": "allow",
                "budget": {"max_calls": 1, "max_cost_usd": "0.40"},
            }
        )
        usage = Usage()
        usage.tool_calls = 1
        usage.estimated_cost_usd = Decimal("0.50")
        call = ToolCall.create("search", estimated_cost_usd="0.10")
        explanation = explain_call(policy, call, usage)
        triggered = {
            check.name for check in explanation.budget.checks if check.triggered
        }
        self.assertEqual(triggered, {"max_calls", "max_cost_usd"})
        self.assertEqual(explanation.budget.message, "run tool-call budget exhausted")


class StateCorruptionTests(unittest.TestCase):
    def test_corrupt_run_usage_row_raises_storage_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "firewall.db"
            store = SQLiteStateStore(path)
            store.evaluate_and_reserve(
                Policy.from_dict({"default_decision": "allow"}),
                ToolCall.create("search"),
            )
            import sqlite3

            with sqlite3.connect(str(path)) as connection:
                connection.execute(
                    "UPDATE run_usage SET estimated_cost_usd = 'garbage' WHERE id = 1"
                )
            with self.assertRaisesRegex(StorageError, "cost record is corrupted"):
                store.usage()
            with self.assertRaises(StorageError):
                store.evaluate_and_reserve(
                    Policy.from_dict({"default_decision": "allow"}),
                    ToolCall.create("search"),
                )


class HugePayloadTests(unittest.TestCase):
    """Large values must not crash or blow up the matchers."""

    def test_megabyte_sql_statement(self):
        statement = "select " + "a" * 1_000_000
        self.assertTrue(
            matchers.match({"operator": "sql", "equals": "select"}, statement)
        )

    def test_megabyte_url(self):
        url = "http://example.com/" + "p" * 1_000_000
        self.assertTrue(
            matchers.match({"operator": "url", "hostname": "example.com"}, url)
        )

    def test_megabyte_command_argv(self):
        self.assertTrue(
            matchers.match(
                {"operator": "command", "executable": "git"},
                ["git", "commit", "-m", "x" * 1_000_000],
            )
        )

    def test_long_path_value(self):
        value = "/tmp/" + "d/" * 100000 + "file"
        self.assertTrue(matchers.match({"operator": "path", "within": "/tmp"}, value))
        self.assertFalse(matchers.match({"operator": "path", "within": "/etc"}, value))

    def test_many_star_glob_is_not_pathological(self):
        pattern = "*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a"
        self.assertTrue(matchers.glob_match(pattern, "a" * 100_000))
        self.assertFalse(matchers.glob_match(pattern, "a" * 99_999 + "b"))

    def test_glob_match_matches_fnmatch_semantics(self):
        import fnmatch

        cases = (
            ("*", "anything"),
            ("*.example.com", "api.example.com"),
            ("git*", "git-lfs"),
            ("?at", "cat"),
            ("[abc]at", "bat"),
            ("a[!x]c", "abc"),
            ("exact", "exact"),
            ("*a*b*", "xxaxxbxx"),
        )
        for pattern, value in cases:
            with self.subTest(pattern=pattern, value=value):
                self.assertEqual(
                    matchers.glob_match(pattern, value),
                    fnmatch.fnmatchcase(value, pattern),
                )


class UnicodeTests(unittest.TestCase):
    def test_unicode_hostname_does_not_crash(self):
        self.assertFalse(
            matchers.match(
                {"operator": "url", "hostname": "example.com"},
                "http://exämple.com/",
            )
        )

    def test_unicode_path_matches(self):
        self.assertTrue(
            matchers.match(
                {"operator": "path", "equals": "/tmp/é"},
                "/tmp/\u00e9",
            )
        )

    def test_unicode_sql_comments(self):
        self.assertTrue(
            matchers.match(
                {"operator": "sql", "equals": "select"},
                "-- émoji comment\nselect 1",
            )
        )

    def test_unicode_command_arguments(self):
        self.assertTrue(
            matchers.match(
                {"operator": "command", "argv_prefix": ["git", "commit"]},
                ["git", "commit", "-m", "héllo \U0001f600"],
            )
        )

    def test_unicode_glob_value(self):
        self.assertTrue(matchers.glob_match("*é*", "héllo"))


class DoctorEmptyCommandTests(unittest.TestCase):
    def test_empty_mcp_command_is_checked_not_crashed(self):
        from agent_firewall import doctor

        with tempfile.TemporaryDirectory() as directory:
            policy_path = Path(directory) / "policy.json"
            policy_path.write_text('{"default_decision": "block"}', encoding="utf-8")
            checks = doctor.run_checks(policy_path, mcp_command=[])
            by_name = {check.name: check for check in checks}
            self.assertFalse(by_name["mcp"].ok)
            self.assertIn("no MCP command", by_name["mcp"].message)


class ToolCallBoundaryTests(unittest.TestCase):
    def test_tool_names_reject_line_breaks(self):
        for name in (
            "email.send\nrm -rf ~",
            "email.send\r\nrm -rf ~",
            "\nemail.send",
            "email.send\n",
        ):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    ToolCall.create(name=name)

    def test_tool_names_still_accept_plain_strings(self):
        for name in ("database.query", "email.send", "tool\tname"):
            with self.subTest(name=name):
                ToolCall.create(name=name)


class CostMagnitudeTests(unittest.TestCase):
    def test_astronomical_exponents_are_rejected_not_accepted(self):
        for cost in ("1e999999999999999999", 10**400, "1e" + str(10**6)):
            with self.subTest(cost=cost):
                with self.assertRaises(ValueError):
                    ToolCall.create(name="t", arguments={}, estimated_cost_usd=cost)

    def test_ordinary_costs_are_still_accepted(self):
        from agent_firewall.models import MAX_CALL_COST_USD

        for cost in (0, "0.25", "19.99", 1e5, Decimal("2500000")):
            with self.subTest(cost=cost):
                call = ToolCall.create(name="t", arguments={}, estimated_cost_usd=cost)
                self.assertLessEqual(call.estimated_cost_usd, MAX_CALL_COST_USD)

    def test_cap_boundary_is_inclusive(self):
        from agent_firewall.models import MAX_CALL_COST_USD

        accepted = ToolCall.create(
            name="t", arguments={}, estimated_cost_usd=Decimal("1e12")
        )
        self.assertEqual(accepted.estimated_cost_usd, MAX_CALL_COST_USD)
        with self.assertRaises(ValueError):
            ToolCall.create(name="t", arguments={}, estimated_cost_usd="1.000001e12")


class ReservationSemanticsTests(unittest.TestCase):
    def test_reserves_usage_truth_table(self):
        from agent_firewall import Decision
        from agent_firewall.models import DecisionKind

        allow = Decision(DecisionKind.ALLOW, "r", "rule")
        block = Decision(DecisionKind.BLOCK, "r", "rule")
        hold = Decision(DecisionKind.REQUIRE_APPROVAL, "r", "rule")
        self.assertTrue(allow.reserves_usage(approved=False))
        self.assertTrue(allow.reserves_usage(approved=True))
        self.assertFalse(block.reserves_usage(approved=False))
        self.assertFalse(block.reserves_usage(approved=True))
        self.assertFalse(hold.reserves_usage(approved=False))
        self.assertTrue(hold.reserves_usage(approved=True))


if __name__ == "__main__":
    unittest.main()
