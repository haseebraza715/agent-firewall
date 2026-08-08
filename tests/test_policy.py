import json
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

from agent_firewall import (
    ArgumentAuditMode,
    DecisionKind,
    Policy,
    PolicyConfigError,
    ToolCall,
    Usage,
)


class PolicyTests(unittest.TestCase):
    def test_first_matching_rule_wins(self):
        policy = Policy.from_dict(
            {
                "default_decision": "block",
                "rules": [
                    {"tool": "email.*", "decision": "require_approval"},
                    {"tool": "*", "decision": "allow"},
                ],
            }
        )

        decision = policy.evaluate(ToolCall.create("email.send"), Usage())

        self.assertEqual(decision.kind, DecisionKind.REQUIRE_APPROVAL)
        self.assertEqual(decision.rule_index, 0)

    def test_policy_fails_closed_by_default(self):
        policy = Policy.from_dict({})

        decision = policy.evaluate(ToolCall.create("unknown.tool"), Usage())

        self.assertEqual(decision.kind, DecisionKind.BLOCK)
        self.assertEqual(decision.code, "default")

    def test_string_argument_patterns_use_glob_matching(self):
        policy = Policy.from_dict(
            {
                "default_decision": "block",
                "rules": [
                    {
                        "tool": "email.send",
                        "arguments": {"to": "*@mycompany.com"},
                        "decision": "allow",
                    }
                ],
            }
        )

        internal = policy.evaluate(
            ToolCall.create("email.send", {"to": "person@mycompany.com"}),
            Usage(),
        )
        external = policy.evaluate(
            ToolCall.create("email.send", {"to": "person@example.com"}),
            Usage(),
        )

        self.assertEqual(internal.kind, DecisionKind.ALLOW)
        self.assertEqual(external.kind, DecisionKind.BLOCK)

    def test_non_string_argument_patterns_use_exact_matching(self):
        policy = Policy.from_dict(
            {
                "rules": [
                    {
                        "tool": "payment.charge",
                        "arguments": {"cents": 500, "live": False},
                        "decision": "allow",
                    }
                ]
            }
        )

        exact = policy.evaluate(
            ToolCall.create("payment.charge", {"cents": 500, "live": False}),
            Usage(),
        )
        changed = policy.evaluate(
            ToolCall.create("payment.charge", {"cents": 501, "live": False}),
            Usage(),
        )

        self.assertEqual(exact.kind, DecisionKind.ALLOW)
        self.assertEqual(changed.kind, DecisionKind.BLOCK)

    def test_missing_rule_argument_does_not_match(self):
        policy = Policy.from_dict(
            {
                "rules": [
                    {
                        "tool": "email.send",
                        "arguments": {"to": "*@mycompany.com"},
                        "decision": "allow",
                    }
                ]
            }
        )

        decision = policy.evaluate(ToolCall.create("email.send"), Usage())

        self.assertEqual(decision.kind, DecisionKind.BLOCK)

    def test_invalid_rule_arguments_are_rejected(self):
        with self.assertRaisesRegex(PolicyConfigError, "arguments must be an object"):
            Policy.from_dict(
                {
                    "rules": [
                        {
                            "tool": "email.send",
                            "arguments": "not-an-object",
                            "decision": "allow",
                        }
                    ]
                }
            )

    def test_unknown_top_level_keys_are_rejected(self):
        with self.assertRaisesRegex(PolicyConfigError, "default_decisionz"):
            Policy.from_dict({"default_decisionz": "block"})

    def test_unknown_rule_keys_are_rejected(self):
        with self.assertRaisesRegex(PolicyConfigError, r"rules\[0\]\.argument"):
            Policy.from_dict(
                {
                    "rules": [
                        {
                            "tool": "email.send",
                            "argument": {"to": "anyone@example.com"},
                            "decision": "allow",
                        }
                    ]
                }
            )

    def test_unknown_budget_keys_are_rejected(self):
        with self.assertRaisesRegex(PolicyConfigError, r"budget\.max_calss"):
            Policy.from_dict({"budget": {"max_calss": 3}})

    def test_argument_auditing_defaults_to_none(self):
        policy = Policy.from_dict({})

        self.assertEqual(policy.audit_arguments, ArgumentAuditMode.NONE)

    def test_invalid_argument_audit_mode_is_rejected(self):
        with self.assertRaisesRegex(PolicyConfigError, "audit_arguments"):
            Policy.from_dict({"audit_arguments": "unsafe"})

    def test_total_call_budget_blocks_next_call(self):
        policy = Policy.from_dict(
            {"default_decision": "allow", "budget": {"max_calls": 1}}
        )
        usage = Usage()
        first = ToolCall.create("search")
        usage.record(first)

        decision = policy.evaluate(ToolCall.create("other"), usage)

        self.assertEqual(decision.code, "max_calls")

    def test_per_tool_budget_only_counts_matching_tool(self):
        policy = Policy.from_dict(
            {"default_decision": "allow", "budget": {"max_calls_per_tool": 1}}
        )
        usage = Usage()
        usage.record(ToolCall.create("search"))

        blocked = policy.evaluate(ToolCall.create("search"), usage)
        allowed = policy.evaluate(ToolCall.create("fetch"), usage)

        self.assertEqual(blocked.code, "max_calls_per_tool")
        self.assertEqual(allowed.kind, DecisionKind.ALLOW)

    def test_identical_call_budget_includes_canonical_arguments(self):
        policy = Policy.from_dict(
            {"default_decision": "allow", "budget": {"max_identical_calls": 1}}
        )
        usage = Usage()
        usage.record(ToolCall.create("search", {"query": "firewall", "limit": 5}))

        repeated = policy.evaluate(
            ToolCall.create("search", {"limit": 5, "query": "firewall"}),
            usage,
        )
        changed = policy.evaluate(
            ToolCall.create("search", {"query": "firewall", "limit": 10}),
            usage,
        )

        self.assertEqual(repeated.code, "max_identical_calls")
        self.assertEqual(changed.kind, DecisionKind.ALLOW)

    def test_fingerprint_includes_tool_name(self):
        first = ToolCall.create("search.web", {"query": "same"})
        second = ToolCall.create("search.files", {"query": "same"})

        self.assertNotEqual(first.fingerprint, second.fingerprint)

    def test_cost_budget_uses_projected_cost(self):
        policy = Policy.from_dict(
            {"default_decision": "allow", "budget": {"max_cost_usd": "0.50"}}
        )
        usage = Usage(estimated_cost_usd=Decimal("0.40"))

        decision = policy.evaluate(
            ToolCall.create("search", estimated_cost_usd="0.11"),
            usage,
        )

        self.assertEqual(decision.code, "max_cost_usd")

    def test_invalid_budget_is_rejected(self):
        with self.assertRaisesRegex(PolicyConfigError, "positive integer"):
            Policy.from_dict({"budget": {"max_calls": True}})

    def test_invalid_money_is_rejected(self):
        with self.assertRaisesRegex(PolicyConfigError, "non-negative"):
            Policy.from_dict({"budget": {"max_cost_usd": "-1"}})

    def test_load_reports_invalid_json_location(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text('{"rules": [}', encoding="utf-8")

            with self.assertRaisesRegex(PolicyConfigError, "line 1"):
                Policy.load(path)

    def test_valid_policy_loads_from_disk(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(
                json.dumps({"default_decision": "allow"}),
                encoding="utf-8",
            )

            policy = Policy.load(path)

        self.assertEqual(policy.default_decision, DecisionKind.ALLOW)


class TypedMatcherPolicyTests(unittest.TestCase):
    def _policy(self, rule):
        return Policy.from_dict({"default_decision": "block", "rules": [rule]})

    def test_typed_url_matcher_runs_through_policy_evaluate(self):
        policy = self._policy(
            {
                "tool": "url.fetch",
                "arguments": {
                    "url": {
                        "operator": "url",
                        "scheme": "https",
                        "hostname": "example.com",
                    }
                },
                "decision": "allow",
            }
        )

        allowed = policy.evaluate(
            ToolCall.create("url.fetch", {"url": "https://example.com/a"}),
            Usage(),
        )
        blocked = policy.evaluate(
            ToolCall.create("url.fetch", {"url": "https://evil.com/a"}),
            Usage(),
        )

        self.assertEqual(allowed.kind, DecisionKind.ALLOW)
        self.assertEqual(blocked.kind, DecisionKind.BLOCK)

    def test_typed_command_matcher_and_old_glob_coexist(self):
        policy = Policy.from_dict(
            {
                "default_decision": "block",
                "rules": [
                    {
                        "tool": "shell.run",
                        "arguments": {
                            "command": {"operator": "command", "executable": "git"}
                        },
                        "decision": "allow",
                    },
                    {
                        "tool": "email.send",
                        "arguments": {"to": "*@mycompany.com"},
                        "decision": "allow",
                    },
                ],
            }
        )

        git = policy.evaluate(
            ToolCall.create("shell.run", {"command": "git status"}),
            Usage(),
        )
        internal = policy.evaluate(
            ToolCall.create("email.send", {"to": "a@mycompany.com"}),
            Usage(),
        )

        self.assertEqual(git.kind, DecisionKind.ALLOW)
        self.assertEqual(internal.kind, DecisionKind.ALLOW)

    def test_unknown_typed_operator_fails_load(self):
        with self.assertRaisesRegex(PolicyConfigError, "unknown matcher operator"):
            Policy.from_dict(
                {
                    "rules": [
                        {
                            "tool": "a",
                            "arguments": {"x": {"operator": "bogus"}},
                            "decision": "allow",
                        }
                    ]
                }
            )

    def test_unknown_typed_key_fails_load(self):
        with self.assertRaisesRegex(
            PolicyConfigError, "unknown typed matcher key\\(s\\)"
        ):
            Policy.from_dict(
                {
                    "rules": [
                        {
                            "tool": "a",
                            "arguments": {"x": {"operator": "url", "bogus": 1}},
                            "decision": "allow",
                        }
                    ]
                }
            )

    def test_invalid_typed_field_fails_load(self):
        with self.assertRaisesRegex(PolicyConfigError, "port"):
            Policy.from_dict(
                {
                    "rules": [
                        {
                            "tool": "a",
                            "arguments": {"x": {"operator": "url", "port": -1}},
                            "decision": "allow",
                        }
                    ]
                }
            )

    def test_missing_rule_argument_does_not_match_typed_pattern(self):
        policy = self._policy(
            {
                "tool": "url.fetch",
                "arguments": {"url": {"operator": "url", "hostname": "example.com"}},
                "decision": "allow",
            }
        )

        decision = policy.evaluate(ToolCall.create("url.fetch"), Usage())

        self.assertEqual(decision.kind, DecisionKind.BLOCK)


if __name__ == "__main__":
    unittest.main()
