import unittest

from agent_firewall import Policy
from agent_firewall.lint import (
    Finding,
    lint_policy,
    render_text,
    to_dict,
)


def findings_of(policy_dict):
    return lint_policy(Policy.from_dict(policy_dict))


def codes_of(policy_dict):
    return [finding.code for finding in findings_of(policy_dict)]


class LintDefaultAndBudgetTests(unittest.TestCase):
    def test_permissive_default_is_an_error(self):
        findings = findings_of({"default_decision": "allow"})
        self.assertEqual(findings[0].severity, "error")
        self.assertEqual(findings[0].code, "permissive_default")

    def test_block_default_is_not_flagged(self):
        self.assertNotIn("permissive_default", codes_of({"default_decision": "block"}))

    def test_missing_budgets_is_an_error(self):
        self.assertIn("no_budgets", codes_of({}))

    def test_partial_budget_is_not_flagged(self):
        self.assertNotIn("no_budgets", codes_of({"budget": {"max_calls": 10}}))


class LintRuleTests(unittest.TestCase):
    def test_broad_allow_all_pattern_is_flagged(self):
        findings = findings_of({"rules": [{"tool": "*", "decision": "allow"}]})
        self.assertIn("broad_allow_all", [f.code for f in findings])

    def test_allow_rule_with_glob_and_no_args_is_flagged(self):
        findings = findings_of({"rules": [{"tool": "email.*", "decision": "allow"}]})
        self.assertIn("empty_arguments", [f.code for f in findings])

    def test_exact_tool_name_rule_without_args_is_not_flagged(self):
        self.assertNotIn(
            "empty_arguments",
            codes_of({"rules": [{"tool": "database.query", "decision": "allow"}]}),
        )

    def test_url_glob_lookalike_argument_is_flagged(self):
        findings = findings_of(
            {
                "rules": [
                    {
                        "tool": "url.fetch",
                        "decision": "allow",
                        "arguments": {"url": "https://*.example.com/*"},
                    }
                ]
            }
        )
        self.assertIn("url_glob_lookalike", [f.code for f in findings])

    def test_plain_glob_argument_is_not_a_url_lookalike(self):
        self.assertNotIn(
            "url_glob_lookalike",
            codes_of(
                {
                    "rules": [
                        {
                            "tool": "email.send",
                            "decision": "allow",
                            "arguments": {"to": "*@mycompany.com"},
                        }
                    ]
                }
            ),
        )


class LintShadowingTests(unittest.TestCase):
    def test_equivalent_rules_are_flagged_as_shadowed(self):
        findings = findings_of(
            {
                "rules": [
                    {"tool": "email.*", "decision": "allow"},
                    {"tool": "email.*", "decision": "allow"},
                ]
            }
        )
        shadowed = [f for f in findings if f.code == "shadowed_equivalent"]
        self.assertEqual(len(shadowed), 1)
        self.assertEqual(shadowed[0].rule_index, 1)
        self.assertEqual(shadowed[0].severity, "error")

    def test_allow_rule_shadowing_approval_is_flagged(self):
        findings = findings_of(
            {
                "rules": [
                    {"tool": "email.*", "decision": "allow"},
                    {"tool": "email.send", "decision": "require_approval"},
                ]
            }
        )
        shadowed = [f for f in findings if f.code == "approval_shadowed_by_allow"]
        self.assertEqual(len(shadowed), 1)
        self.assertEqual(shadowed[0].rule_index, 1)

    def test_exact_allow_rule_does_not_shadow_other_tool_approval(self):
        self.assertNotIn(
            "approval_shadowed_by_allow",
            codes_of(
                {
                    "rules": [
                        {"tool": "database.query", "decision": "allow"},
                        {"tool": "filesystem.delete", "decision": "require_approval"},
                    ]
                }
            ),
        )

    def test_allow_rule_with_arguments_does_not_shadow_approval(self):
        self.assertNotIn(
            "approval_shadowed_by_allow",
            codes_of(
                {
                    "rules": [
                        {
                            "tool": "email.*",
                            "decision": "allow",
                            "arguments": {"to": "*@mycompany.com"},
                        },
                        {"tool": "email.send", "decision": "require_approval"},
                    ]
                }
            ),
        )


class LintRenderingTests(unittest.TestCase):
    def test_clean_policy_text(self):
        text = render_text("policy.json", [])
        self.assertEqual(text, "policy lint: policy.json: no findings")

    def test_render_text_includes_severity_and_count(self):
        findings = [
            Finding("error", "permissive_default", "default is allow"),
            Finding("warning", "empty_arguments", "no arguments", rule_index=3),
        ]
        text = render_text("policy.json", findings)
        self.assertIn("error: permissive_default", text)
        self.assertIn("warning: empty_arguments: rule 3:", text)
        self.assertIn("1 error(s), 1 warning(s)", text)

    def test_to_dict_counts_and_serializes(self):
        findings = [Finding("error", "no_budgets", "no budgets")]
        data = to_dict("policy.json", findings)
        self.assertEqual(data["policy"], "policy.json")
        self.assertEqual(data["error_count"], 1)
        self.assertEqual(data["warning_count"], 0)
        self.assertEqual(data["findings"][0]["code"], "no_budgets")

    def test_example_policy_lints_clean(self):
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        policy = Policy.load(root / "examples" / "policy.json")
        self.assertEqual(lint_policy(policy), [])

    def test_demo_policy_lints_clean(self):
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        policy = Policy.load(root / "examples" / "demo_policy.json")
        self.assertEqual(
            [
                finding.code
                for finding in lint_policy(policy)
                if finding.severity == "error"
            ],
            [],
        )


if __name__ == "__main__":
    unittest.main()
