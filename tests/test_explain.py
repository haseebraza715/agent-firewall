import unittest
from decimal import Decimal

from agent_firewall import Policy, ToolCall, Usage
from agent_firewall.explain import explain_call, render_text


class ExplainTests(unittest.TestCase):
    def setUp(self):
        self.policy = Policy.from_dict(
            {
                "default_decision": "block",
                "budget": {"max_calls": 2},
                "rules": [
                    {
                        "tool": "email.*",
                        "arguments": {"to": "*@mycompany.com"},
                        "decision": "allow",
                        "reason": "company recipients allowed",
                    },
                    {
                        "tool": "email.*",
                        "decision": "require_approval",
                        "reason": "outbound email requires review",
                    },
                ],
            }
        )

    def test_final_decision_matches_runtime_evaluate(self):
        call = ToolCall.create("email.send", {"to": "x@example.com"})
        explanation = explain_call(self.policy, call, Usage())
        runtime = self.policy.evaluate(call, Usage())
        self.assertEqual(explanation.decision, runtime)

    def test_budget_is_visible_and_not_triggered_by_default(self):
        explanation = explain_call(self.policy, ToolCall.create("email.send"), Usage())
        self.assertFalse(explanation.budget.triggered)
        self.assertEqual(explanation.budget.checks[0].name, "max_calls")
        self.assertEqual(explanation.budget.checks[0].current, "0")
        self.assertEqual(explanation.budget.checks[0].limit, "2")

    def test_budget_trigger_is_reported(self):
        usage = Usage()
        usage.record(ToolCall.create("a"))
        usage.record(ToolCall.create("b"))
        explanation = explain_call(self.policy, ToolCall.create("c"), usage)
        self.assertTrue(explanation.budget.triggered)
        self.assertTrue(explanation.budget.checks[0].triggered)
        self.assertIsNotNone(explanation.budget.message)

    def test_every_rule_records_tool_and_argument_match(self):
        explanation = explain_call(
            self.policy,
            ToolCall.create("email.send", {"to": "x@example.com"}),
            Usage(),
        )
        allow_rule, approval_rule = explanation.rules
        self.assertTrue(allow_rule.tool_matched)
        self.assertFalse(allow_rule.arguments_matched)
        self.assertFalse(allow_rule.matched)
        self.assertFalse(allow_rule.selected)
        self.assertTrue(approval_rule.tool_matched)
        self.assertTrue(approval_rule.matched)
        self.assertTrue(approval_rule.selected)

    def test_first_match_is_selected_when_later_rule_also_matches(self):
        explanation = explain_call(
            self.policy,
            ToolCall.create("email.send", {"to": "x@mycompany.com"}),
            Usage(),
        )

        allow_rule, approval_rule = explanation.rules
        self.assertTrue(allow_rule.matched)
        self.assertTrue(allow_rule.selected)
        self.assertTrue(approval_rule.matched)
        self.assertFalse(approval_rule.selected)

    def test_cost_budget_shows_projected_cost(self):
        policy = Policy.from_dict(
            {"budget": {"max_cost_usd": "0.50"}, "default_decision": "allow"}
        )
        usage = Usage(estimated_cost_usd=Decimal("0.40"))

        explanation = explain_call(
            policy,
            ToolCall.create("search", estimated_cost_usd="0.11"),
            usage,
        )

        self.assertEqual(explanation.budget.checks[0].current, "0.51")
        self.assertTrue(explanation.budget.checks[0].triggered)

    def test_decision_carries_matching_rule_index(self):
        explanation = explain_call(
            self.policy,
            ToolCall.create("email.send", {"to": "x@example.com"}),
            Usage(),
        )
        self.assertEqual(explanation.decision.rule_index, 1)
        self.assertEqual(explanation.decision.kind.value, "require_approval")

    def test_default_decision_for_unknown_tool(self):
        explanation = explain_call(
            self.policy, ToolCall.create("unknown.tool"), Usage()
        )
        self.assertEqual(explanation.decision.kind.value, "block")
        self.assertEqual(explanation.decision.code, "default")

    def test_json_shape(self):
        explanation = explain_call(
            self.policy,
            ToolCall.create("email.send", {"to": "x@example.com"}),
            Usage(),
        )
        data = explanation.as_dict()
        self.assertEqual(data["tool"], "email.send")
        self.assertIn("budget", data)
        self.assertIn("rules", data)
        self.assertEqual(data["rules"][0]["tool_matched"], True)
        self.assertEqual(data["rules"][1]["matched"], True)
        self.assertEqual(data["rules"][1]["selected"], True)
        self.assertEqual(data["decision"]["decision"], "require_approval")

    def test_render_text_ends_with_decision_and_reason(self):
        text = render_text(
            explain_call(
                self.policy,
                ToolCall.create("email.send", {"to": "x@example.com"}),
                Usage(),
            )
        )
        self.assertIn("budget decision: none", text)
        self.assertIn("decision: require_approval (rule 1)", text)
        self.assertIn("outbound email requires review", text)
        self.assertIn("tool_match=yes", text)
        self.assertIn("argument_match=no", text)
        self.assertIn("selected=yes", text)

    def test_no_budget_policy_says_no_limits(self):
        policy = Policy.from_dict({})
        text = render_text(explain_call(policy, ToolCall.create("a"), Usage()))
        self.assertIn("no limits configured", text)
        self.assertIn("budget decision: none", text)


if __name__ == "__main__":
    unittest.main()
