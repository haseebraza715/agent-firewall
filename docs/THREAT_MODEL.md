# Threat model

This document describes what Agent Firewall enforces, what it does not
enforce, and how it fails. It is written for reviewers who want to know
exactly where the enforcement boundary sits and what a regression test can
and cannot prove.

## Enforcement boundary

Agent Firewall is an in-process enforcement point around tool calls and a
stdio proxy in front of a local MCP child server. It sees the tool name and
the arguments after positional arguments are resolved to parameter names,
plus a per-call estimated cost. Over the MCP proxy, a client-supplied cost in
`params._meta.estimated_cost_usd` is read and validated, so cost budgets
enforce before a call is forwarded; an absent cost means zero. It decides
`allow`, `require_approval`, or `block` before the underlying tool runs. When
an audit path is configured, decided outcomes are appended to a JSONL audit
log.

MCP cost metadata is an unverified client assertion. A client can omit
`params._meta.estimated_cost_usd`, which the proxy treats as zero; deployments
that require authoritative cost enforcement must derive cost before this
boundary rather than trusting the caller.

Decisions come from the ordered policy engine (`src/agent_firewall/policy.py`):
rules matched by tool name and arguments, budgets and repetition caps, and a
fail-closed default. The MCP proxy (`src/agent_firewall/mcp_proxy.py`) is the
only component that reads and writes the JSON-RPC stream between the client
and the wrapped server, and every `tools/call` passes through the policy.
Other MCP methods (`initialize`, `tools/list`, `resources/read`,
`prompts/get`, notifications) are relayed without policy evaluation: they are
in scope for the framing, duplicate-key, batch, and timeout defenses, but a
method that can fetch a URL or read a file without being a `tools/call` is
not policed today.

## Assets

- **Tool-call authorization.** No guarded tool executes without a decision.
- **Budget and repetition counters.** Persisted in SQLite so they survive
  restarts (`src/agent_firewall/state.py`).
- **The optional audit log.** JSONL, with arguments omitted by default because
  they commonly contain secrets (`src/agent_firewall/audit.py`).
- **Pending approvals.** The SQLite-backed queue and the loopback-only
  dashboard (`src/agent_firewall/approvals.py`, `dashboard.py`).
- **Integrity of the JSON-RPC stream.** The client-to-server path the proxy
  guards.

## Trust assumptions

- The embedding code is trusted to route calls through the firewall
  (`Firewall.wrap`, `Firewall.call`, `Firewall.acall`). A caller that invokes
  a tool directly never enters the enforcement boundary.
- The policy file is trusted configuration: the operator writes it, and the
  loader rejects unknown keys so a typo cannot silently widen enforcement.
- Same-operating-system-user processes are trusted. They can read or write
  the state file and the audit log directly; the firewall does not defend
  against same-user tampering, and the dashboard threat model is documented
  in [SECURITY.md](../SECURITY.md).
- The human approver (terminal or dashboard) is trusted to make the final
  decision.
- Once a call is allowed, the tool implementation and its arguments are
  trusted to do what the operator expects.

## Out of scope

Agent Firewall is an enforcement point, not a sandbox. Specifically it does
**not** provide:

- **Operating-system isolation.** A blocked decision stops the call, but the
  tool process, the wrapped server, and the agent itself run with the
  permissions of the embedding user. Use least-privilege credentials and OS
  isolation as separate layers.
- **Prompt-injection detection.** Nothing inspects tool outputs for
  instruction-like content before it reaches the model.
- **Distributed or multi-host budgets.** Budgets are per state store (per
  run, per host), not coordinated across machines.
- **External adoption or an independent safety evaluation.** The benchmark in
  `benchmarks/v1` is an internal development benchmark; its reports are
  selected replay coverage, not a held-out evaluation.
- **Encryption of the audit log or state at rest**, and defense against a
  same-user attacker who can read or write those files directly.

## Failure matrix

| Failure | Behavior | Where enforced | Regression test |
|---|---|---|---|
| Unknown tool with no matching rule | blocked by the fail-closed default | `policy.py` | `tests/test_policy.py::PolicyTests::test_policy_fails_closed_by_default` |
| Null or malformed `tools/call` arguments | rejected with a JSON-RPC params error; never evaluated as empty and never forwarded raw | `mcp_proxy.py` | `tests/test_mcp_proxy.py::McpProxyTests::test_tools_call_with_null_arguments_is_rejected`, `test_tools_call_with_non_object_arguments_is_rejected`, `test_name_only_allow_rule_does_not_rescue_malformed_arguments`, `test_tools_call_with_non_object_params_is_rejected` |
| Client or child line containing duplicate JSON keys | client lines are answered with a parse error; child-originated frames are dropped so an ambiguous response can never be relayed verbatim to the client — the pending request fails closed at its timeout | `jsonrpc.py` (`decode_message`), `mcp_proxy.py` (`_read_child`) | `tests/test_jsonrpc.py::JsonRpcFramingTests::test_duplicate_keys_at_any_depth_are_rejected`, `tests/test_mcp_proxy.py::McpProxyTests::test_duplicate_key_child_response_is_dropped_and_request_fails_closed` |
| `tools/call` requiring approval with no approver configured | answered with `-32001` and a message naming the missing approver, with `data.decision = "require_approval"`; the call is not executed | `mcp_proxy.py`, `firewall.py` | `tests/test_mcp_proxy_inprocess.py::TruthfulProxyErrorTests::test_held_call_without_approver_reports_hold_not_block` |
| Audit write failure before execution | explicit `AuditWriteError`; execution is refused and the proxy answers `-32603` stating the call did not run | `audit.py`, `firewall.py` | `tests/test_audit_failures.py::AuditFailureTests::test_audit_write_failure_is_explicit_and_fail_closed` |
| Audit write failure after the call was attempted | explicit `AuditWriteError` with `after_execution=True`; the tool ran or its outcome is unknown, so the proxy answers `-32603` saying the audit record could not be written — it never claims the call did not execute | `firewall.py` (`_audit_terminal`) | `tests/test_firewall.py::TerminalAuditFailureTests::test_failure_after_execution_is_marked`, `tests/test_mcp_proxy_inprocess.py::TruthfulProxyErrorTests::test_post_execution_audit_failure_never_claims_not_executed` |
| Missing or empty tool name in `tools/call` | rejected with a JSON-RPC params error | `mcp_proxy.py` | `tests/test_mcp_proxy.py::McpProxyTests::test_tools_call_without_or_empty_name_is_rejected` |
| JSON-RPC batch requests | never forwarded; every id-bearing element answered with a batch error | `mcp_proxy.py` (`_reject_batch`) | `tests/test_mcp_proxy.py::McpProxyTests::test_jsonrpc_batch_is_rejected_not_forwarded` |
| Duplicate in-flight request id | the second request is answered with a duplicate-id error; the proxy stays alive | `mcp_proxy.py` (`_forward_request`) | `tests/test_mcp_proxy.py::McpProxyTests::test_duplicate_in_flight_id_returns_error_and_proxy_stays_alive` |
| Approval timeout | the waiting request auto-denies and fails closed | `approvals.py` (`SQLiteApprovalQueue.wait`) | `tests/test_approvals.py::ApprovalQueueTests::test_wait_auto_denies_after_timeout` |
| Audit write failure | explicit `AuditWriteError`; the call is not treated as executed when the failure happens before execution, and is reported as executed-but-unaudited when it happens after (see the two rows above) | `audit.py`, `firewall.py` | `tests/test_audit_failures.py::AuditFailureTests::test_audit_write_failure_is_explicit_and_fail_closed` |
| State read/write failure | explicit `StorageError`; no reservation is made and execution is refused | `state.py` | `tests/test_state.py::SQLiteStateStoreTests::test_corrupt_database_has_targeted_error`, `tests/test_cli.py::CliTests::test_storage_failure_exits_with_invalid_input_code` |
| Child MCP server exits before responding | the pending request fails closed with an error instead of hanging | `mcp_proxy.py` (`_read_child`) | `tests/test_mcp_proxy.py::McpProxyTests::test_child_server_failure_fails_pending_call_closed` |
| Child MCP server stalls without responding | the request times out after `--request-timeout` seconds and is answered with a fail-closed JSON-RPC error (`-32002`); the eventual late response is discarded and the proxy stays alive | `mcp_proxy.py` (`_forward_request`, `_read_child`) | `tests/test_mcp_proxy.py::McpProxyTests::test_request_timeout_fails_call_closed`, `test_late_response_after_timeout_is_discarded_and_proxy_stays_alive` |
| Child MCP server stops reading stdin | request and notification writes time out after `--request-timeout`; the child is terminated and awaited (then killed if needed) to prevent a cancelled partial write from corrupting JSONL framing; concurrent and later requests receive child-unavailable error `-32003` | `mcp_proxy.py` (`_write_child_with_timeout`, `_abort_child`) | `tests/test_mcp_proxy.py::McpProxyTests::test_request_timeout_covers_child_write_and_audits_failed`, `test_passthrough_notification_timeout_aborts_child`, `test_tool_notification_timeout_is_audited_failed`, `test_real_stalled_write_terminates_child_and_marks_session_unavailable` |
| Malformed `params._meta.estimated_cost_usd` | the call is rejected with a JSON-RPC params error and never forwarded or executed | `mcp_proxy.py` (`_extract_cost`) | `tests/test_mcp_proxy.py::McpProxyTests::test_invalid_cost_is_rejected_and_not_forwarded`, `test_invalid_cost_notification_is_dropped_not_forwarded` |
| A `params._meta.estimated_cost_usd` that exceeds a cost budget | blocked by `max_cost_usd` before the child is reached; other `_meta` keys are still forwarded unchanged | `mcp_proxy.py` (`_extract_cost`), `policy.py` | `tests/test_mcp_proxy.py::McpProxyTests::test_cost_budget_blocks_without_reaching_child`, `test_meta_with_cost_and_other_keys_is_forwarded_unchanged` |
| Direct calls outside the proxy | not covered: they never enter the enforcement boundary | n/a | `tests/test_firewall.py::ArgumentBindingTests` documents the in-process call contract the boundary depends on |

The failure matrix is not a substitute for a security review of the embedding
deployment: every row still assumes the trust assumptions above hold.
