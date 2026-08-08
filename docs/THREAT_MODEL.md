# Threat model

This document describes what Agent Firewall enforces, what it does not
enforce, and how it fails. It is written for reviewers who want to know
exactly where the enforcement boundary sits and what a regression test can
and cannot prove.

## Enforcement boundary

Agent Firewall is an in-process enforcement point around tool calls and a
stdio proxy in front of a local MCP child server. It sees the tool name and
the arguments after positional arguments are resolved to parameter names,
plus a per-call estimated cost. It decides `allow`, `require_approval`, or
`block` before the underlying tool runs. When an audit path is configured,
decided outcomes are appended to a JSONL audit log.

Decisions come from the ordered policy engine (`src/agent_firewall/policy.py`):
rules matched by tool name and arguments, budgets and repetition caps, and a
fail-closed default. The MCP proxy (`src/agent_firewall/mcp_proxy.py`) is the
only component that reads and writes the JSON-RPC stream between the client
and the wrapped server, and every `tools/call` passes through the policy.

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
| Null or malformed `tools/call` arguments | evaluated with no arguments or rejected; never forwarded raw | `mcp_proxy.py` | `tests/test_mcp_proxy.py::McpProxyTests::test_tools_call_with_null_arguments_is_policed`, `test_tools_call_with_non_object_arguments_is_policed`, `test_tools_call_with_non_object_params_is_rejected` |
| Missing or empty tool name in `tools/call` | rejected with a JSON-RPC params error | `mcp_proxy.py` | `tests/test_mcp_proxy.py::McpProxyTests::test_tools_call_without_or_empty_name_is_rejected` |
| JSON-RPC batch requests | never forwarded; every id-bearing element answered with a batch error | `mcp_proxy.py` (`_reject_batch`) | `tests/test_mcp_proxy.py::McpProxyTests::test_jsonrpc_batch_is_rejected_not_forwarded` |
| Duplicate in-flight request id | the second request is answered with a duplicate-id error; the proxy stays alive | `mcp_proxy.py` (`_forward_request`) | `tests/test_mcp_proxy.py::McpProxyTests::test_duplicate_in_flight_id_returns_error_and_proxy_stays_alive` |
| Approval timeout | the waiting request auto-denies and fails closed | `approvals.py` (`SQLiteApprovalQueue.wait`) | `tests/test_approvals.py::ApprovalQueueTests::test_wait_auto_denies_after_timeout` |
| Audit write failure | explicit `AuditWriteError`; the call is not treated as executed | `audit.py` | `tests/test_audit_failures.py::AuditFailureTests::test_audit_write_failure_is_explicit_and_fail_closed` |
| State read/write failure | explicit `StorageError`; no reservation is made and execution is refused | `state.py` | `tests/test_state.py::SQLiteStateStoreTests::test_corrupt_database_has_targeted_error`, `tests/test_cli.py::CliTests::test_storage_failure_exits_with_invalid_input_code` |
| Child MCP server exits before responding | the pending request fails closed with an error instead of hanging | `mcp_proxy.py` (`_read_child`) | `tests/test_mcp_proxy.py::McpProxyTests::test_child_server_failure_fails_pending_call_closed` |
| Direct calls outside the proxy | not covered: they never enter the enforcement boundary | n/a | `tests/test_firewall.py::ArgumentBindingTests` documents the in-process call contract the boundary depends on |

The failure matrix is not a substitute for a security review of the embedding
deployment: every row still assumes the trust assumptions above hold.
