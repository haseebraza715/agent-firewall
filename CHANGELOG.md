# Changelog

## 0.2.0 — 2026-07-06

- Match policy rules against selected tool arguments.
- Detect repeated identical tool calls using canonical fingerprints.
- Add privacy-aware argument auditing.
- Guard arbitrary local MCP stdio servers without code changes.
- Persist budgets and approvals in SQLite.
- Add a loopback-only dashboard with idempotent web approvals.

## 0.1.0 — 2026-07-06

- Add the first framework-neutral policy engine and Python tool wrapper.
- Enforce call, per-tool, and estimated-cost budgets.
- Add terminal approvals, JSONL auditing, complaint replay, and tests.
