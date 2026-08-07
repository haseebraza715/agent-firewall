# Changelog

## Unreleased

- Fix argument rules silently failing to match when a wrapped tool is called
  with positional arguments. `Firewall.call` and `Firewall.acall` now bind
  positional arguments to their parameter names before evaluating the policy,
  so a rule keyed on an argument applies regardless of call style. Previously
  such a rule could be skipped, which could let a call reach a permissive
  tool-name rule below it.
- Add `--format text` to `check` and `replay`. JSON remains the default. The
  text output is ASCII and stays within 72 columns so it renders cleanly in the
  recorded demo; `replay` shortens GitHub sources to `owner/repo#number`.
- Include the scenario `title` in `replay` results.
- Add `scripts/record-demo.sh` and `scripts/demo.exp`, and record the terminal
  demo to `docs/demo.cast` / `docs/demo.gif`.
- Correct the upstream reports cited by `examples/complaints.json`. The
  `langgraph#1097` reference did not exist as an issue or a discussion and is
  replaced by `langchain#26019`, which reports the same behaviour; the OpenCode
  repository has moved from `sst/opencode` to `anomalyco/opencode`; and the
  LangGraph human-in-the-loop scenario no longer claims the approval was
  "bypassed", which overstates a report about the approval never being shown.
- Add `scripts/check-sources.sh` to verify every cited report still resolves.
- Add `scripts/polish-demo-svg.py` and a `--svg` flag on the recorder, for a
  vector render. It pins every text run to its character cells and widens the
  font stack: svg-term relies on the viewer having one of several macOS-only
  fonts with an exactly 0.6 advance ratio, and without this the column-aligned
  output shears apart on the Linux renderers that serve GitHub READMEs.
- Catch `ToolCallBlocked` in `examples/wrap_tool.py` instead of exiting with a
  traceback, and show both a pre-approved and a gated recipient.

## 0.2.0 - 2026-07-06

- Match policy rules against selected tool arguments.
- Detect repeated identical tool calls using canonical fingerprints.
- Add privacy-aware argument auditing.
- Guard arbitrary local MCP stdio servers without code changes.
- Persist budgets and approvals in SQLite.
- Add a loopback-only dashboard with idempotent web approvals.

## 0.1.0 - 2026-07-06

- Add the first framework-neutral policy engine and Python tool wrapper.
- Enforce call, per-tool, and estimated-cost budgets.
- Add terminal approvals, JSONL auditing, complaint replay, and tests.
