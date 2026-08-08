# Changelog

## Unreleased

Nothing yet.

## 0.3.0 - 2026-08-08

- Expand `benchmarks/v1` to 47 development cases: 26 unsafe or
  approval-required scenarios (10 reconstructed from public reports plus 16
  synthetic) and 21 internally curated safe controls, spanning six categories
  (`budget`, `destructive-action`, `missing-approval`, `network-ssrf`,
  `repetition-loop`, `side-effect`). The published development report is 47/47
  cases and 84/84 calls correct (exact decision accuracy 1.0000,
  dangerous-allow rate 0.0000, safe-call friction 0.0000). These are internal,
  internally labeled results only.
- Add a hash-pinned internal evaluation split under `benchmarks/v1/holdout`: 23
  distinct cases (11 synthetic unsafe or approval-required scenarios plus 12
  safe controls). `benchmarks/v1/freeze.json` confirms the policy and case
  SHA-256 hashes have not moved since the manifest was written. The `benchmark`
  command gains a `--freeze MANIFEST` flag that verifies the manifest and
  writes an `internal-evaluation-benchmark` report carrying
  `frozen_policy_sha256` and labels declaring the evaluation internally
  curated and labeled. A freeze mismatch fails with no report written. Add
  `scripts/run-holdout-benchmark.sh` and document that the cases were authored
  with access to the policy and inspected before the manifest was written.
  Hash pinning prevents later drift; it does not make the cases a blind
  holdout, independent, or externally validated.
- Add tests for freeze creation, freeze verification, policy and holdout
  mismatch rejection, holdout report labeling, holdout byte stability, and the
  `benchmark --freeze` CLI behavior, plus a published-evaluation coverage
  check (at least 20 unsafe and 20 safe scenarios across at least five
  categories).
- The Puppeteer issue 3662 reproduction now writes `evidence.json` only when
  the run passes. It clears stale evidence before starting, records the policy
  and package-lock SHA-256 hashes, and exits nonzero without leaving an earlier
  passing artifact behind when a later run fails.

- Add an opt-in end-to-end reproduction harness for the pinned
  `@modelcontextprotocol/server-puppeteer@0.6.2` package. It uses a loopback
  fixture to verify an allowed call, an approval pause, a prohibited call, and
  an identical-call budget stop without contacting a real metadata endpoint.
- Add typed argument matchers for policy rules. A rule argument value can now
  be an object with an `operator` key that selects a validated matcher: `url`
  (scheme, hostname, port, path, and literal-IP-only `deny_private_networks`),
  `path` (lexical absolute within/equals, no filesystem access), `domain`
  (email domain with subdomain suffix boundaries), `http_method`, `number`
  (inclusive min/max), `sql` (leading operation ignoring comments and
  whitespace), and `command` (executable glob plus argv prefix). Scalar string
  glob patterns and exact non-string patterns keep their previous behaviour.
  Unknown typed keys or operators fail policy load. See
  `docs/ARGUMENT_MATCHERS.md`.
- Add `policy lint` to report permissive defaults, missing budgets, shadowed
  duplicate/equivalent tool rules, broad allow-all tool patterns, unsafe URL
  string-glob lookalikes, allow rules with no argument constraints and a broad
  tool pattern, and approval rules shadowed by broader allow rules. Text and
  JSON output; nonzero exit when any error-level finding is present.
- Add `policy explain` to show budget evaluation, every rule's tool and
  argument match result, and the exact runtime decision. Text and JSON output.
- Add `doctor` to check policy loading, state and audit parent writability
  without destructive writes, optional MCP child command availability,
  fail-closed unknown-tool behaviour, and the installed version. Text and JSON
  output.
- Extend `benchmark` with optional threshold flags
  (`--max-dangerous-allow-rate`, `--max-safe-friction-rate`,
  `--min-intervention-recall`, `--min-approval-accuracy`,
  `--min-exact-accuracy`), each validated to the inclusive 0..1 range. Every
  failed threshold is printed and the command exits with code 5. Reports stay
  byte-stable.
- Update CI to regenerate the benchmark reports into a temporary directory and
  byte-compare them against the committed reports, and to build the wheel,
  install it into a clean virtual environment, and run `--help` plus a
  `benchmark` from the installed wheel.
- Add a deterministic `benchmark` command that evaluates a policy against
  labeled cases and writes byte-stable JSON and Markdown reports:
  `agent-firewall benchmark --policy PATH --cases PATH --output DIR`. Reports
  include exact decision accuracy, a 3x3 confusion matrix, unsafe
  intervention recall, dangerous-allow rate, safe-call friction rate,
  approval accuracy, per-category results, and SHA-256 hashes of the policy
  and case files. Output contains no timestamps, so repeated runs are
  identical.
- Add `benchmarks/v1`: an explicitly internal development benchmark with 26
  unsafe or approval-required scenarios (10 reconstructed from public reports
  plus 16 synthetic) and 21 paired safe controls across six categories, its
  own policy, regeneration scripts, and committed reports. It is not presented
  as external, independent, or held-out.
- Add `scripts/run-benchmark.sh` to regenerate the v1 reports in one command.
- Add `docs/THREAT_MODEL.md` describing the enforcement boundary, assets,
  trust assumptions, out-of-scope behavior, and a failure matrix with links
  to regression tests. Added regression tests for approval-timeout auto-denial
  and child-server failure failing pending calls closed.
- Correct public-claim wording throughout the documentation: the replayed
  inputs are reconstructed incident scenarios, ten based on public reports
  and one synthetic, and the 11/11 result is selected replay coverage rather
  than a held-out safety benchmark. Removed the contradictory "no pip"
  phrasing while keeping the zero-runtime-dependency claim.
- Fix the stale README anchor in `30-day-firewall-plan.md`.
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
