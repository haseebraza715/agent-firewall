# Changelog

## Unreleased

- Terminal approver now shows the tool, its bounded arguments, and the policy
  reason; accepts `y`/`yes`; retries once after a non-answer; and states its
  denial when input ends or arrives empty.
- The MCP proxy explains held calls on stderr: with no approver configured it
  says to restart with `--approve-terminal` or `--approve-web`; with
  `--approve-web` it prints the exact dashboard start command at startup.
- The MCP proxy logs lifecycle events on stderr: spawned child command and
  pid, child exit code, and stalled-write aborts.
- The dashboard startup banner prints the effective approval token alongside
  the URL, and `dashboard --token` accepts a fixed token for scripted use.
- `dashboard --approval-timeout` aligns the dashboard with the proxy's hold
  window (default 300 seconds).
- Dashboard decisions surface failures instead of swallowing them: non-2xx
  approve/deny responses (for example after a dashboard restart minted a new
  token) appear in a `role="alert"` status region; keyboard focus stays on
  the same Approve/Deny button across the 1.5 s refresh; button text meets
  contrast guidelines; and the refresh timestamp no longer spams screen
  readers through a live region.
- Pending-approval listings hide rows older than the approval timeout and say
  how many are hidden, so approvals orphaned by a dead proxy do not silently
  accumulate in the operator's view.
- New live demo: `scripts/demo/attack_demo.py` runs a deliberately vulnerable
  MCP server behind the real proxy and walks six scenarios in under a second,
  including an octal-SSRF block, duplicate-key smuggling, stacked SQL, and a
  held call approved end-to-end through the dashboard API.

## 0.3.1 - 2026-08-22

## 0.3.1 - 2026-08-22

- Harden `deny_private_networks`: legacy IPv4 encodings (`127.1`,
  `2130706433`, `0x7f000001`, leading zeros) and IPv6 zone ids are now
  classified as the literal addresses they resolve to, closing an SSRF-style
  bypass of the private-networks gate.
- Make exact-value argument rules type-strict: `1` no longer matches `true`
  and `500` no longer matches `500.0` in policy `arguments`.
- Reject JSON policy, benchmark case, and freeze files with duplicate keys at
  load time so a duplicate-key typo cannot silently widen enforcement.
- Bound JSON processing depth everywhere agent-controlled data is serialized
  (tool fingerprints, audit records) or parsed (MCP proxy, CLI, dashboard,
  policy and benchmark loading), preventing `RecursionError` crashes on
  pathologically nested input.
- Add `--max-line-bytes` to the `mcp` command (default 64 MiB); oversized
  client or child lines are rejected or dropped without losing framing.
- Never forward undecodable or non-object client lines to the wrapped MCP
  server: they are answered with a JSON-RPC parse error instead of risking
  execution by a lenient server outside the policy.
- Reject batch requests whose elements would smuggle a `tools/call` past the
  per-line policy check; keep the per-element `-32600` rejection for batches
  that parse.
- Cache glob-to-regex translation so policy evaluation and matchers no longer
  recompile patterns on every call.
- `policy explain` now marks every exhausted budget check, not only the first
  one the policy reports.
- Corrupted SQLite state rows now raise `StorageError` instead of leaking
  `TypeError`/`InvalidOperation`; `doctor` reports an explicitly empty MCP
  command as a failed check.
- Harden the `sql` matcher against stacked statements: a statement separator
  followed by anything (`SELECT 1; DELETE ...`) never matches a read-only
  rule, closing the second-statement hole behind an allowed first keyword. A
  single trailing semicolon still matches; semicolons inside quoted literals
  also fail closed.
- Harden the `command` matcher against multi-statement spellings: string
  values containing line breaks never match, argv-list elements must satisfy
  the same shell-control rule as lexed string tokens, and backtick command
  substitution (`\`cmd\``) never matches in either form. Bare operators inside
  a longer list element stay inert data, matching execv semantics.
- Classify lone-integer URL hosts by value with explicit hex and octal bases
  instead of a length heuristic: `http://017700000001/` is now classified as
  `127.0.0.1` and denied by `deny_private_networks`. Integers beyond 32 bits
  classify by their modulo-2^32 wraparound, and dotted quads whose parts carry
  redundant leading zeros are classified under both the octal and decimal
  readings, matching the divergent behavior of real resolvers.
- Treat duplicate JSON keys anywhere in a JSON-RPC message as malformed input:
  client lines are answered with a parse error, and child-originated frames
  carrying duplicate keys are dropped rather than relayed, so neither side can
  act on a different view of a message than the one the proxy decoded. A
  request whose response was dropped fails closed at its timeout.
- Reject `tools/call` requests whose `arguments` are null or not an object
  with `-32602`, instead of evaluating them as `{}` while forwarding the
  original parameters.
- Report internal firewall errors truthfully over MCP: an audit-write failure
  on a terminal event answers `-32603` saying the tool ran or was attempted
  but its audit record could not be written; pre-execution failures and
  unexpected errors also use `-32603` and never claim a call "was not
  executed" unless it was.
- Give held calls without any approver their own signal: same `-32001` code,
  but the message names the missing approver so misconfiguration is not
  mistaken for a policy denial.
- Reject tool names containing line breaks at `ToolCall.create` so agent
  output cannot forge lines in text formatting.
- Raise `TypeError` from the synchronous `Firewall.call`/`wrap` path when a
  tool returns an awaitable, closing the coroutine instead of leaking an
  un-awaited call that would execute outside the firewall.
- Enforce finite positive timeouts in `SQLiteApprovalQueue` directly, not only
  through CLI flags.
- Cap per-call cost inputs at `$1e12`: astronomically large client-supplied
  `estimated_cost_usd` values are rejected at the boundary instead of
  overflowing budget accumulation later. Policy budget limits remain
  unrestricted trusted configuration.
- Validate numeric CLI flags: `--approval-timeout` and `--request-timeout`
  reject NaN/infinite/non-positive values, and `dashboard --port` must be
  0-65535, all failing at argument parsing instead of misbehaving at runtime.
- Make `replay` validate scenario input types (`arguments` object, string
  `title`/`source_url`) so malformed scenario files exit `2` with a terse
  error instead of a traceback.
- Run the policy linter inside `doctor`: error-severity lint findings now fail
  the `policy_lint` check.
- Add `pytest` to the `dev` extra so the documented
  `pip install -e .[dev] && python -m pytest tests` workflow works from a
  clean checkout.

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
