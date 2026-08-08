# Benchmark v1

An **internal development benchmark** and a **hash-pinned internal evaluation
split** for the Agent Firewall policy engine.

Status: development. Both case sets are written and maintained by this
repository to catch regressions in the policy engine and in the example policy.
They are **not** external, independent, or blind held-out safety evaluations. A
passing report is selected replay coverage of scenarios we reconstructed and
labeled ourselves; it does not measure safety on unseen real-world traffic.

## Contents

| File | Purpose |
|---|---|
| `policy.json` | the policy under test |
| `cases.json` | 47 labeled development cases (see below) |
| `freeze.json` | SHA-256 freeze of the policy, dev cases, and holdout cases |
| `run.sh` | regenerates the development reports |
| `reports/report.json` | development report (machine-readable, byte-stable) |
| `reports/report.md` | development report (human-readable, byte-stable) |
| `holdout/cases.json` | 23 internally labeled evaluation cases, distinct from `cases.json` |
| `holdout/reports/` | evaluation report, written only after hash verification |
| `holdout/run.sh` | verifies the hashes, then regenerates the evaluation reports |

## Development cases

`cases.json` contains 47 cases:

- **26 unsafe or approval-required scenarios.** 10 are reconstructed from
  public bug reports against other projects (`reconstructed-public-report`
  provenance, each with a `source_url`); the other 16 are internally written
  synthetic scenarios (`synthetic` provenance) covering budget caps, SSRF-style
  browser navigation, destructive filesystem actions, side effects, and
  repetition loops. Each is expected to stop or gate the risky action.
- **21 paired safe controls.** These cover normal behaviour that must keep
  flowing (`internal-control` provenance): browser navigation to a documented
  safe site, approved internal email recipients, read-only filesystem access,
  non-identical and single searches/shell/model/delegation calls, and
  sequential calls that stay under the budgets.

The 47 cases span six categories: `budget`, `destructive-action`,
`missing-approval`, `network-ssrf`, `repetition-loop`, and `side-effect`.

Every case carries a `provenance` label: `reconstructed-public-report`,
`synthetic`, or `internal-control`.

## Case schema

```json
{
  "id": "unique non-empty string",
  "title": "optional string",
  "category": "non-empty string, groups per-category results",
  "provenance": "reconstructed-public-report | synthetic | internal-control",
  "source_url": "optional string or null",
  "calls": [
    {"tool": "tool.name", "arguments": {...}, "estimated_cost_usd": "0.02"}
  ],
  "expected_decisions": ["allow" | "require_approval" | "block", ...]
}
```

The calls inside one case are evaluated sequentially against a single
`Usage`, so per-tool, identical-call, and cost budgets apply within the case.
Each case starts from a fresh `Usage`, matching `replay` semantics. Unknown
keys are rejected at load time.

## Metrics

Let `allow`, `require_approval`, and `block` remain separate everywhere.

- **Exact decision accuracy.** Predicted equals expected for every call.
- **Unsafe intervention recall.** Unsafe calls (expected `require_approval`
  or `block`) predicted `require_approval` or `block`, divided by all unsafe
  calls.
- **Dangerous-allow rate.** Expected-`block` calls predicted `allow`, divided
  by expected-`block` calls.
- **Safe-call friction rate.** Expected-`allow` calls predicted
  `require_approval` or `block`, divided by expected-`allow` calls.
- **Approval accuracy.** Expected-`require_approval` calls predicted
  `require_approval`, divided by expected-`require_approval` calls.
- **3x3 confusion matrix.** Expected rows, predicted columns.

A rate with an empty denominator is reported as `n/a` in Markdown and `null`
in JSON, never as a misleading zero.

## Published results (development benchmark)

Regenerated from the committed `policy.json` and `cases.json`:

| metric | value |
|---|---|
| cases | 47 |
| calls | 84 |
| exact decision accuracy | 1.0000 |
| unsafe intervention recall | 1.0000 |
| dangerous-allow rate | 0.0000 |
| safe-call friction rate | 0.0000 |
| approval accuracy | 1.0000 |

Confusion matrix (expected rows, predicted columns):

| expected \ predicted | allow | require_approval | block |
|---|---|---|---|
| allow | 58 | 0 | 0 |
| require_approval | 0 | 10 | 0 |
| block | 0 | 0 | 16 |

These numbers are on the internally curated set only. They say nothing about
unseen real-world traffic: the policy was written alongside these cases, the
labels are ours, and the evaluation is deliberately not held out.

## Frozen internal evaluation split

`holdout/cases.json` contains 23 distinct cases (11 synthetic unsafe or
approval-required scenarios plus 12 safe controls, all labeled internally).
Before the evaluation report can be written, `freeze.json` must verify that
`policy.json` and `holdout/cases.json` still match the SHA-256 hashes recorded
at freeze time:

```bash
./scripts/run-holdout-benchmark.sh
```

If either hash has moved since the manifest was written, the command fails and
writes no report. The report records `frozen_policy_sha256` and labels itself
`internal-evaluation-benchmark`. The cases were authored with access to the
policy, and their initial results were inspected before the manifest was
written. The hashes prevent later drift; they do not make this a blind holdout,
an independent evaluation, or external validation.

Current evaluation-split results are 23/23 cases and 31/31 calls correct (exact
decision accuracy 1.0000, dangerous-allow rate 0.0000, safe-call friction rate
0.0000). These are the results published in `holdout/reports/`.

## Regenerate

```bash
./benchmarks/v1/run.sh
```

or, from anywhere in the repository:

```bash
./scripts/run-benchmark.sh
./scripts/run-holdout-benchmark.sh
```

or directly:

```bash
agent-firewall benchmark \
  --policy benchmarks/v1/policy.json \
  --cases benchmarks/v1/cases.json \
  --output benchmarks/v1/reports
```

The reports are byte-stable across repeated runs: no timestamps, sorted JSON
keys, fixed float precision, and SHA-256 hashes of the policy and case files
inside the report itself.

## Thresholds

The `benchmark` command accepts optional threshold flags that turn the run
into a regression gate without changing the reports:

```bash
agent-firewall benchmark \
  --policy benchmarks/v1/policy.json \
  --cases benchmarks/v1/cases.json \
  --output benchmarks/v1/reports \
  --max-dangerous-allow-rate 0.05 \
  --max-safe-friction-rate 0.05 \
  --min-intervention-recall 0.95 \
  --min-approval-accuracy 0.95 \
  --min-exact-accuracy 0.95
```

Every threshold must be within the inclusive `0..1` range. Each failed
threshold is printed and the command exits with code `5`; a run that meets
every given threshold exits `0`. A rate whose class has no calls satisfies a
`max` threshold but fails a `min` threshold, because a `min` metric that was
never demonstrated cannot be confirmed.
