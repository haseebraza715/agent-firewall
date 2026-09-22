# Contributing

Thanks for helping make Agent Firewall more useful and harder to misuse.

## Development Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install ".[dev]"
```

Use `PYTHONPATH=src` when running from a checkout without reinstalling:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

## Test Commands

Run the local gate before opening a PR:

```bash
PYTHONPATH=src coverage run -m unittest discover -s tests -v
coverage report
PYTHONPATH=src agent-firewall replay --policy examples/policy.json --scenarios examples/complaints.json
ruff format --check src tests examples
ruff check src tests examples
mypy src
python -m build
twine check dist/*
```

Real MCP server compatibility tests are opt-in because they use `npx` and may
perform network calls:

```bash
AGENT_FIREWALL_INTEGRATION=1 \
  PYTHONPATH=src \
  python -m unittest discover -s tests/integration -v
```

## PR Expectations

- Keep changes focused and covered by regression tests.
- Do not commit secrets, personal audit logs, or real tool arguments.
- Prefer fail-closed behavior for policy parsing, MCP proxy errors, and approval flows.
- Keep the package publish path out of ordinary PRs; maintainers handle releases.
- Include docs updates when behavior, configuration, or user-facing commands change.
- Mention any compatibility server you tested and add notes to `docs/compatibility.md`.
