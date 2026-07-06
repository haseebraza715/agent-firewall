# Show HN draft

## Title

Show HN: Agent Firewall – deterministic runtime policy for MCP tool calls

## Body

Agent Firewall is a small, framework-neutral Python policy engine that runs
before an agent tool executes. It can allow, block, or hold a call for human
approval, with call, cost, per-tool, and identical-call budgets.

The MCP stdio proxy can wrap an existing local server without changing agent
code. This [recorded demo](https://github.com/haseebraza715/agent-firewall/blob/main/docs/media/agent-firewall-demo.gif)
wraps the reference filesystem MCP server and shows an allowed read, a blocked
repeat, and a delete held for approval. The
[script and tape](https://github.com/haseebraza715/agent-firewall/tree/main/examples/demo)
are in the repository.

The project also includes an
[incident corpus](https://github.com/haseebraza715/agent-firewall/tree/main/docs/incidents)
of 11 sourced agent failures. Each report is paired with the smallest
deterministic policy used in the replay suite.

Repository: https://github.com/haseebraza715/agent-firewall
