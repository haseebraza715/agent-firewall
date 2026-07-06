# r/LangChain draft

## Title

I built a deterministic runtime guard for the agent failure modes in 4 LangGraph/LangChain reports

## Body

I collected public LangGraph/LangChain reports where an agent repeated a tool,
retriggered a side effect, or missed a human-approval boundary:

- [database-query loop in LangGraph #6731](https://github.com/langchain-ai/langgraph/issues/6731)
- [repeated quotation tool in LangChain #16712](https://github.com/langchain-ai/langchain/issues/16712)
- [missing human approval in LangGraph #6053](https://github.com/langchain-ai/langgraph/issues/6053)
- [repeated human-input invocation in LangGraph #4172](https://github.com/langchain-ai/langgraph/issues/4172)

Agent Firewall handles these outside the framework with ordered allow, block,
and approval rules plus per-tool and identical-call budgets. The repository’s
replay command runs the sourced scenarios against one policy file.

The [MCP demo](https://github.com/haseebraza715/agent-firewall/blob/main/docs/media/agent-firewall-demo.gif)
shows the same enforcement point wrapping the reference filesystem server:
one read is allowed, the repeat is blocked, and delete requires approval.

The full [incident corpus](https://github.com/haseebraza715/agent-firewall/tree/main/docs/incidents)
and implementation are here:
https://github.com/haseebraza715/agent-firewall

I’m especially interested in cases where a framework-level interrupt was not
enough and an independent runtime policy helped.
