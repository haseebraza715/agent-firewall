# X thread draft

1. A LangGraph agent repeated the same database query until its recursion
   limit. An identical-call cap can stop the second attempt before execution.
   Source: https://github.com/langchain-ai/langgraph/issues/6731

2. A LangChain agent retriggered a quotation tool with external effects. An
   approval rule can pause the call before the quotation is created.
   Source: https://github.com/langchain-ai/langchain/issues/16712

3. A LangGraph report described a human-in-the-loop approval step being
   bypassed. A fail-closed runtime rule can require approval independently of
   graph flow. Source: https://github.com/langchain-ai/langgraph/issues/6053

4. The reference MCP servers tracker documented browser navigation to cloud
   metadata endpoints. Argument-aware rules can block those destinations.
   Source: https://github.com/modelcontextprotocol/servers/issues/3662

5. A Cline restore operation deleted files across projects. A deletion rule
   can hold the filesystem call for explicit approval.
   Source: https://github.com/cline/cline/issues/1213

6. VS Code reported agent delegation stuck in an infinite loop. Per-tool and
   identical-call budgets provide a framework-independent stop.
   Source: https://github.com/microsoft/vscode/issues/275957

7. A LangGraph human-input node ran more times on later invocations after
   validation loops. The same deterministic repetition cap applies.
   Source: https://github.com/langchain-ai/langgraph/issues/4172
   Repo: https://github.com/haseebraza715/agent-firewall
