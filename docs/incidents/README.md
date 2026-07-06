# Agent Incident Wall

Each entry links a public report to the smallest deterministic policy that
would have stopped or paused the risky action.

| Incident | Runtime control |
|---|---|
| [LangGraph query loop](langgraph-6731.md) | identical-call cap |
| [LangChain repeated quotation](langchain-16712.md) | approval rule |
| [LangGraph missing approval](langgraph-6053.md) | approval rule |
| [LangGraph tool-result loop](langgraph-1097.md) | identical-call cap |
| [OpenCode repeated actions](opencode-3444.md) | identical-call cap |
| [Hermes retry loop](hermes-7069.md) | identical-call cap |
| [VS Code delegation loop](vscode-275957.md) | identical-call cap |
| [MCP browser SSRF](mcp-3662.md) | fail-closed navigation policy |
| [Cline destructive restore](cline-1213.md) | deletion approval |
| [Cline unsafe overwrite](cline-1831.md) | write approval |
