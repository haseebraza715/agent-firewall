# LangGraph approval UI gap

**Source:** [langgraph#6053](https://github.com/langchain-ai/langgraph/issues/6053)

A human-in-the-loop integration behaved like an ordinary tool call instead of
surfacing approval.

```json
{"tool": "email.*", "decision": "require_approval"}
```

The runtime gate is independent of graph or UI pause behavior.
