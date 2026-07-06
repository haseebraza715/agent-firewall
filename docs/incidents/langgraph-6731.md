# LangGraph database-query loop

**Source:** [langgraph#6731](https://github.com/langchain-ai/langgraph/issues/6731)

A text-to-SQL agent repeatedly invoked the same database tool until its graph
recursion limit stopped the run.

```json
{"budget": {"max_identical_calls": 2}}
```

The third identical query is blocked before execution.
