# LangGraph tool-result loop

**Source:** [discussion#1097](https://github.com/langchain-ai/langgraph/discussions/1097)

An agent selected the right tool but failed to treat its result as final and
kept calling it.

```json
{"budget": {"max_identical_calls": 2}}
```

Canonical argument fingerprints stop the repeated call.
