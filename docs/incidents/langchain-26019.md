# LangChain tool-result loop

**Source:** [langchain#26019](https://github.com/langchain-ai/langchain/issues/26019)

A LangGraph customer-support agent repeatedly called the same tool without
processing its output or answering the user.

```json
{"budget": {"max_identical_calls": 2}}
```

Canonical argument fingerprints stop the repeated call.
