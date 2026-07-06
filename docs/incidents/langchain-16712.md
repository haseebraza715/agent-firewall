# LangChain repeated quotation action

**Source:** [langchain#16712](https://github.com/langchain-ai/langchain/issues/16712)

An agent retriggered a quotation tool with external customer and email side
effects.

```json
{"tool": "quotation.create", "decision": "require_approval"}
```

The action pauses before its first execution.
