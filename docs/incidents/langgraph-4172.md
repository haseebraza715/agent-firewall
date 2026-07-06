# LangGraph repeated human-input invocation

- Source: [langgraph issue #4172](https://github.com/langchain-ai/langgraph/issues/4172)
- Reported failure: a human-input node executes more times on each later
  invocation after validation loops.
- Guardrail: cap identical `human.input` calls at one per run.
- Expected result: the first request is allowed and the repeated request is
  blocked.

This scenario is encoded as `langgraph-4172-repeated-human-input` in
[`examples/complaints.json`](../../examples/complaints.json).
