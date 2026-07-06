# Hermes backend retry loop

**Source:** [hermes-agent#7069](https://github.com/NousResearch/hermes-agent/issues/7069)

A stale timeout caused the same expensive backend request to retry
indefinitely.

```json
{"budget": {"max_identical_calls": 2, "max_cost_usd": "0.50"}}
```

Wrapping the backend call gives retries both repetition and spend limits.
