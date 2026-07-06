# OpenCode repeated actions

**Source:** [opencode#3444](https://github.com/sst/opencode/issues/3444)

A coding-agent model repeated the same actions without progressing.

```json
{"budget": {"max_identical_calls": 2}}
```

The cap stops a third identical action while allowing changed arguments.
