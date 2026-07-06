# Cline unsafe overwrite

**Source:** [discussion#1831](https://github.com/cline/cline/discussions/1831)

The discussion reports auto-approved file writes overwriting existing content
without enough safeguards.

```json
{"tool": "filesystem.write", "decision": "require_approval"}
```

Writes require an explicit decision before they reach the filesystem server.
