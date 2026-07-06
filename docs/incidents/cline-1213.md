# Cline destructive restore

**Source:** [cline#1213](https://github.com/cline/cline/issues/1213)

A snapshot restore reportedly deleted files across multiple workspace
projects.

```json
{"tool": "filesystem.delete", "decision": "require_approval"}
```

Deletion pauses before execution and leaves an audit event.
