# Argument matchers

A policy rule's `arguments` object maps argument names to patterns. A pattern
is either a **scalar** — the original behaviour: string patterns are globs and
everything else is exact equality — or a **typed matcher**: a JSON object with
an `operator` key that selects a validated matcher type.

Typed matchers let rules match on structure (a URL's host, a path, an email
domain, an HTTP method, a numeric range, a SQL operation, a command's argv)
instead of raw string globs. They are validated when the policy loads: an
unknown operator, an unknown key, or an invalid field value is a hard policy
error, so a typo cannot silently widen a rule.

```json
{
  "tool": "url.fetch",
  "decision": "allow",
  "arguments": {
    "url": {
      "operator": "url",
      "scheme": "https",
      "hostname": "*.example.com",
      "deny_private_networks": true
    }
  }
}
```

## `url`

Matches a URL string. Constraints are combined with AND.

| field | value | meaning |
|---|---|---|
| `scheme` | `str` or `[str]` | equality / membership (case-insensitive) |
| `hostname` | `str` or `[str]` | glob equality / membership (case-insensitive) |
| `port` | `int` or `[int]` | literal port equality / membership |
| `path` | `{"equals" \| "prefix" \| "suffix": str}` | path comparison |
| `deny_private_networks` | `bool` | only public literal IPs match |

At least one field is required. The hostname is the URL's host without any
`user:pass@` prefix, so `https://attacker@example.com/` has hostname
`example.com` and `https://example.com@attacker.com/` has hostname
`attacker.com`; a trailing dot (`example.com.`) is a different hostname. A URL
with no network location (for example `https:example.com`) has no hostname and
never matches a hostname constraint. `port` matches the literal port written
in the URL; implied defaults are not applied.

`deny_private_networks` classifies the hostname **only when it is a literal
IPv4 or IPv6 address**. Loopback, link-local, private, reserved, and other
non-globally-routable literal addresses do not match. Legacy encodings that
common resolvers still accept are classified as well — `127.1`,
`2130706433`, `0x7f000001`, and leading zeros all resolve to loopback, and
an IPv6 zone id (`[fe80::1%25eth0]`) does not hide a link-local address. DNS
resolution and HTTP redirects are deliberately not inspected, and a non-IP
hostname is never denied by this field.

## `path`

Matches a filesystem path string. `within` requires the value to be the target
directory or a descendant; `equals` requires the normalized path to be equal.
Both normalize the value and the pattern to an absolute POSIX path lexically —
`.` and `..` components are resolved — with no filesystem access and no
symlink resolution, and never expand `~`.

| field | value | meaning |
|---|---|---|
| `within` | `str` | the value must be inside this directory |
| `equals` | `str` | the value must equal this path |

At least one field is required. `within` is boundary-aware: `/etc` contains
`/etc/passwd` but not `/etc2/passwd`.

## `domain`

Matches an email address's domain (the part after the last `@`).
`equals` matches exactly; `suffix` matches the domain itself or any of its
subdomains. Both are case-insensitive and boundary-aware: `evil-example.com`
is not a subdomain of `example.com`. A value without `@` never matches.

| field | value | meaning |
|---|---|---|
| `equals` | `str` | exact domain match |
| `suffix` | `str` | the domain or a subdomain |

At least one field is required.

## `http_method`

Matches an HTTP method string, case-insensitively. Exactly one of `equals` or
`in` is required.

| field | value | meaning |
|---|---|---|
| `equals` | `str` | the method must equal this |
| `in` | `[str]` | the method must be in this list |

## `number`

Matches a numeric argument against inclusive bounds. Values and bounds may be
JSON numbers or numeric strings; comparison uses exact decimal values.

| field | value | meaning |
|---|---|---|
| `min` | number | the value must be >= min |
| `max` | number | the value must be <= max |

At least one field is required.

## `sql`

Matches the leading SQL operation of a statement string, ignoring whitespace
and `--`, `#`, and `/* ... */` comments. Comparisons are case-insensitive.
Exactly one of `equals` or `in` is required.

| field | value | meaning |
|---|---|---|
| `equals` | `str` | the leading operation must equal this |
| `in` | `[str]` | the leading operation must be in this list |

Only the first keyword is examined; the matcher does not parse the rest of the
statement.

## `command`

Matches a command value that is either a string (split lexically with
`shlex`) or an argv list. `executable` is a glob matched against `argv[0]` or
its basename; `argv_prefix` is a list of globs the full argv (including the
executable element) must start with. Constraints are combined with AND; at
least one is required.

| field | value | meaning |
|---|---|---|
| `executable` | `str` | glob for the command name |
| `argv_prefix` | `[str]` | leading argv elements (globs) |

```json
{
  "tool": "shell.run",
  "decision": "allow",
  "arguments": {
    "command": {
      "operator": "command",
      "executable": "git",
      "argv_prefix": ["git", "commit"]
    }
  }
}
```

Values that cannot be modeled as one argv vector never match: strings
containing line breaks, and — in either form — tokens that are entirely shell
operators (`;`, `|`, `&`, `<`, `>`, parentheses, backticks), contain command
substitution (`$(...)`, `` `...` ``, `${...}`), or contain line breaks.
Bare operators inside a longer argv-list element (for example
`["sh", "-c", "ls; ls"]` or `["sed", "s/a;b/c/"]`) are treated as inert data,
matching how an execv-style consumer sees them; if the guarded tool joins its
argv back into a shell string, prefer a string-form rule or constrain on
`executable` alone instead.

## Security notes

Matchers are an enforcement aid, not a sandbox. In particular the `url`
matcher never performs DNS lookups or follows redirects, and the `path`
matcher is purely lexical — it does not resolve symlinks or check the
filesystem. Rules built on these matchers sit inside the same enforcement
boundary as every other rule; see `docs/THREAT_MODEL.md` for what the firewall
does and does not guarantee.
