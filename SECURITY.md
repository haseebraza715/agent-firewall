# Security policy

Please report suspected vulnerabilities privately through GitHub Security
Advisories for this repository. Do not include secrets, credentials, or
personal data in a public issue.

Agent Firewall is an enforcement point, not a process sandbox. Use
least-privilege tool credentials and operating-system isolation as separate
layers.

## Dashboard threat model

The dashboard binds to loopback only. Processes running as the same operating
system user are trusted: they can read the state file directly, so the HTTP
surface does not defend against them. The HTTP-level defenses target browsers:
every request must carry a loopback `Host` header (blocks DNS rebinding), and
mutating requests require the per-process token (cross-site request forgery
protection) plus a loopback `Origin` when a browser supplies one. If untrusted
same-user processes are a concern, run the agent under a separate OS account.

The latest release is the only supported version during the alpha period.
