"""doctor: environment and configuration checks.

``run_checks`` probes the pieces the firewall depends on without leaving any
writes behind: the policy is loaded, existing state and audit parent
directories are checked with a temporary probe file that is removed again, the
optional MCP child command is resolved on PATH, and a probe call to a tool
name no policy rule can match verifies the runtime would fail closed.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ._version import __version__
from .models import DecisionKind, ToolCall, Usage
from .policy import Policy

UNKNOWN_TOOL_PROBE = "agent_firewall.doctor.unknown_tool_probe"


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    ok: bool
    message: str

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "message": self.message}


def run_checks(
    policy_path: Path,
    state_path: Path | None = None,
    audit_path: Path | None = None,
    mcp_command: Sequence[str] | None = None,
) -> list[DoctorCheck]:
    checks: list[DoctorCheck] = [DoctorCheck("version", True, __version__)]

    try:
        policy = Policy.load(policy_path)
    except Exception as exc:
        checks.append(DoctorCheck("policy", False, f"could not load policy: {exc}"))
        checks.append(
            DoctorCheck(
                "fail_closed_unknown_tool",
                False,
                "cannot evaluate without a loadable policy",
            )
        )
        return checks

    checks.append(DoctorCheck("policy", True, f"loaded {policy_path}"))

    for name, path in (("state", state_path), ("audit", audit_path)):
        checks.append(
            _check_parent_writable(name, path)
            if path is not None
            else DoctorCheck(name, True, "not configured")
        )

    checks.append(
        _check_mcp(mcp_command)
        if mcp_command
        else DoctorCheck("mcp", True, "not configured")
    )

    decision = policy.evaluate(ToolCall.create(UNKNOWN_TOOL_PROBE), Usage())
    fail_closed = decision.kind is DecisionKind.BLOCK
    if fail_closed:
        message = f"unknown tool {UNKNOWN_TOOL_PROBE!r} is blocked"
    else:
        message = (
            f"unknown tool {UNKNOWN_TOOL_PROBE!r} resolves to "
            f"{decision.kind.value}; the policy does not fail closed for "
            "unknown tools"
        )
    checks.append(DoctorCheck("fail_closed_unknown_tool", fail_closed, message))
    return checks


def _check_parent_writable(name: str, path: Path) -> DoctorCheck:
    parent = path.parent
    if not parent.exists():
        return DoctorCheck(name, False, f"parent {parent} does not exist")
    if not parent.is_dir():
        return DoctorCheck(name, False, f"parent {parent} is not a directory")
    probe: str | None = None
    try:
        fd, probe = tempfile.mkstemp(prefix=".agent-firewall-doctor-", dir=str(parent))
        os.close(fd)
    except OSError as exc:
        return DoctorCheck(name, False, f"parent {parent} is not writable: {exc}")
    finally:
        if probe is not None:
            try:
                os.unlink(probe)
            except FileNotFoundError:
                pass
    return DoctorCheck(name, True, f"parent {parent} is writable")


def _check_mcp(command: Sequence[str]) -> DoctorCheck:
    executable = command[0]
    if "/" in executable or os.sep in executable:
        if os.path.isfile(executable) and os.access(executable, os.X_OK):
            return DoctorCheck("mcp", True, f"{executable} is executable")
        return DoctorCheck("mcp", False, f"{executable} is not an executable file")
    found = shutil.which(executable)
    if found is None:
        return DoctorCheck("mcp", False, f"executable {executable!r} not found on PATH")
    return DoctorCheck("mcp", True, f"{executable} resolves to {found}")


def render_text(checks: list[DoctorCheck]) -> str:
    lines = ["agent-firewall doctor"]
    for check in checks:
        status = "ok" if check.ok else "FAIL"
        lines.append(f"{check.name}: {status}")
        lines.append(f"  {check.message}")
    failed = sum(not check.ok for check in checks)
    if failed:
        lines.append(f"doctor: {failed} of {len(checks)} check(s) failed")
    else:
        lines.append(f"doctor: all {len(checks)} check(s) passed")
    return "\n".join(lines)


def to_dict(checks: list[DoctorCheck]) -> dict[str, Any]:
    failed = sum(not check.ok for check in checks)
    return {
        "version": __version__,
        "checks": [check.as_dict() for check in checks],
        "all_ok": failed == 0,
        "failed_checks": failed,
    }
