"""Guard a real Python function with Agent Firewall.

The policy in this directory requires approval for every email send and uses
a local print stub as the email tool. A denial is a normal outcome, not a
crash, so `ToolCallBlocked` is caught and reported.
"""

from pathlib import Path

from agent_firewall import Firewall
from agent_firewall.exceptions import ToolCallBlocked


def approve(call, decision):
    answer = input(f"{call.name}: {decision.reason}. Approve? [y/N] ")
    return answer.strip().lower() == "y"


def send_email(to, subject):
    print(f"  SENT {subject!r} to {to}")


firewall = Firewall.from_policy_file(
    Path(__file__).with_name("policy.json"),
    approver=approve,
    audit_path=Path("firewall-audit.jsonl"),
)
safe_send_email = firewall.wrap("email.send", send_email)

for recipient in ("teammate@mycompany.com", "customer@example.com"):
    print(f"agent wants to email {recipient}")
    try:
        safe_send_email(recipient, "Agent Firewall test")
    except ToolCallBlocked as blocked:
        print(f"  NOT SENT - {blocked.decision.reason}")
