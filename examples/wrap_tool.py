from pathlib import Path

from agent_firewall import Firewall


def approve(call, decision):
    answer = input("{}: {}. Approve? [y/N] ".format(call.name, decision.reason))
    return answer.strip().lower() == "y"


def send_email(to, subject):
    print("sent {!r} to {}".format(subject, to))


firewall = Firewall.from_policy_file(
    Path(__file__).with_name("policy.json"),
    approver=approve,
    audit_path=Path("firewall-audit.jsonl"),
)
safe_send_email = firewall.wrap("email.send", send_email)

safe_send_email("customer@example.com", "Agent Firewall test")
