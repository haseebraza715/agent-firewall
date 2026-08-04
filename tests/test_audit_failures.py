import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_firewall import AuditWriteError, JsonlAuditLog, ToolCall, Usage


class AuditFailureTests(unittest.TestCase):
    def test_audit_write_failure_is_explicit_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            log = JsonlAuditLog(Path(directory) / "audit.jsonl")
            call = ToolCall.create("email.send", {"secret": "hidden"})
            with patch.object(Path, "open", side_effect=PermissionError("denied")):
                with self.assertRaisesRegex(AuditWriteError, "could not append"):
                    log.record("decision", call, Usage())


if __name__ == "__main__":
    unittest.main()
