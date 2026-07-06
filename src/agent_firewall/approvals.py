from __future__ import annotations

import asyncio
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Decision, ToolCall


class ApprovalNotFound(KeyError):
    pass


class ApprovalConflict(RuntimeError):
    pass


@dataclass(frozen=True)
class ApprovalRecord:
    call_id: str
    tool: str
    reason: str
    requested_at: str
    status: str
    decided_at: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "call_id": self.call_id,
            "tool": self.tool,
            "reason": self.reason,
            "requested_at": self.requested_at,
            "status": self.status,
            "decided_at": self.decided_at,
        }


class SQLiteApprovalQueue:
    def __init__(
        self,
        path: Path,
        timeout_seconds: float = 300,
        poll_seconds: float = 0.25,
    ) -> None:
        if timeout_seconds <= 0 or poll_seconds <= 0:
            raise ValueError("approval timeout and poll interval must be positive")
        self.path = path
        self.timeout_seconds = timeout_seconds
        self.poll_seconds = poll_seconds
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    async def __call__(self, call: ToolCall, decision: Decision) -> bool:
        return await asyncio.to_thread(self.wait, call, decision)

    def wait(self, call: ToolCall, decision: Decision) -> bool:
        self.request(call, decision)
        deadline = time.monotonic() + self.timeout_seconds
        while time.monotonic() < deadline:
            record = self.get(call.id)
            if record.status != "pending":
                return record.status == "approved"
            time.sleep(self.poll_seconds)

        try:
            self.decide(call.id, "denied")
        except ApprovalConflict:
            pass
        return self.get(call.id).status == "approved"

    def request(self, call: ToolCall, decision: Decision) -> ApprovalRecord:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO approvals
                    (call_id, tool, reason, requested_at, status, decided_at)
                VALUES (?, ?, ?, ?, 'pending', NULL)
                """,
                (call.id, call.name, decision.reason, _now()),
            )
        return self.get(call.id)

    def pending(self) -> list[ApprovalRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT call_id, tool, reason, requested_at, status, decided_at
                FROM approvals
                WHERE status = 'pending'
                ORDER BY requested_at
                """
            ).fetchall()
        return [ApprovalRecord(*row) for row in rows]

    def get(self, call_id: str) -> ApprovalRecord:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT call_id, tool, reason, requested_at, status, decided_at
                FROM approvals
                WHERE call_id = ?
                """,
                (call_id,),
            ).fetchone()
        if row is None:
            raise ApprovalNotFound(call_id)
        return ApprovalRecord(*row)

    def decide(self, call_id: str, status: str) -> ApprovalRecord:
        if status not in {"approved", "denied"}:
            raise ValueError("approval decision must be approved or denied")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT status FROM approvals WHERE call_id = ?",
                (call_id,),
            ).fetchone()
            if row is None:
                raise ApprovalNotFound(call_id)
            current = row[0]
            if current == status:
                connection.commit()
                return self.get(call_id)
            if current != "pending":
                raise ApprovalConflict(f"approval was already decided as {current}")
            connection.execute(
                """
                UPDATE approvals
                SET status = ?, decided_at = ?
                WHERE call_id = ? AND status = 'pending'
                """,
                (status, _now(), call_id),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return self.get(call_id)

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS approvals (
                    call_id TEXT PRIMARY KEY,
                    tool TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    requested_at TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (
                        status IN ('pending', 'approved', 'denied')
                    ),
                    decided_at TEXT
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=10)
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
