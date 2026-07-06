from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from threading import Lock
from typing import Protocol

from .models import Decision, DecisionKind, ToolCall, Usage
from .policy import Policy


@dataclass(frozen=True)
class StateResult:
    decision: Decision
    usage: Usage


class StateStore(Protocol):
    def usage(self) -> Usage: ...

    def evaluate_and_reserve(
        self,
        policy: Policy,
        call: ToolCall,
        approved: bool = False,
    ) -> StateResult: ...


class MemoryStateStore:
    def __init__(self) -> None:
        self._usage = Usage()
        self._lock = Lock()

    def usage(self) -> Usage:
        with self._lock:
            return self._usage.copy()

    def evaluate_and_reserve(
        self,
        policy: Policy,
        call: ToolCall,
        approved: bool = False,
    ) -> StateResult:
        with self._lock:
            decision = policy.evaluate(call, self._usage)
            if decision.kind is DecisionKind.ALLOW or (
                approved and decision.kind is not DecisionKind.BLOCK
            ):
                self._usage.record(call)
            return StateResult(decision, self._usage.copy())


class SQLiteStateStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def usage(self) -> Usage:
        with self._connect() as connection:
            return self._load_usage(connection)

    def evaluate_and_reserve(
        self,
        policy: Policy,
        call: ToolCall,
        approved: bool = False,
    ) -> StateResult:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            usage = self._load_usage(connection)
            decision = policy.evaluate(call, usage)
            if decision.kind is DecisionKind.ALLOW or (
                approved and decision.kind is not DecisionKind.BLOCK
            ):
                self._record(connection, usage, call)
            connection.commit()
            return StateResult(decision, usage)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS run_usage (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    tool_calls INTEGER NOT NULL,
                    estimated_cost_usd TEXT NOT NULL
                );
                INSERT OR IGNORE INTO run_usage
                    (id, tool_calls, estimated_cost_usd)
                    VALUES (1, 0, '0');

                CREATE TABLE IF NOT EXISTS tool_usage (
                    tool TEXT PRIMARY KEY,
                    call_count INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS fingerprint_usage (
                    fingerprint TEXT PRIMARY KEY,
                    call_count INTEGER NOT NULL
                );
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=10)
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    @staticmethod
    def _load_usage(connection: sqlite3.Connection) -> Usage:
        row = connection.execute(
            "SELECT tool_calls, estimated_cost_usd FROM run_usage WHERE id = 1"
        ).fetchone()
        tools: dict[str, int] = dict(
            connection.execute("SELECT tool, call_count FROM tool_usage")
        )
        fingerprints: dict[str, int] = dict(
            connection.execute("SELECT fingerprint, call_count FROM fingerprint_usage")
        )
        return Usage(
            tool_calls=int(row[0]),
            estimated_cost_usd=Decimal(row[1]),
            calls_by_tool=tools,
            calls_by_fingerprint=fingerprints,
        )

    @staticmethod
    def _record(
        connection: sqlite3.Connection,
        usage: Usage,
        call: ToolCall,
    ) -> None:
        usage.record(call)
        connection.execute(
            """
            UPDATE run_usage
            SET tool_calls = ?, estimated_cost_usd = ?
            WHERE id = 1
            """,
            (usage.tool_calls, str(usage.estimated_cost_usd)),
        )
        connection.execute(
            """
            INSERT INTO tool_usage (tool, call_count) VALUES (?, 1)
            ON CONFLICT(tool) DO UPDATE SET call_count = call_count + 1
            """,
            (call.name,),
        )
        connection.execute(
            """
            INSERT INTO fingerprint_usage (fingerprint, call_count) VALUES (?, 1)
            ON CONFLICT(fingerprint) DO UPDATE SET call_count = call_count + 1
            """,
            (call.fingerprint,),
        )
