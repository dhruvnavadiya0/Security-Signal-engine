"""Local, provider-neutral specialist-agent coordination and persistence."""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class Agent:
    id: str
    name: str
    task: str
    parent_id: str | None = None
    status: str = "created"
    error: str | None = None
    recovery_count: int = 0


class AgentCoordinator:
    """Persist a small agent graph in SQLite for local Ollama workflows."""

    def __init__(self, database_path: str = ".sse/agents.db") -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS agents (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, task TEXT NOT NULL,
                    parent_id TEXT, status TEXT NOT NULL, error TEXT,
                    recovery_count INTEGER NOT NULL, metadata TEXT NOT NULL,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                )
            """)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def register(self, name: str, task: str, parent_id: str | None = None) -> Agent:
        """Register a specialist and return its stable identity."""
        now = datetime.now(timezone.utc).isoformat()
        agent = Agent(id=str(uuid.uuid4()), name=name, task=task, parent_id=parent_id)
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO agents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (agent.id, agent.name, agent.task, agent.parent_id, agent.status,
                 agent.error, agent.recovery_count, "{}", now, now),
            )
        return agent

    def update_status(self, agent_id: str, status: str, error: str | None = None) -> None:
        """Update lifecycle state without losing the prior graph node."""
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            connection.execute(
                "UPDATE agents SET status=?, error=?, updated_at=? WHERE id=?",
                (status, error, now, agent_id),
            )

    def graph(self) -> list[dict]:
        """Return all agents in creation order for duplicate checks and UI views."""
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM agents ORDER BY created_at").fetchall()
        return [dict(row) for row in rows]

    def snapshot(self) -> str:
        """Serialize the graph for run artifacts."""
        return json.dumps(self.graph(), indent=2)
