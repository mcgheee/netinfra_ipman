from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .models import utc_now_iso


class RuntimeStore:
    """Durable runtime state, separate from the authoritative NetInfra file.

    Construction performs no I/O. Call initialize before use and close only
    after all consumers (including the scan runner) have stopped.
    """

    SCHEMA_VERSION = 1

    def __init__(self, sqlite_path: str | Path):
        self.sqlite_path = str(sqlite_path)
        self._connection: sqlite3.Connection | None = None

    @property
    def _db(self) -> sqlite3.Connection:
        if self._connection is None:
            raise RuntimeError("RuntimeStore is not initialized")
        return self._connection

    def initialize(self) -> None:
        if self._connection is not None:
            return
        if self.sqlite_path != ":memory:":
            Path(self.sqlite_path).parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.sqlite_path)
        try:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version > self.SCHEMA_VERSION:
                raise ValueError(f"Unsupported SQLite schema version {version}; supported version is {self.SCHEMA_VERSION}")
            with connection:
                connection.execute("BEGIN")
                if version == 0:
                    connection.execute(
                        "CREATE TABLE observations (key TEXT PRIMARY KEY, payload TEXT NOT NULL, source_revision TEXT)"
                    )
                    connection.execute(
                        "CREATE TABLE jobs (id TEXT PRIMARY KEY, status TEXT NOT NULL, "
                        "started_at TEXT NOT NULL, payload TEXT NOT NULL, source_revision TEXT)"
                    )
                    connection.execute("CREATE TABLE schedules (id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
                    connection.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION}")
                interrupted = connection.execute(
                    "SELECT id, payload FROM jobs WHERE status IN ('queued', 'running')"
                ).fetchall()
                for job_id, payload in interrupted:
                    job = json.loads(payload)
                    job.update(status="interrupted", incomplete=True, finished_at=utc_now_iso())
                    connection.execute(
                        "UPDATE jobs SET status = ?, payload = ? WHERE id = ?",
                        (job["status"], json.dumps(job), job_id),
                    )
        except BaseException:
            connection.close()
            raise
        self._connection = connection

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def get(self, key: str) -> dict[str, Any] | None:
        row = self._db.execute("SELECT payload FROM observations WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row is not None else None

    def set(self, key: str, value: dict[str, Any]) -> None:
        with self._db:
            self._db.execute(
                "INSERT INTO observations (key, payload, source_revision) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET payload = excluded.payload, source_revision = excluded.source_revision",
                (key, json.dumps(value), value.get("source_revision")),
            )

    def save_job(self, job: dict[str, Any]) -> None:
        with self._db:
            self._db.execute(
                "INSERT INTO jobs (id, status, started_at, payload, source_revision) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET status = excluded.status, started_at = excluded.started_at, "
                "payload = excluded.payload, source_revision = excluded.source_revision",
                (job["id"], job["status"], job["started_at"], json.dumps(job), job.get("source_revision")),
            )

    def list_jobs(self) -> list[dict[str, Any]]:
        rows = self._db.execute("SELECT payload FROM jobs ORDER BY started_at DESC, rowid DESC").fetchall()
        return [json.loads(row[0]) for row in rows]

    def prune_jobs(self, completed_job_retention: int) -> None:
        if completed_job_retention < 0:
            raise ValueError("completed_job_retention must not be negative")
        with self._db:
            self._db.execute(
                "DELETE FROM jobs WHERE id IN ("
                "SELECT id FROM jobs WHERE status NOT IN ('queued', 'running') "
                "ORDER BY started_at DESC, rowid DESC LIMIT -1 OFFSET ?)",
                (completed_job_retention,),
            )

    def save_schedule(self, schedule: dict[str, Any]) -> None:
        payload = {"enabled": False, **schedule}
        with self._db:
            self._db.execute(
                "INSERT INTO schedules (id, payload) VALUES (?, ?) "
                "ON CONFLICT(id) DO UPDATE SET payload = excluded.payload",
                (payload["id"], json.dumps(payload)),
            )

    def list_schedules(self) -> list[dict[str, Any]]:
        rows = self._db.execute("SELECT payload FROM schedules ORDER BY id").fetchall()
        return [json.loads(row[0]) for row in rows]
