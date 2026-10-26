from __future__ import annotations

import os
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

    SCHEMA_VERSION = 4

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
            descriptor = os.open(self.sqlite_path, os.O_CREAT | os.O_RDWR, 0o600)
            os.close(descriptor)
            os.chmod(self.sqlite_path, 0o600)
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
                if version < 2:
                    self._migrate_observations(connection)
                if version < 3:
                    for table in ("sessions", "oidc_transactions"):
                        connection.execute(
                            f"CREATE TABLE {table} (token_hash TEXT PRIMARY KEY, "
                            "payload TEXT NOT NULL, expires_at REAL NOT NULL)"
                        )
                        connection.execute(f"CREATE INDEX {table}_expiry ON {table}(expires_at)")
                if version < 4:
                    connection.execute(
                        "CREATE TABLE discovery_coverage (job_id TEXT PRIMARY KEY, payload TEXT NOT NULL)"
                    )
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

    @staticmethod
    def _migrate_observations(connection: sqlite3.Connection) -> None:
        """Replace phase-1 cached verdicts with latest raw evidence per address."""
        rows = connection.execute(
            "SELECT key, payload FROM observations WHERE key LIKE 'status:%' OR key LIKE 'observation:%'"
        ).fetchall()
        latest: dict[str, dict[str, Any]] = {}
        for key, encoded in rows:
            payload = json.loads(encoded)
            ip = payload.get("ip") or key.split(":")[1]
            raw = {
                "ip": ip,
                "checked_at": payload.get("checked_at"),
                "ping_ok": payload.get("ping_ok", payload.get("responding")),
                "ping_error": payload.get("ping_error", payload.get("error")),
                "latency_ms": payload.get("latency_ms"),
                "mac_found": payload.get("mac_found"),
                "mac_error": payload.get("mac_error"),
                "dns": payload.get("dns", {}),
                "source_revision": payload.get("source_revision"),
            }
            for metadata in ("expectation_fingerprint", "job_id"):
                if metadata in payload:
                    raw[metadata] = payload[metadata]
            if ip not in latest or (raw["checked_at"] or "") > (latest[ip]["checked_at"] or ""):
                latest[ip] = raw
            connection.execute("DELETE FROM observations WHERE key = ?", (key,))
        for ip, raw in latest.items():
            connection.execute(
                "INSERT INTO observations (key, payload, source_revision) VALUES (?, ?, ?)",
                (f"observation:{ip}", json.dumps(raw), raw["source_revision"]),
            )

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def get(self, key: str) -> dict[str, Any] | None:
        row = self._db.execute("SELECT payload FROM observations WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row is not None else None

    def observation_ips(self):
        """Stream sparse observation addresses without materializing payloads."""
        for row in self._db.execute("SELECT key FROM observations WHERE key LIKE 'observation:%'"):
            yield row[0].removeprefix("observation:")

    def set(self, key: str, value: dict[str, Any]) -> None:
        with self._db:
            self._db.execute(
                "INSERT INTO observations (key, payload, source_revision) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET payload = excluded.payload, source_revision = excluded.source_revision",
                (key, json.dumps(value), value.get("source_revision")),
            )

    def delete(self, key: str) -> None:
        with self._db:
            self._db.execute("DELETE FROM observations WHERE key = ?", (key,))

    def save_discovery_coverage(self, payload: dict[str, Any]) -> None:
        """Keep latest completed coverage, splitting older overlapping intervals.

        Storage grows with distinct coverage boundaries, not silent addresses.
        """
        intervals = [tuple(pair) for pair in payload["intervals"]]
        with self._db:
            for old in self.list_discovery_coverage():
                remaining = [tuple(pair) for pair in old["intervals"]]
                for start, end in intervals:
                    trimmed = []
                    for left, right in remaining:
                        if right < start or left > end:
                            trimmed.append((left, right))
                        else:
                            if left < start:
                                trimmed.append((left, start - 1))
                            if right > end:
                                trimmed.append((end + 1, right))
                    remaining = trimmed
                if not remaining:
                    self._db.execute("DELETE FROM discovery_coverage WHERE job_id = ?", (old["job_id"],))
                elif remaining != [tuple(pair) for pair in old["intervals"]]:
                    old["intervals"] = remaining
                    self._db.execute(
                        "UPDATE discovery_coverage SET payload = ? WHERE job_id = ?",
                        (json.dumps(old), old["job_id"]),
                    )
            if intervals:
                self._db.execute(
                    "INSERT INTO discovery_coverage VALUES (?, ?) "
                    "ON CONFLICT(job_id) DO UPDATE SET payload = excluded.payload",
                    (payload["job_id"], json.dumps(payload)),
                )

    def list_discovery_coverage(self) -> list[dict[str, Any]]:
        rows = self._db.execute("SELECT payload FROM discovery_coverage ORDER BY rowid").fetchall()
        return [json.loads(row[0]) for row in rows]

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        row = self._db.execute("SELECT payload FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return json.loads(row[0]) if row is not None else None

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

    def get_schedule(self, schedule_id: str) -> dict[str, Any] | None:
        row = self._db.execute("SELECT payload FROM schedules WHERE id = ?", (schedule_id,)).fetchone()
        return json.loads(row[0]) if row is not None else None

    def delete_schedule(self, schedule_id: str) -> None:
        with self._db:
            self._db.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))

    def save_session(self, token_hash: str, payload: dict[str, Any], expires_at: float) -> None:
        with self._db:
            self._db.execute(
                "INSERT INTO sessions VALUES (?, ?, ?) ON CONFLICT(token_hash) DO UPDATE SET "
                "payload = excluded.payload, expires_at = excluded.expires_at",
                (token_hash, json.dumps(payload), expires_at),
            )

    def get_session(self, token_hash: str, now: float) -> dict[str, Any] | None:
        with self._db:
            row = self._db.execute(
                "SELECT payload, expires_at FROM sessions WHERE token_hash = ?", (token_hash,)
            ).fetchone()
            if row is None:
                return None
            if row[1] <= now:
                self._db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
                return None
            try:
                payload = json.loads(row[0])
            except (ValueError, TypeError):
                return None
            return payload if isinstance(payload, dict) else None

    def delete_session(self, token_hash: str) -> None:
        with self._db:
            self._db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))

    def save_oidc_transaction(self, state_hash: str, payload: dict[str, Any], expires_at: float) -> None:
        with self._db:
            self._db.execute(
                "INSERT INTO oidc_transactions VALUES (?, ?, ?) "
                "ON CONFLICT(token_hash) DO UPDATE SET payload = excluded.payload, expires_at = excluded.expires_at",
                (state_hash, json.dumps(payload), expires_at),
            )

    def consume_oidc_transaction(self, state_hash: str, now: float) -> dict[str, Any] | None:
        with self._db:
            row = self._db.execute(
                "DELETE FROM oidc_transactions WHERE token_hash = ? RETURNING payload, expires_at",
                (state_hash,),
            ).fetchone()
            if row is None or row[1] <= now:
                return None
            try:
                payload = json.loads(row[0])
            except (ValueError, TypeError):
                return None
            return payload if isinstance(payload, dict) else None

    def purge_expired_security_state(self, now: float) -> None:
        with self._db:
            self._db.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
            self._db.execute("DELETE FROM oidc_transactions WHERE expires_at <= ?", (now,))
