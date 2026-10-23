import sqlite3
import json

import pytest

from netinfra_ipman.persistence import RuntimeStore


def job(job_id, status="complete", started_at="2026-01-01T00:00:00+00:00"):
    return {"id": job_id, "status": status, "started_at": started_at, "progress": 2,
            "total": 5, "incomplete": False, "source_revision": "revision"}


def test_explicit_initialization_and_reopen_preserve_runtime_state(tmp_path):
    path = tmp_path / "runtime.sqlite3"
    store = RuntimeStore(path)
    assert not path.exists()
    with pytest.raises(RuntimeError, match="not initialized"):
        store.get("missing")
    store.initialize()
    store.set("observation:192.0.2.1", {"ping_ok": True, "source_revision": "rev"})
    store.save_schedule({"id": "daily", "scope": "192.0.2.0/24", "custom": {"hour": 12}})
    store.save_schedule({"id": "enabled", "enabled": True})
    store.save_job(job("completed"))
    store.close()
    reopened = RuntimeStore(path)
    reopened.initialize()
    assert reopened.get("observation:192.0.2.1")["source_revision"] == "rev"
    assert reopened.get("missing") is None
    assert reopened.list_schedules() == [
        {"enabled": False, "id": "daily", "scope": "192.0.2.0/24", "custom": {"hour": 12}},
        {"enabled": True, "id": "enabled"},
    ]
    assert reopened.list_jobs() == [job("completed")]
    reopened.close()


def test_recovery_marks_queued_and_running_incomplete(tmp_path):
    path = tmp_path / "runtime.sqlite3"
    store = RuntimeStore(path)
    store.initialize()
    for status in ("queued", "running", "complete", "cancelled", "failed"):
        store.save_job(job(status, status))
    store.close()
    store.initialize()
    summaries = {item["id"]: item for item in store.list_jobs()}
    for status in ("queued", "running"):
        recovered = summaries[status]
        assert recovered["status"] == "interrupted"
        assert recovered["incomplete"] is True
        assert recovered["finished_at"]
        assert recovered["progress"] == 2
        assert recovered["source_revision"] == "revision"
    for status in ("complete", "cancelled", "failed"):
        assert summaries[status] == job(status, status)
    store.close()


def test_schema_version_rejects_future_database_without_modification(tmp_path):
    path = tmp_path / "future.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version = 999")
    store = RuntimeStore(path)
    with pytest.raises(ValueError, match="Unsupported SQLite schema"):
        store.initialize()
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 999
        assert connection.execute("SELECT name FROM sqlite_master").fetchall() == []


def test_storage_failure_does_not_fall_back_to_memory(tmp_path):
    parent = tmp_path / "not-a-directory"
    parent.write_text("occupied")
    store = RuntimeStore(parent / "runtime.sqlite3")
    with pytest.raises((OSError, sqlite3.OperationalError)):
        store.initialize()
    with pytest.raises(RuntimeError, match="not initialized"):
        store.set("key", {})


def test_upsert_and_bounded_completed_retention_preserve_active_jobs(tmp_path):
    store = RuntimeStore(tmp_path / "runtime.sqlite3")
    store.initialize()
    store.set("key'", {"value": 1})
    store.set("key'", {"value": 2})
    assert store.get("key'") == {"value": 2}
    store.save_job(job("old", started_at="2026-01-01"))
    store.save_job(job("new", started_at="2026-01-02"))
    store.save_job(job("active", "running"))
    store.prune_jobs(1)
    assert {item["id"] for item in store.list_jobs()} == {"active", "new"}
    store.prune_jobs(0)
    assert [item["id"] for item in store.list_jobs()] == ["active"]
    store.close()


def test_schema_initialization_is_atomic(tmp_path):
    path = tmp_path / "runtime.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE schedules (id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
    store = RuntimeStore(path)
    with pytest.raises(sqlite3.OperationalError, match="already exists"):
        store.initialize()
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
        assert connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall() == [("schedules",)]


def test_initialization_creates_runtime_directory(tmp_path):
    path = tmp_path / "runtime" / "state.sqlite3"
    store = RuntimeStore(path)
    store.initialize()
    store.set("key", {"value": True})
    assert store.get("key") == {"value": True}
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == RuntimeStore.SCHEMA_VERSION
    store.close()


def test_phase_one_cached_status_migrates_to_latest_raw_evidence(tmp_path):
    path = tmp_path / "runtime.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.executescript("""
            CREATE TABLE observations (key TEXT PRIMARY KEY, payload TEXT NOT NULL, source_revision TEXT);
            CREATE TABLE jobs (id TEXT PRIMARY KEY, status TEXT NOT NULL, started_at TEXT NOT NULL,
                               payload TEXT NOT NULL, source_revision TEXT);
            CREATE TABLE schedules (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            PRAGMA user_version = 1;
        """)
        old = {"ip": "192.0.2.1", "fqdn": "old.example", "mac": "aa:bb:cc:dd:ee:ff",
               "checked_at": "2026-01-01T00:00:00+00:00", "ping_ok": False, "severity": "red"}
        newer = {**old, "checked_at": "2026-01-02T00:00:00+00:00", "ping_ok": True,
                 "mac_found": "aa:bb:cc:dd:ee:ff"}
        ping = {"ip": "192.0.2.2", "checked_at": "2026-01-01T00:00:00+00:00",
                "responding": False, "error": "Ping timeout", "source_revision": "old-revision",
                "severity": "neutral", "managed": True}
        for key, payload in [("status:192.0.2.1:old.example", old),
                             ("status:192.0.2.1:new.example", newer), ("observation:192.0.2.2", ping)]:
            connection.execute("INSERT INTO observations VALUES (?, ?, ?)", (key, json.dumps(payload), None))
    store = RuntimeStore(path)
    store.initialize()
    evidence = store.get("observation:192.0.2.1")
    assert evidence["ping_ok"] is True
    assert evidence["mac_found"] == "aa:bb:cc:dd:ee:ff"
    assert evidence["checked_at"] == newer["checked_at"]
    assert not {"fqdn", "mac", "severity", "expectation_fingerprint"} & evidence.keys()
    assert store.get("status:192.0.2.1:old.example") is None
    assert store.get("status:192.0.2.1:new.example") is None
    assert store.get("observation:192.0.2.2")["ping_error"] == "Ping timeout"
    assert store.get("observation:192.0.2.2")["ping_ok"] is False
    assert store.get("observation:192.0.2.2")["source_revision"] == "old-revision"
    store.close()
    store.initialize()
    assert store.get("observation:192.0.2.1") == evidence
    store.close()
