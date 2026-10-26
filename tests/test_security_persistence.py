import json
import sqlite3
import stat

import pytest

from netinfra_ipman.persistence import RuntimeStore


def test_sessions_persist_expire_absolutely_and_delete(tmp_path):
    path = tmp_path / "runtime.db"
    store = RuntimeStore(path)
    store.initialize()
    payload = {"kind": "preauth"}
    store.save_session("hash-one", payload, 120)
    assert store.get_session("hash-one", 100) == payload
    store.save_session("hash-one", {"kind": "authenticated"}, 130)
    store.close()
    store.initialize()
    assert store.get_session("hash-one", 129) == {"kind": "authenticated"}
    assert store.get_session("hash-one", 130) is None
    assert store.get_session("unknown", 0) is None
    store.save_session("delete", payload, 999)
    store.delete_session("delete")
    store.delete_session("delete")
    assert store.get_session("delete", 0) is None
    store.close()


def test_oidc_transactions_are_durable_one_use_and_expire_at_boundary(tmp_path):
    path = tmp_path / "runtime.db"
    store = RuntimeStore(path)
    store.initialize()
    transaction = {"nonce": "nonce", "code_verifier": "private-pkce", "browser_binding": "browser-hash"}
    store.save_oidc_transaction("state-hash", transaction, 120)
    store.save_oidc_transaction("expired", transaction, 120)
    store.close()
    store.initialize()
    assert store.consume_oidc_transaction("state-hash", 119) == transaction
    assert store.consume_oidc_transaction("state-hash", 119) is None
    assert store.consume_oidc_transaction("expired", 120) is None
    assert store.consume_oidc_transaction("expired", 0) is None
    assert store.consume_oidc_transaction("missing", 0) is None
    store.close()


def test_security_cleanup_preserves_unexpired_and_inventory_state(tmp_path):
    store = RuntimeStore(tmp_path / "runtime.db")
    store.initialize()
    store.set("observation:192.0.2.1", {"ping_ok": True})
    store.save_schedule({"id": "daily", "scope": "192.0.2.0/24"})
    for key, expiry in (("old", 9), ("boundary", 10), ("live", 11)):
        store.save_session(key, {"kind": "preauth"}, expiry)
        store.save_oidc_transaction(key, {"nonce": key}, expiry)
    store.purge_expired_security_state(10)
    for expired in ("old", "boundary"):
        assert store.get_session(expired, 0) is None
        assert store.consume_oidc_transaction(expired, 0) is None
    assert store.get_session("live", 10) == {"kind": "preauth"}
    assert store.consume_oidc_transaction("live", 10) == {"nonce": "live"}
    assert store.get("observation:192.0.2.1") == {"ping_ok": True}
    assert store.list_schedules() == [{"id": "daily", "scope": "192.0.2.0/24", "enabled": False}]
    store.close()


def phase_two_database(path):
    with sqlite3.connect(path) as connection:
        connection.executescript("""
            CREATE TABLE observations (key TEXT PRIMARY KEY, payload TEXT NOT NULL, source_revision TEXT);
            CREATE TABLE jobs (id TEXT PRIMARY KEY, status TEXT NOT NULL, started_at TEXT NOT NULL,
                               payload TEXT NOT NULL, source_revision TEXT);
            CREATE TABLE schedules (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            PRAGMA user_version = 2;
        """)
        connection.execute("INSERT INTO observations VALUES (?, ?, ?)",
                           ("observation:192.0.2.1", json.dumps({"ping_ok": True}), "rev"))
        connection.execute("INSERT INTO schedules VALUES (?, ?)", ("daily", json.dumps({"id": "daily"})))


def test_schema_three_upgrade_preserves_prior_state_and_protects_existing_file(tmp_path):
    path = tmp_path / "runtime.db"
    phase_two_database(path)
    path.chmod(0o666)
    store = RuntimeStore(path)
    store.initialize()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert store.get("observation:192.0.2.1") == {"ping_ok": True}
    assert store.list_schedules() == [{"id": "daily"}]
    store.save_session("hash", {"kind": "preauth"}, 100)
    store.save_oidc_transaction("state", {"nonce": "secret"}, 100)
    store.close()
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3
    store.initialize()
    assert store.get_session("hash", 99) == {"kind": "preauth"}
    assert store.consume_oidc_transaction("state", 99) == {"nonce": "secret"}
    store.close()


def test_schema_three_upgrade_is_atomic_on_security_table_collision(tmp_path):
    path = tmp_path / "runtime.db"
    phase_two_database(path)
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE oidc_transactions (existing TEXT)")
    store = RuntimeStore(path)
    with pytest.raises(sqlite3.OperationalError, match="already exists"):
        store.initialize()
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert connection.execute("SELECT name FROM sqlite_master WHERE name = 'sessions'").fetchone() is None
        assert json.loads(connection.execute("SELECT payload FROM observations").fetchone()[0]) == {"ping_ok": True}
    with pytest.raises(RuntimeError, match="not initialized"):
        store.save_session("hash", {}, 100)


def test_malformed_security_payloads_fail_closed_and_state_is_consumed(tmp_path):
    path = tmp_path / "runtime.db"
    store = RuntimeStore(path)
    store.initialize()
    with sqlite3.connect(path) as connection:
        for value, encoded in (("broken", "not json"), ("list", "[]"), ("null", "null")):
            connection.execute("INSERT INTO sessions VALUES (?, ?, ?)", (value, encoded, 100))
            connection.execute("INSERT INTO oidc_transactions VALUES (?, ?, ?)", (value, encoded, 100))
    for key in ("broken", "list", "null"):
        assert store.get_session(key, 0) is None
        assert store.consume_oidc_transaction(key, 0) is None
        assert store.consume_oidc_transaction(key, 0) is None
    store.close()


def test_new_database_is_private_before_storing_pkce(tmp_path):
    path = tmp_path / "private" / "runtime.db"
    store = RuntimeStore(path)
    assert not path.exists()
    store.initialize()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    store.close()
