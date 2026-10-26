import json
import stat
from types import SimpleNamespace

import pytest

from netinfra_ipman.audit import AuditLogger, source_ip
from netinfra_ipman.config import AppConfig


def request(peer, forwarded=None):
    return SimpleNamespace(
        client=SimpleNamespace(host=peer) if peer is not None else None,
        headers={} if forwarded is None else {"x-forwarded-for": forwarded},
    )


@pytest.mark.parametrize("peer,header,expected", [
    ("198.51.100.4", "203.0.113.8", "198.51.100.4"),
    (None, "203.0.113.8", "unknown"),
    ("proxy-name", "203.0.113.8", "unknown"),
    ("192.0.2.5", "203.0.113.8", "203.0.113.8"),
    ("192.0.2.5", "203.0.113.8, 192.0.2.6", "203.0.113.8"),
    ("192.0.2.5", "203.0.113.8, 198.51.100.4", "198.51.100.4"),
    ("192.0.2.5", "spoofed, 192.0.2.6", "192.0.2.5"),
    ("192.0.2.5", "203.0.113.8,", "192.0.2.5"),
    ("192.0.2.5", "203.0.113.8:80", "192.0.2.5"),
    ("192.0.2.5", "", "192.0.2.5"),
    ("::1", "2001:db8::123", "2001:db8::123"),
])
def test_source_ip_requires_trusted_valid_chain(peer, header, expected):
    config = AppConfig(trusted_proxies=["192.0.2.0/24", "::1"])
    assert source_ip(request(peer, header), config) == expected


def test_default_does_not_trust_local_proxy_headers():
    assert source_ip(request("127.0.0.1", "203.0.113.8"), AppConfig()) == "127.0.0.1"


def test_audit_redacts_nested_secrets_and_arbitrary_strings(tmp_path):
    path = tmp_path / "audit.log"
    audit = AuditLogger(AppConfig(audit_log_file=str(path), oidc_client_secret="configured-secret"))
    try:
        audit.record(
            "user-configured-secret", "192.0.2.1", "change", 
            'password="secret words" token=opaque-token configured-secret Bearer bearer-token',
            before={"nested": [{"password": "old-password", "access_token": "old-token"}]},
            after={"oidc_client_secret": "new-secret", "description": "configured-secret", "safe": "preserved"},
        )
        raw = path.read_text()
        for secret in ("configured-secret", "secret words", "opaque-token", "bearer-token", "old-password", "old-token", "new-secret"):
            assert secret not in raw
        event = json.loads(raw)
        assert event["after"]["safe"] == "preserved"
        assert event["before"]["nested"][0]["password"] == "[REDACTED]"
    finally:
        audit.close()
    assert audit.logger.handlers == []


def test_rotation_bounds_retention_and_keeps_all_files_private(tmp_path):
    path = tmp_path / "audit.log"
    path.write_text("")
    path.chmod(0o666)
    audit = AuditLogger(AppConfig(audit_log_file=str(path), audit_max_bytes=1024, audit_backup_count=2))
    try:
        for number in range(40):
            audit.record("admin", "127.0.0.1", "event", f"event-{number}: " + "x" * 200)
        # A single large payload must not bypass the file size cap.
        audit.record("\U00010000" * 1000, "\U00010000" * 1000, "\U00010000" * 1000, "x" * 10000, after={"data": "y" * 10000})
    finally:
        audit.close()
    files = list(tmp_path.glob("audit.log*"))
    assert len(files) == 3
    for file in files:
        assert file.stat().st_size <= 1024
        assert stat.S_IMODE(file.stat().st_mode) == 0o600
    assert "Oversized audit detail omitted" in path.read_text()
    assert "event-0:" not in "".join(file.read_text() for file in files)


def test_logger_instances_have_independent_handler_lifecycles(tmp_path):
    first_path, second_path = tmp_path / "first.log", tmp_path / "second.log"
    first = AuditLogger(AppConfig(audit_log_file=str(first_path)))
    second = AuditLogger(AppConfig(audit_log_file=str(second_path)))
    first.close()
    first.close()
    try:
        second.record("admin", "127.0.0.1", "second", "still active")
        assert "still active" in second_path.read_text()
        assert first_path.read_text() == ""
    finally:
        second.close()


def test_recent_events_redacts_legacy_data_and_limits_results(tmp_path):
    path = tmp_path / "audit.log"
    path.write_text("\n".join([
        json.dumps({"action": "old", "before": "password: unstructured-old-password", "after": {"nested": {"client_secret": "legacy-secret"}}}),
        "not-json-private-data",
        json.dumps({"action": "latest", "before": {"safe": "visible"}, "after": "complete old YAML data"}),
    ]) + "\n")
    audit = AuditLogger(AppConfig(audit_log_file=str(path)))
    try:
        events = audit.recent_events()
        assert [event["action"] for event in events] == ["old", "latest"]
        assert "unstructured-old-password" not in repr(events)
        assert "legacy-secret" not in repr(events)
        assert "complete old YAML data" not in repr(events)
        assert events[-1]["before"]["safe"] == "visible"
        assert audit.recent_events(1) == events[-1:]
        assert audit.recent_events(0) == []
    finally:
        audit.close()


def test_no_file_logging_has_no_local_history_or_files(tmp_path):
    path = tmp_path / "absent.log"
    audit = AuditLogger(AppConfig(audit_to_file=False, audit_log_file=str(path)))
    try:
        audit.record("admin", "127.0.0.1", "event", "safe")
        assert audit.recent_events() == []
        assert not path.exists()
    finally:
        audit.close()


def test_scalar_snapshots_are_omitted_at_record_time(tmp_path):
    path = tmp_path / "audit.log"
    audit = AuditLogger(AppConfig(audit_log_file=str(path)))
    try:
        audit.record("admin", "127.0.0.1", "settings", "Updated", before="full YAML private value", after="new YAML private value")
        raw = path.read_text()
        assert "YAML private value" not in raw
        assert json.loads(raw)["before"] == "[REDACTED]"
    finally:
        audit.close()


def test_reduced_rotation_retention_removes_excess_numbered_backups(tmp_path):
    path = tmp_path / "audit.log"
    retained = tmp_path / "audit.log.1"
    excess = tmp_path / "audit.log.7"
    unrelated = tmp_path / "audit.log.notes"
    for file in (retained, excess, unrelated):
        file.write_text("historical")
    retained.chmod(0o666)
    audit = AuditLogger(AppConfig(audit_log_file=str(path), audit_backup_count=2))
    try:
        assert not excess.exists()
        assert stat.S_IMODE(retained.stat().st_mode) == 0o600
        assert unrelated.read_text() == "historical"
    finally:
        audit.close()
