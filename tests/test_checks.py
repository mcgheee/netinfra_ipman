import asyncio

from netinfra_ipman.config import AppConfig
from netinfra_ipman.models import CheckResult, ManagedRecord, Severity
import netinfra_ipman.checks as checks


def test_blank_status_is_neutral():
    result = CheckResult.blank("10.0.0.1")
    assert result.severity == Severity.neutral
    assert result.ip == "10.0.0.1"


def test_check_many_serializes_severity(monkeypatch):
    async def fake_check_record_async(record, config):
        return CheckResult(ip=record.ip, fqdn=record.fqdn, mac=record.mac, severity=Severity.green, reason="OK")

    monkeypatch.setattr(checks, "check_record_async", fake_check_record_async)
    record = ManagedRecord(0, 0, "host", "host.example.com", "10.0.0.1", "aa:bb")
    result = asyncio.run(checks.check_many([record], AppConfig()))
    assert result["10.0.0.1"]["severity"] == "green"
