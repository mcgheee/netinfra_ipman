from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from ipaddress import IPv4Address
from typing import Any


class Severity(str, Enum):
    neutral = "neutral"
    green = "green"
    yellow = "yellow"
    red = "red"


@dataclass(frozen=True)
class Subnet:
    cidr: str
    label: str
    data: dict[str, Any]


@dataclass
class ManagedRecord:
    host_index: int
    record_index: int
    hostname: str
    fqdn: str
    ip: str
    mac: str
    comment: str = ""
    no_dns: bool = False
    raw_host: dict[str, Any] = field(default_factory=dict)
    raw_record: dict[str, Any] = field(default_factory=dict)

    @property
    def ip_address(self) -> IPv4Address:
        return IPv4Address(self.ip)


@dataclass
class CheckResult:
    fqdn: str = ""
    ip: str = ""
    mac: str = ""
    checked_at: str = ""
    severity: Severity = Severity.neutral
    reason: str = ""
    tooltip: str = ""
    ping_ok: bool | None = None
    dns_ok: bool | None = None
    dns_expected: bool = True
    mac_found: str | None = None
    mac_ok: bool | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    latency_ms: float | None = None

    @classmethod
    def blank(cls, ip: str) -> "CheckResult":
        return cls(ip=ip, checked_at="", severity=Severity.neutral)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
