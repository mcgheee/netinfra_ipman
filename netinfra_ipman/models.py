from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from ipaddress import IPv4Address, IPv4Network
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
class AddressGroup:
    ip: str
    records: list[ManagedRecord]
    preferred: list[ManagedRecord]
    mac: str | None
    conflict: bool

    @property
    def dns_names(self) -> tuple[str, ...]:
        return tuple(sorted({record.fqdn for record in self.preferred if not record.no_dns and record.fqdn}))

    @property
    def hostnames(self) -> tuple[str, ...]:
        return tuple(sorted({record.hostname for record in self.preferred if record.hostname}))


@dataclass(frozen=True)
class Diagnostic:
    path: str
    message: str


@dataclass
class Inventory:
    revision: str
    groups: dict[str, AddressGroup]
    subnets: list[Subnet]
    diagnostics: list[Diagnostic]
    expected_dns: dict[str, frozenset[str]]
    _networks: tuple[IPv4Network, ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._networks = tuple(IPv4Network(subnet.cidr) for subnet in self.subnets)

    def contains(self, ip: str) -> bool:
        try:
            address = IPv4Address(ip)
        except ValueError:
            return False
        return any(address in network for network in self._networks)

    @property
    def outliers(self) -> list[AddressGroup]:
        return [group for group in self.groups.values() if not self.contains(group.ip)]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
