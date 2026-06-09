from __future__ import annotations

from collections import Counter
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from .models import ManagedRecord, Subnet


class NetInfraError(Exception):
    """Raised when the NetInfra file cannot be loaded or interpreted."""


def _yaml() -> YAML:
    yaml = YAML()
    yaml.preserve_quotes = True
    return yaml


def load_netinfra(path: str | Path) -> dict[str, Any]:
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            data = _yaml().load(handle) or {}
    except Exception as exc:  # noqa: BLE001 - converted into top-page UI error
        raise NetInfraError(f"Invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise NetInfraError("Invalid YAML: top-level document must be a mapping")
    return data


def save_netinfra(path: str | Path, data: dict[str, Any]) -> None:
    with Path(path).open("w", encoding="utf-8") as handle:
        _yaml().dump(data, handle)


def valid_ipv4(value: Any) -> str | None:
    try:
        addr = ip_address(str(value))
    except ValueError:
        return None
    if isinstance(addr, IPv4Address):
        return str(addr)
    return None


def normalize_name(value: Any) -> str:
    return str(value or "").strip().rstrip(".").lower()


def fqdn_for(host: dict[str, Any], record: dict[str, Any]) -> str:
    zone = normalize_name(record.get("ZoneName"))
    owner = normalize_name(record.get("Source") or record.get("HostName") or host.get("Name"))
    if not zone:
        return owner
    if owner == zone:
        return zone
    if owner.endswith(f".{zone}"):
        return owner
    return f"{owner}.{zone}"


def is_managed_record(record: dict[str, Any]) -> bool:
    rrtype = str(record.get("RRType", "A")).lower()
    if rrtype not in {"a", "no_dns"}:
        return False
    return bool(valid_ipv4(record.get("Target")) and record.get("MAC"))


def iter_managed_records(data: dict[str, Any]) -> list[ManagedRecord]:
    records: list[ManagedRecord] = []
    for host_index, host in enumerate(data.get("Hosts") or []):
        if not isinstance(host, dict):
            continue
        host_name = normalize_name(host.get("Name"))
        for record_index, record in enumerate(host.get("Records") or []):
            if not isinstance(record, dict) or not is_managed_record(record):
                continue
            target = valid_ipv4(record.get("Target"))
            if not target:
                continue
            records.append(
                ManagedRecord(
                    host_index=host_index,
                    record_index=record_index,
                    hostname=host_name,
                    fqdn=fqdn_for(host, record),
                    ip=target,
                    mac=str(record.get("MAC")).strip().lower(),
                    comment=str(record.get("Comment", "")),
                    no_dns=str(record.get("RRType", "A")).lower() == "no_dns",
                    raw_host=host,
                    raw_record=record,
                )
            )
    return sorted(records, key=lambda item: item.ip_address)


def iter_subnets(data: dict[str, Any]) -> list[Subnet]:
    subnets: list[Subnet] = []
    for idx, item in enumerate(data.get("subnets") or []):
        if not isinstance(item, dict) or "cidr" not in item:
            continue
        try:
            network = ip_network(str(item["cidr"]), strict=False)
        except ValueError:
            continue
        if not isinstance(network, IPv4Network):
            continue
        label_bits = [str(item.get("env", "")).strip(), str(item.get("vlan_id", "")).strip(), str(network)]
        label = " / ".join(bit for bit in label_bits if bit)
        subnets.append(Subnet(cidr=str(network), label=label or f"subnet-{idx + 1}", data=item))
    return subnets


def duplicate_ip_map(records: list[ManagedRecord]) -> dict[str, int]:
    counts = Counter(record.ip for record in records)
    return {ip: count for ip, count in counts.items() if count > 1}


def duplicate_fqdn_ip_conflicts(records: list[ManagedRecord]) -> set[tuple[str, str]]:
    seen: dict[tuple[str, str], int] = {}
    conflicts: set[tuple[str, str]] = set()
    for record in records:
        key = (record.fqdn.lower(), record.ip)
        seen[key] = seen.get(key, 0) + 1
        if seen[key] > 1:
            conflicts.add(key)
    return conflicts


def append_discovered_host(data: dict[str, Any], name: str, zone_name: str, target: str, mac: str | None, comment: str | None) -> None:
    if not valid_ipv4(target):
        raise ValueError("Target must be a valid IPv4 address")
    record: dict[str, Any] = {"ZoneName": zone_name, "Target": target}
    if mac:
        record["MAC"] = mac
        record["Comment"] = comment or ""
    else:
        record["Comment"] = "Placeholder"
    host = {"Name": name.strip().rstrip("."), "Records": [record]}
    hosts = data.setdefault("Hosts", [])
    if not isinstance(hosts, list):
        raise ValueError("Hosts must be a list")
    hosts.append(host)
