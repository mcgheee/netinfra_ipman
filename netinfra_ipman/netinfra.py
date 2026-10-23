from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from .models import AddressGroup, Diagnostic, Inventory, ManagedRecord, Subnet


class NetInfraError(Exception):
    """Raised when the NetInfra file cannot be loaded or interpreted."""


def _yaml() -> YAML:
    yaml = YAML()
    yaml.preserve_quotes = True
    return yaml


def _parse(content: bytes) -> Any:
    try:
        text = content.decode("utf-8")
        parse_text = text
        # ruamel drops comments before an explicit document-start marker,
        # while attaching its inline comment to the root mapping. Preserve the
        # whole preamble and omit the marker comment from parsing to avoid
        # emitting it twice. Keep directives in the parser's input.
        leading: list[str] = []
        preamble = ""
        for line in text.splitlines(keepends=True):
            if re.match(r"^---(?:\s|$)", line):
                prefix = "".join(leading)
                preamble = prefix + line
                if "#" in line:
                    ending = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
                    marker = line.split("#", 1)[0].rstrip() + ending
                    parse_text = prefix + marker + text[len(preamble):]
                break
            if line.strip() and not line.lstrip().startswith(("#", "%")):
                break
            leading.append(line)
        data = _yaml().load(parse_text)
        if preamble and hasattr(data, "ca"):
            data._ipman_preamble = preamble
        return data
    except Exception as exc:  # noqa: BLE001 - converted into top-page UI error
        raise NetInfraError(f"Invalid YAML: {exc}") from exc


def load_netinfra(path: str | Path) -> dict[str, Any]:
    try:
        data = _parse(Path(path).read_bytes())
    except OSError as exc:
        raise NetInfraError(f"Cannot read NetInfra: {exc}") from exc
    if not isinstance(data, dict):
        raise NetInfraError("Invalid YAML: top-level document must be a mapping")
    return data


def load_inventory(path: str | Path) -> Inventory:
    """Interpret exactly the bytes whose SHA-256 identifies this snapshot."""
    try:
        content = Path(path).read_bytes()
    except OSError as exc:
        raise NetInfraError(f"Cannot read NetInfra: {exc}") from exc
    return build_inventory(_parse(content), revision=hashlib.sha256(content).hexdigest())


def save_netinfra(path: str | Path, data: dict[str, Any]) -> None:
    with Path(path).open("w", encoding="utf-8") as handle:
        handle.write(getattr(data, "_ipman_preamble", ""))
        _yaml().dump(data, handle)


def valid_ipv4(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        addr = ip_address(value.strip())
    except ValueError:
        return None
    return str(addr) if isinstance(addr, IPv4Address) else None


def normalize_mac(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if re.fullmatch(r"[0-9a-fA-F]{12}", value):
        compact = value
    elif re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value):
        compact = value.replace(":", "")
    elif re.fullmatch(r"(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}", value):
        compact = value.replace("-", "")
    elif re.fullmatch(r"[0-9a-fA-F]{4}(?:\.[0-9a-fA-F]{4}){2}", value):
        compact = value.replace(".", "")
    else:
        return None
    return ":".join(compact[index:index + 2].lower() for index in range(0, 12, 2))


def normalize_name(value: Any) -> str:
    return value.strip().rstrip(".").lower() if isinstance(value, str) else ""


def fqdn_for(host: dict[str, Any], record: dict[str, Any]) -> str:
    """Render the upstream owner tokens without changing their original fields."""
    owner = next((value.strip() for value in (record.get("Source"), record.get("AltHostName"), host.get("Name"))
                  if isinstance(value, str) and value.strip()), "")
    absolute = owner.endswith(".")
    owner = owner.lower().replace("star", "*").replace("___", "").rstrip(".")
    zone = normalize_name(record.get("ZoneName"))
    if owner == "@":
        return zone
    if not owner or absolute or not zone:
        return owner
    return f"{owner}.{zone}"


def build_inventory(data: Any, revision: str = "") -> Inventory:
    """Build a non-mutating interpretation, retaining every eligible definition."""
    diagnostics: list[Diagnostic] = []
    records_by_ip: dict[str, list[ManagedRecord]] = defaultdict(list)
    subnets: list[Subnet] = []

    def report(path: str, message: str) -> None:
        diagnostics.append(Diagnostic(path, message))

    def collection(mapping: dict[str, Any], key: str, path: str, *, required: bool = False) -> list[Any]:
        if key not in mapping:
            if required:
                report(path, "Missing required list")
            return []
        value = mapping[key]
        if not isinstance(value, list):
            report(path, "Must be a list")
            return []
        return value

    if not isinstance(data, dict):
        report("$", "Top-level document must be a mapping")
        return Inventory(revision, {}, [], diagnostics, {})

    for index, item in enumerate(collection(data, "subnets", "subnets")):
        path = f"subnets[{index}]"
        if not isinstance(item, dict):
            report(path, "Subnet must be a mapping")
            continue
        cidr = item.get("cidr")
        try:
            network = ip_network(cidr.strip(), strict=False) if isinstance(cidr, str) else None
        except ValueError:
            network = None
        if not isinstance(network, IPv4Network):
            report(f"{path}.cidr", "Must be a valid IPv4 CIDR")
            continue
        label = " / ".join(str(item[key]).strip() for key in ("env", "vlan_id") if item.get(key) is not None)
        subnets.append(Subnet(str(network), f"{label} / {network}" if label else str(network), item))

    host_names: dict[str, str] = {}
    for host_index, host in enumerate(collection(data, "Hosts", "Hosts")):
        host_path = f"Hosts[{host_index}]"
        if not isinstance(host, dict):
            report(host_path, "Host must be a mapping")
            continue
        name = host.get("Name")
        if not isinstance(name, str) or not name.strip():
            report(f"{host_path}.Name", "Must be a populated string")
        else:
            identity = normalize_name(name)
            if identity in host_names:
                report(f"{host_path}.Name", f"Host name collides with {host_names[identity]}")
            else:
                host_names[identity] = f"{host_path}.Name"
        for record_index, record in enumerate(collection(host, "Records", f"{host_path}.Records", required=True)):
            path = f"{host_path}.Records[{record_index}]"
            if not isinstance(record, dict):
                report(path, "Record must be a mapping")
                continue
            for key in ("Source", "AltHostName", "ZoneName", "RRType", "MAC", "Target"):
                if key in record and not isinstance(record[key], str):
                    report(f"{path}.{key}", "Must be a string")
            rrtype = record.get("RRType", "A")
            if not isinstance(rrtype, str) or not rrtype.strip():
                if isinstance(rrtype, str):
                    report(f"{path}.RRType", "Must be a populated string")
                continue
            rrtype = rrtype.strip().lower()
            raw_mac = record.get("MAC", "")
            has_mac = not isinstance(raw_mac, str) or bool(raw_mac.strip())
            mac = normalize_mac(raw_mac)
            if has_mac and mac is None:
                report(f"{path}.MAC", "Invalid MAC address")
            if rrtype not in {"a", "no_dns"}:
                continue
            target = valid_ipv4(record.get("Target"))
            if target is None:
                report(f"{path}.Target", "A/no_dns target must be a valid IPv4 address")
                continue
            fqdn = fqdn_for(host, record)
            if rrtype == "a" and not fqdn:
                report(path, "A record has no DNS owner")
            # Keep invalid populated values authoritative enough to expose a
            # conflict rather than falling back to unrelated MAC-free aliases.
            retained_mac = ""
            if has_mac:
                retained_mac = mac or (raw_mac.strip() if isinstance(raw_mac, str) else repr(raw_mac))
            records_by_ip[target].append(ManagedRecord(
                host_index=host_index, record_index=record_index,
                hostname=name if isinstance(name, str) else "", fqdn=fqdn, ip=target,
                mac=retained_mac,
                comment=str(record.get("Comment", "")), no_dns=rrtype == "no_dns",
                raw_host=host, raw_record=record,
            ))

    groups: dict[str, AddressGroup] = {}
    expected: dict[str, set[str]] = defaultdict(set)
    for ip in sorted(records_by_ip, key=IPv4Address):
        records = records_by_ip[ip]
        preferred = [record for record in records if record.mac] or list(records)
        macs = {normalize_mac(record.mac) for record in preferred if record.mac}
        invalid_owner = any(not record.no_dns and not record.fqdn for record in preferred)
        conflict = len(macs) > 1 or None in macs or invalid_owner
        mac = next(iter(macs)) if len(macs) == 1 and not conflict else None
        group = AddressGroup(ip, records, preferred, mac, conflict)
        groups[ip] = group
        if conflict:
            report(f"groups[{ip}]", "Conflicting or invalid preferred DNS/MAC definitions")
        for name in group.dns_names:
            expected[name].add(ip)
    inventory = Inventory(revision, groups, subnets, diagnostics,
                          {name: frozenset(addresses) for name, addresses in sorted(expected.items())})
    for group in inventory.outliers:
        report(f"groups[{group.ip}]", "Address is outside declared subnets")
    return inventory


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
