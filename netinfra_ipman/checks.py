from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from ipaddress import ip_address, ip_network
import json

import dns.exception
import dns.resolver
from getmac import get_mac_address
from ping3 import ping

from .config import AppConfig
from .models import AddressGroup, Inventory, Severity, utc_now_iso
from .netinfra import normalize_mac


@dataclass
class AddressStatus:
    ip: str
    state: str
    severity: Severity
    reason: str
    tooltip: str
    checked_at: str | None = None
    ping_ok: bool | None = None
    mac_found: str | None = None
    mac_ok: bool | None = None
    dns_checks: list[dict] = field(default_factory=list)
    source_revision: str | None = None


def resolver_servers(ip: str, config: AppConfig) -> list[str]:
    """Select scanner resolvers, never DHCP options from the inventory."""
    address = ip_address(ip)
    matches = [
        (ip_network(cidr), servers)
        for cidr, servers in config.subnet_dns_servers.items()
        if address in ip_network(cidr)
    ]
    if matches:
        _, servers = max(matches, key=lambda match: match[0].prefixlen)
        if servers:
            return list(servers)
    return list(config.dns_servers)


def dns_resolver(ip: str, config: AppConfig) -> dns.resolver.Resolver:
    servers = resolver_servers(ip, config)
    resolver = dns.resolver.Resolver(configure=not bool(servers))
    if servers:
        resolver.nameservers = servers
    resolver.timeout = config.dns_timeout
    resolver.lifetime = config.dns_lifetime
    return resolver


def expectation_fingerprint(group: AddressGroup, inventory: Inventory, config: AppConfig) -> str:
    """Hash semantic expectations, not source formatting or unrelated definitions."""
    expectations = {
        "ip": group.ip,
        "member": inventory.contains(group.ip),
        "conflict": group.conflict,
        "mac": group.mac,
        "preferred": sorted({
            (record.fqdn, record.no_dns, normalize_mac(record.mac))
            for record in group.preferred
        }, key=lambda value: (value[0], value[1], value[2] or "")),
        "dns": {name: sorted(inventory.expected_dns[name]) for name in group.dns_names},
        "resolvers": resolver_servers(group.ip, config) if group.dns_names else [],
    }
    payload = json.dumps(expectations, sort_keys=True, separators=(",", ":"))
    return sha256(payload.encode("utf-8")).hexdigest()


def check_ping(ip: str, timeout: float) -> tuple[bool, float | None, str | None]:
    try:
        response = ping(ip, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - ping3 errors depend on the environment
        return False, None, f"Ping error: {exc}"
    if isinstance(response, (int, float)) and not isinstance(response, bool):
        return True, float(response) * 1000, None
    return False, None, "Ping timeout"


def _observe_dns(name: str, ip: str, config: AppConfig) -> dict:
    try:
        resolver = dns_resolver(ip, config)
        answers = resolver.resolve(name.rstrip(".") + ".", "A", search=False)
        return {"answers": sorted({answer.to_text() for answer in answers}), "error": None}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return {"answers": [], "error": None}
    except dns.exception.Timeout:
        return {"answers": None, "error": "DNS timeout"}
    except dns.resolver.NoNameservers:
        return {"answers": None, "error": "DNS unavailable"}
    except Exception as exc:  # noqa: BLE001 - retain resolver failures as unknown evidence
        return {"answers": None, "error": f"DNS error: {exc}"}


def check_address(group: AddressGroup, inventory: Inventory, config: AppConfig) -> dict:
    """Collect raw evidence; intended values and reconciliation are never persisted."""
    if not inventory.contains(group.ip):
        raise ValueError("Address must be within a declared IPv4 subnet")
    ping_ok, latency, ping_error = check_ping(group.ip, config.ping_timeout)
    mac_found = None
    mac_error = None
    if group.mac is not None:
        try:
            mac_found = normalize_mac(get_mac_address(ip=group.ip))
            if mac_found is None:
                mac_error = "MAC unavailable"
        except Exception as exc:  # noqa: BLE001 - remote MAC lookup may be unsupported
            mac_error = f"MAC unavailable: {exc}"
    return {
        "ip": group.ip,
        "checked_at": utc_now_iso(),
        "ping_ok": ping_ok,
        "ping_error": ping_error,
        "latency_ms": latency,
        "mac_found": mac_found,
        "mac_error": mac_error,
        "dns": {name: _observe_dns(name, group.ip, config) for name in group.dns_names},
        "source_revision": inventory.revision,
        "expectation_fingerprint": expectation_fingerprint(group, inventory, config),
    }




def reconcile(
    group: AddressGroup, inventory: Inventory, config: AppConfig, observation: dict | None,
) -> AddressStatus:
    """Interpret immutable raw evidence against the current inventory."""
    evidence = observation or {}
    current = bool(observation) and evidence.get("ip") == group.ip and (
        evidence.get("expectation_fingerprint") == expectation_fingerprint(group, inventory, config)
    )
    status = AddressStatus(
        ip=group.ip, state="unchecked", severity=Severity.neutral,
        reason="Unchecked", tooltip="No observations are available.",
        checked_at=evidence.get("checked_at"), ping_ok=evidence.get("ping_ok"),
        mac_found=evidence.get("mac_found"), source_revision=evidence.get("source_revision"),
    )
    mismatches: list[str] = []
    incomplete: list[str] = []
    for name in sorted(set(group.dns_names) | set(evidence.get("dns", {}))):
        expected = sorted(inventory.expected_dns.get(name, ())) if name in group.dns_names else []
        dns_evidence = evidence.get("dns", {}).get(name, {})
        answers = dns_evidence.get("answers")
        observed = sorted(set(answers)) if answers is not None else None
        error = dns_evidence.get("error")
        ok = None
        if current:
            if observed is None or error:
                incomplete.append(f"DNS {name}: {error or 'not observed'}")
            else:
                ok = observed == expected
                if not ok:
                    mismatches.append(
                        f"DNS {name}: expected {', '.join(expected)}, "
                        f"observed {', '.join(observed) or 'no A records'}"
                    )
        status.dns_checks.append({
            "name": name, "expected": expected, "observed": observed, "ok": ok, "error": error,
        })
    if group.conflict:
        status.state = "conflict"
        status.severity = Severity.red
        status.reason = "Configuration conflict"
        status.tooltip = "Preferred definitions have invalid or conflicting DNS/MAC assignments."
        return status
    if not observation:
        return status
    if not current:
        status.state = "stale"
        status.reason = "Stale evidence"
        status.tooltip = "Observations predate relevant expectations; run checks again."
        return status
    if evidence.get("ping_ok") is not True or evidence.get("ping_error"):
        incomplete.append(evidence.get("ping_error") or "Ping not observed")
    if group.mac is not None:
        found = normalize_mac(evidence.get("mac_found"))
        status.mac_found = found
        if found is None or evidence.get("mac_error"):
            incomplete.append(evidence.get("mac_error") or "MAC unavailable")
        else:
            status.mac_ok = found == group.mac
            if not status.mac_ok:
                mismatches.append(f"MAC: expected {group.mac}, observed {found}")
    if mismatches:
        status.state, status.severity, status.reason = "mismatch", Severity.red, "Mismatch"
    elif incomplete:
        status.state, status.severity, status.reason = "incomplete", Severity.yellow, "Incomplete evidence"
    else:
        status.state, status.severity, status.reason = "matches", Severity.green, "Matches"
    status.tooltip = "; ".join(mismatches + incomplete) or "All applicable checks completed and match."
    return status
