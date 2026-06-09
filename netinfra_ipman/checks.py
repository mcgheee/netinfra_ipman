from __future__ import annotations

import asyncio
import socket
from typing import Iterable

import dns.exception
import dns.resolver
from getmac import get_mac_address
from ping3 import ping

from .config import AppConfig
from .models import CheckResult, ManagedRecord, Severity, utc_now_iso


def _reason(result: CheckResult) -> None:
    if result.errors:
        first = result.errors[0]
        result.reason = first[:32]
        result.tooltip = "; ".join(result.errors + result.warnings)
        result.severity = Severity.red
        return
    if result.warnings:
        result.reason = result.warnings[0][:32]
        result.tooltip = "; ".join(result.warnings)
        result.severity = Severity.yellow
        return
    result.reason = "OK"
    result.tooltip = "Ping, DNS, and MAC checks passed."
    result.severity = Severity.green


def dns_resolver(config: AppConfig) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=True)
    if config.dns_servers:
        resolver.nameservers = config.dns_servers
    resolver.timeout = config.dns_timeout
    resolver.lifetime = config.dns_lifetime
    return resolver


def check_dns(record: ManagedRecord, config: AppConfig) -> tuple[bool | None, list[str]]:
    if record.no_dns:
        return None, []
    resolver = dns_resolver(config)
    try:
        answers = resolver.resolve(record.fqdn, "A")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return False, ["DNS missing"]
    except dns.exception.Timeout:
        return False, ["DNS timeout"]
    except dns.resolver.NoNameservers:
        return False, ["DNS unavailable"]
    except Exception as exc:  # noqa: BLE001 - displayed in tooltip
        return False, ["DNS error", str(exc)]
    ips = {answer.to_text() for answer in answers}
    if record.ip not in ips:
        return False, ["DNS mismatch", f"Expected {record.ip}, got {', '.join(sorted(ips)) or 'no A records'}"]
    return True, []


def check_ping(ip: str, timeout: float) -> tuple[bool, float | None, str | None]:
    try:
        response = ping(ip, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - ping3 raises several environment-dependent errors
        return False, None, f"Ping error: {exc}"
    if isinstance(response, (int, float)) and response is not False:
        return True, float(response) * 1000, None
    return False, None, "Ping timeout"


def check_mac(ip: str, expected_mac: str) -> tuple[bool | None, str | None, list[str], list[str]]:
    try:
        found = get_mac_address(ip=ip)
    except Exception as exc:  # noqa: BLE001 - unsupported network path is a warning
        return None, None, [], [f"MAC unknown: {exc}"]
    if not found:
        return None, None, [], ["MAC unknown"]
    normalized = found.lower()
    if normalized != expected_mac.lower():
        return False, normalized, ["MAC mismatch", f"Expected {expected_mac}, got {normalized}"], []
    return True, normalized, [], []


def check_record(record: ManagedRecord, config: AppConfig) -> CheckResult:
    result = CheckResult(
        fqdn=record.fqdn,
        ip=record.ip,
        mac=record.mac,
        checked_at=utc_now_iso(),
        dns_expected=not record.no_dns,
    )
    ping_ok, latency, ping_error = check_ping(record.ip, config.ping_timeout)
    result.ping_ok = ping_ok
    result.latency_ms = latency
    if ping_error:
        result.errors.append("Ping timeout" if "timeout" in ping_error.lower() else "Ping error")
        result.errors.append(ping_error)

    dns_ok, dns_errors = check_dns(record, config)
    result.dns_ok = dns_ok
    if dns_errors:
        result.errors.extend(dns_errors)
    no_dns_tooltip = record.no_dns

    mac_ok, mac_found, mac_errors, mac_warnings = check_mac(record.ip, record.mac)
    result.mac_ok = mac_ok
    result.mac_found = mac_found
    result.errors.extend(mac_errors)
    result.warnings.extend(mac_warnings)
    _reason(result)
    if no_dns_tooltip and result.severity is Severity.green:
        result.tooltip = "Ping and MAC checks passed; DNS is not expected for RRType no_dns."
    return result


async def check_record_async(record: ManagedRecord, config: AppConfig) -> CheckResult:
    return await asyncio.to_thread(check_record, record, config)


async def check_many(records: Iterable[ManagedRecord], config: AppConfig) -> dict[str, dict]:
    semaphore = asyncio.Semaphore(config.scan_concurrency)

    async def guarded(record: ManagedRecord) -> tuple[str, dict]:
        async with semaphore:
            result = await check_record_async(record, config)
            payload = result.__dict__.copy()
            payload["severity"] = result.severity.value
            return record.ip, payload

    return dict(await asyncio.gather(*(guarded(record) for record in records)))


def resolver_available(config: AppConfig) -> bool:
    try:
        resolver = dns_resolver(config)
        resolver.resolve(".", "NS")
    except dns.exception.DNSException:
        try:
            socket.gethostbyname("localhost")
        except OSError:
            return False
    return True
