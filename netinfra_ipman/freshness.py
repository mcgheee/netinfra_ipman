from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address
from typing import Any

from .config import AppConfig
from .models import Inventory
from .schedules import next_trigger, validate_definition
from .targets import ScanRequest, plan_targets

UTC = timezone.utc
MANUAL_MAX_AGE_SECONDS = 24 * 60 * 60


def _calendar_interval(definition: dict[str, Any], now: datetime) -> float:
    """UTC seconds between calendar occurrences bracketing now.

    A weekly occurrence can be skipped by a DST gap. Fifteen days includes
    the preceding valid occurrence even in that case. Reuse the scheduler's
    gap rejection and fold-zero rule rather than treating local days as 24h.
    """
    previous = next_trigger(definition, now - timedelta(days=15))
    following = next_trigger(definition, previous)
    while following <= now:
        previous, following = following, next_trigger(definition, following)
    return (following - previous).total_seconds()


def freshness_max_age(
    ip: str, inventory: Inventory, config: AppConfig, store, *, now: datetime | None = None,
) -> float:
    """Return age limit without iterating any scan's IP addresses.

    Match the existing planner's exact scope, declared-subnet boundaries, and
    known/discovery-mode semantics. Disabled or invalid schedules do not apply.
    For calendar schedules the applicable interval is the pair of occurrences
    surrounding the current instant, including actual DST elapsed time.
    """
    if config.freshness_seconds is not None:
        return config.freshness_seconds
    now = _utc_clock(now)
    address = int(IPv4Address(ip))
    fastest = None
    for schedule in store.list_schedules():
        if not isinstance(schedule, Mapping) or schedule.get("enabled") is not True:
            continue
        try:
            definition = validate_definition(schedule)
            plan = plan_targets(ScanRequest(
                scope=definition["scope"], target=definition["target"], mode=definition["mode"],
            ), inventory)
            if not any(start <= address <= end for start, end in plan.intervals):
                continue
            interval = (
                definition["interval_seconds"] if definition["kind"] == "interval"
                else _calendar_interval(definition, now)
            )
        except (ValueError, TypeError, KeyError, OverflowError):
            continue
        fastest = interval if fastest is None else min(fastest, interval)
    return MANUAL_MAX_AGE_SECONDS if fastest is None else 2 * fastest


def _utc_clock(now: datetime | None) -> datetime:
    now = now if now is not None else datetime.now(UTC)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("Freshness clock must be timezone-aware")
    return now.astimezone(UTC)


def observation_freshness(
    ip: str, inventory: Inventory, config: AppConfig, store,
    observation: Mapping[str, Any] | None, *, now: datetime | None = None,
) -> dict[str, Any]:
    """Age-only evidence policy; combine with, never replace, semantic staleness.

    Evidence is fresh strictly before its age limit; at the limit it is stale.
    Missing, malformed, timezone-naive, and future timestamps are stale. This
    helper intentionally does not reinterpret fingerprints or scan outcomes.
    """
    now = _utc_clock(now)
    limit = freshness_max_age(ip, inventory, config, store, now=now)
    result = {"stale": True, "max_age_seconds": limit, "age_seconds": None,
              "reason": "Observation timestamp is missing or invalid."}
    if not isinstance(observation, Mapping):
        return result
    checked_at = observation.get("checked_at")
    if not isinstance(checked_at, str):
        return result
    try:
        checked = datetime.fromisoformat(checked_at)
        if checked.tzinfo is None or checked.utcoffset() is None:
            return result
        age = (now - checked.astimezone(UTC)).total_seconds()
    except (ValueError, TypeError, OverflowError):
        return result
    result["age_seconds"] = age
    if age < 0:
        result["reason"] = "Observation timestamp is in the future."
    elif age >= limit:
        result["reason"] = f"Observation age reached the {limit:g}-second freshness limit."
    else:
        result.update(stale=False, reason="Observation is within its freshness age limit.")
    return result


def dhcp_pool_context(ip: str, inventory: Inventory) -> list[dict[str, str]]:
    """Declared inclusive pool membership, not verified DHCP lease evidence.

    NetInfra's upstream shape is subnets[].pools: ["first-IP-last-IP"]. Read
    only those declarations; malformed optional fields are ignored. Pool bounds
    are not silently clipped to the subnet: upstream declarations may extend
    beyond it, and the UI must describe what is declared rather than a lease.
    """
    try:
        address = IPv4Address(ip)
    except (ValueError, TypeError):
        return []
    memberships = []
    for subnet in inventory.subnets:
        if not isinstance(subnet.data, Mapping):
            continue
        pools = subnet.data.get("pools")
        if not isinstance(pools, (list, tuple)):
            continue
        for pool in pools:
            if not isinstance(pool, str):
                continue
            parts = pool.split("-")
            if len(parts) != 2:
                continue
            try:
                first, last = (IPv4Address(part.strip()) for part in parts)
            except ValueError:
                continue
            if first <= address <= last:
                memberships.append({
                    "subnet": subnet.cidr, "pool": f"{first}-{last}",
                    "explanation": "Inside a declared DHCP pool; no DHCP lease has been verified.",
                })
    return memberships
