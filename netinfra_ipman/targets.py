from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from typing import Iterable, Iterator

from .models import Inventory


@dataclass(frozen=True)
class ScanRequest:
    scope: str = "all"
    target: str = ""
    mode: str = "full"

    def __post_init__(self) -> None:
        if not isinstance(self.scope, str) or self.scope not in {"all", "subnet", "range", "ip"}:
            raise ValueError("Scan scope must be all, subnet, range, or ip")
        if not isinstance(self.mode, str) or self.mode not in {"full", "known-only", "discovery-only"}:
            raise ValueError("Scan mode must be full, known-only, or discovery-only")
        if not isinstance(self.target, str):
            raise ValueError("Scan target must be a string")
        if self.scope == "all" and self.target.strip():
            raise ValueError("The all scope does not accept a target")
        if self.scope != "all" and not self.target.strip():
            raise ValueError("This scan scope requires a target")


def merge_intervals(intervals: Iterable[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return tuple(merged)


def _bounds(network: IPv4Network, *, hosts: bool) -> tuple[int, int]:
    offset = int(hosts and network.prefixlen < 31)
    return int(network.network_address) + offset, int(network.broadcast_address) - offset


def _contains(intervals: tuple[tuple[int, int], ...], start: int, end: int) -> bool:
    index = bisect_right(intervals, (start, 2**32)) - 1
    return index >= 0 and intervals[index][0] <= start <= end <= intervals[index][1]


@dataclass(frozen=True)
class TargetPlan:
    request: ScanRequest
    intervals: tuple[tuple[int, int], ...]
    total: int

    def __iter__(self) -> Iterator[str]:
        for start, end in self.intervals:
            for address in range(start, end + 1):
                yield str(IPv4Address(address))


def plan_targets(request: ScanRequest, inventory: Inventory) -> TargetPlan:
    """Plan in subnet/known-address space, never in the size of an IPv4 range."""
    networks = tuple(IPv4Network(subnet.cidr) for subnet in inventory.subnets)
    declared = merge_intervals(_bounds(network, hosts=False) for network in networks)
    hosts = request.mode != "known-only"
    try:
        if request.scope == "all":
            selected = merge_intervals(_bounds(network, hosts=hosts) for network in networks)
        elif request.scope == "subnet":
            network = IPv4Network(request.target.strip(), strict=False)
            start, end = _bounds(network, hosts=False)
            if not _contains(declared, start, end):
                raise ValueError("Targets must be within declared IPv4 subnets")
            selected = (_bounds(network, hosts=hosts),)
        elif request.scope == "ip":
            address = int(IPv4Address(request.target.strip()))
            selected = ((address, address),)
        else:
            parts = request.target.split("-")
            if len(parts) != 2:
                raise ValueError("An inclusive range must be written as start-IP - end-IP")
            start, end = (int(IPv4Address(part.strip())) for part in parts)
            if start > end:
                raise ValueError("Range start must not exceed range end")
            selected = ((start, end),)
    except ValueError as exc:
        raise ValueError(f"Invalid IPv4 scan target: {exc}") from exc
    if any(not _contains(declared, start, end) for start, end in selected):
        raise ValueError("Targets must be within declared IPv4 subnets")

    if request.mode != "full":
        known = sorted(
            int(IPv4Address(ip)) for ip in inventory.groups
            if _contains(selected, int(IPv4Address(ip)), int(IPv4Address(ip)))
        )
        if request.mode == "known-only":
            selected = merge_intervals((address, address) for address in known)
        else:
            remaining: list[tuple[int, int]] = []
            index = 0
            for start, end in selected:
                cursor = start
                while index < len(known) and known[index] <= end:
                    address = known[index]
                    if cursor < address:
                        remaining.append((cursor, address - 1))
                    cursor = address + 1
                    index += 1
                if cursor <= end:
                    remaining.append((cursor, end))
            selected = tuple(remaining)
    return TargetPlan(request, selected, sum(end - start + 1 for start, end in selected))
