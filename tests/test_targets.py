from ipaddress import IPv4Address
from itertools import islice

import pytest

from netinfra_ipman.netinfra import build_inventory
from netinfra_ipman.targets import ScanRequest, plan_targets


def inventory(subnets, known=()):
    return build_inventory({
        "subnets": [{"cidr": cidr} for cidr in subnets],
        "Hosts": [{"Name": ip, "Records": [{"Target": ip, "RRType": "no_dns"}]} for ip in known],
    }, revision="targets-revision")


def test_overlapping_subnets_preserve_each_subnet_host_semantics():
    data = inventory(["192.0.2.0/30", "192.0.2.0/31", "192.0.2.2/31", "192.0.2.1/32"])
    plan = plan_targets(ScanRequest(), data)
    assert plan.total == 4
    assert list(plan) == [f"192.0.2.{index}" for index in range(4)]
    assert plan.intervals == ((int(IPv4Address("192.0.2.0")), int(IPv4Address("192.0.2.3"))),)


def test_full_ipv4_plan_is_compact_and_streamed():
    plan = plan_targets(ScanRequest(), inventory(["0.0.0.0/0"]))
    assert plan.total == 2**32 - 2
    assert plan.intervals == ((1, 2**32 - 2),)
    assert list(islice(plan, 3)) == ["0.0.0.1", "0.0.0.2", "0.0.0.3"]


@pytest.mark.parametrize("mode, expected", [
    ("full", ["192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"]),
    ("known-only", ["192.0.2.0", "192.0.2.2"]),
    ("discovery-only", ["192.0.2.1", "192.0.2.3"]),
])
def test_inclusive_range_modes_include_explicit_boundaries(mode, expected):
    data = inventory(["192.0.2.0/30"], ["192.0.2.0", "192.0.2.2", "198.51.100.1"])
    plan = plan_targets(ScanRequest("range", "192.0.2.0 - 192.0.2.3", mode), data)
    assert list(plan) == expected
    assert plan.total == len(expected)


def test_range_must_have_no_undeclared_holes():
    data = inventory(["192.0.2.0/31", "192.0.2.4/31"])
    with pytest.raises(ValueError, match="declared"):
        plan_targets(ScanRequest("range", "192.0.2.1-192.0.2.4"), data)
    adjacent = inventory(["192.0.2.0/31", "192.0.2.2/31"])
    assert plan_targets(ScanRequest("range", "192.0.2.1-192.0.2.3"), adjacent).total == 3


@pytest.mark.parametrize("scope,target", [
    ("ip", "::1"), ("subnet", "::/0"), ("range", "192.0.2.3-192.0.2.1"),
    ("range", "192.0.2.1"), ("ip", "192.0.2.1/32"),
])
def test_malformed_targets_fail_before_iteration(scope, target):
    with pytest.raises(ValueError):
        plan_targets(ScanRequest(scope, target), inventory(["0.0.0.0/0"]))


def test_discovery_subtracts_known_addresses_without_expanding_large_ranges():
    data = inventory(["0.0.0.0/0"], ["0.0.0.1", "128.0.0.0", "255.255.255.254"])
    plan = plan_targets(ScanRequest(mode="discovery-only"), data)
    assert plan.total == 2**32 - 5
    assert len(plan.intervals) == 2
    assert list(islice(plan, 2)) == ["0.0.0.2", "0.0.0.3"]
