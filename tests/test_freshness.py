from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from netinfra_ipman.checks import reconcile
from netinfra_ipman.config import AppConfig, load_config, save_config
from netinfra_ipman.freshness import (
    dhcp_pool_context, freshness_max_age, observation_freshness,
)
from netinfra_ipman.models import AddressGroup, Inventory, Subnet
from netinfra_ipman.netinfra import load_inventory
from netinfra_ipman.targets import ScanRequest, TargetPlan, plan_targets

UTC = timezone.utc
NOW = datetime(2026, 1, 1, 12, tzinfo=UTC)


def inventory(cidr="192.0.2.0/24", pools=None):
    group = AddressGroup("192.0.2.10", [], [], None, False)
    return Inventory("revision", {group.ip: group}, [Subnet(cidr, cidr, {"pools": pools})], [], {})


def store(*schedules):
    return SimpleNamespace(list_schedules=lambda: schedules)


def interval(seconds=60, **changes):
    return {"enabled": True, "kind": "interval", "interval_seconds": seconds,
            "scope": "all", "target": "", "mode": "full", **changes}


@pytest.mark.parametrize("value", [0, -1, float("inf"), float("nan"), True, "60", [], {}, 10**1000])
def test_invalid_override(value):
    with pytest.raises(ValueError, match="freshness_seconds"):
        AppConfig(freshness_seconds=value)


@pytest.mark.parametrize("value", [None, 1, 2.5])
def test_override_config_roundtrip(tmp_path, value):
    path = tmp_path / "settings.yml"
    save_config(AppConfig(freshness_seconds=value, config_path=str(path)), path)
    assert load_config(path).freshness_seconds == value


def test_override_precedes_all_schedules():
    class UnreadableStore:
        def list_schedules(self):
            raise AssertionError("Override must not load schedules")

    assert freshness_max_age("192.0.2.10", inventory(), AppConfig(freshness_seconds=17),
                             UnreadableStore(), now=NOW) == 17


def test_fastest_enabled_and_manual_fallback():
    inv = inventory()
    config = AppConfig()
    assert freshness_max_age("192.0.2.10", inv, config, store(), now=NOW) == 86400
    schedules = store(interval(10, enabled=False), interval(100), interval(60),
                      interval(1, scope="ip", target="192.0.2.11"),
                      interval(1, scope="subnet", target="198.51.100.0/24"),
                      interval(-1), {"enabled": True})
    assert freshness_max_age("192.0.2.10", inv, config, schedules, now=NOW) == 120


@pytest.mark.parametrize("scope,target", [
    ("all", ""), ("subnet", "192.0.2.0/28"),
    ("range", "192.0.2.9-192.0.2.11"), ("ip", "192.0.2.10"),
])
@pytest.mark.parametrize("mode", ["full", "known-only", "discovery-only"])
@pytest.mark.parametrize("ip", ["192.0.2.0", "192.0.2.10", "192.0.2.11", "192.0.2.255"])
def test_scope_and_mode_exactly_match_target_planner(scope, target, mode, ip):
    inv = inventory()
    request = ScanRequest(scope, target, mode)
    expected = 120 if ip in set(plan_targets(request, inv)) else 86400
    assert freshness_max_age(ip, inv, AppConfig(), store(interval(scope=scope, target=target, mode=mode)),
                             now=NOW) == expected


def test_large_network_never_iterates_targets(monkeypatch):
    def forbidden(_self):
        raise AssertionError("Freshness must never enumerate planned IPs")

    monkeypatch.setattr(TargetPlan, "__iter__", forbidden)
    assert freshness_max_age("192.0.2.10", inventory("0.0.0.0/0"), AppConfig(),
                             store(interval()), now=NOW) == 120


@pytest.mark.parametrize("cidr,ip", [("192.0.2.0/31", "192.0.2.0"),
                                      ("192.0.2.10/32", "192.0.2.10")])
def test_small_network_endpoints(cidr, ip):
    assert freshness_max_age(ip, inventory(cidr), AppConfig(), store(interval()), now=NOW) == 120


@pytest.mark.parametrize("kind,clock,weekdays,instant,hours", [
    ("daily", "02:30", None, datetime(2026, 3, 8, 12, tzinfo=UTC), 47),
    ("daily", "01:30", None, datetime(2026, 11, 1, 12, tzinfo=UTC), 25),
    ("daily", "03:30", None, datetime(2026, 3, 7, 12, tzinfo=UTC), 23),
    ("weekly", "02:30", [6], datetime(2026, 3, 8, 12, tzinfo=UTC), 335),
    ("weekly", "10:00", [2, 4], datetime(2026, 1, 1, 12, tzinfo=UTC), 48),
])
def test_calendar_occurrences_respect_timezone_dst(kind, clock, weekdays, instant, hours):
    schedule = {"enabled": True, "kind": kind, "time": clock,
                "timezone": "America/New_York", "weekdays": weekdays}
    assert freshness_max_age("192.0.2.10", inventory(), AppConfig(), store(schedule), now=instant) == 2 * hours * 3600


@pytest.mark.parametrize("age,stale", [(59.999999, False), (60, True), (61, True), (-1, True)])
def test_observation_age_boundary(age, stale):
    evidence = {"checked_at": (NOW - timedelta(seconds=age)).isoformat()}
    result = observation_freshness("192.0.2.10", inventory(), AppConfig(freshness_seconds=60),
                                   store(), evidence, now=NOW)
    assert result["stale"] is stale
    assert result["age_seconds"] == age


@pytest.mark.parametrize("evidence", [None, {}, {"checked_at": None}, {"checked_at": "invalid"},
                                       {"checked_at": "2026-01-01T12:00:00"}, {"checked_at": 1}])
def test_invalid_missing_or_naive_dates_stale(evidence):
    assert observation_freshness("192.0.2.10", inventory(), AppConfig(), store(), evidence, now=NOW)["stale"]


def test_age_policy_does_not_modify_semantic_staleness():
    inv = inventory()
    evidence = {"ip": "192.0.2.10", "checked_at": NOW.isoformat(),
                "expectation_fingerprint": "old"}
    config = AppConfig()
    assert observation_freshness("192.0.2.10", inv, config, store(), evidence, now=NOW)["stale"] is False
    assert reconcile(inv.groups["192.0.2.10"], inv, config, evidence).state == "stale"
    assert evidence["expectation_fingerprint"] == "old"


def test_upstream_declared_pool_context_is_not_lease_evidence():
    inv = load_inventory(Path(__file__).parent / "fixtures" / "upstream-netinfra.yml")
    for ip in ("192.168.0.100", "192.168.0.150", "192.168.0.200"):
        context = dhcp_pool_context(ip, inv)
        assert len(context) == 1
        assert context[0]["pool"] == "192.168.0.100-192.168.0.200"
        assert "no DHCP lease has been verified" in context[0]["explanation"]
    assert dhcp_pool_context("192.168.0.99", inv) == []
    assert dhcp_pool_context("192.168.0.201", inv) == []


@pytest.mark.parametrize("pools", [None, "192.0.2.1-192.0.2.20", 10, {},
                                    [None, {}, 1, "", "bad-ip", "::1-::2", "192.0.2.20-192.0.2.1"]])
def test_malformed_optional_pools_ignored(pools):
    assert dhcp_pool_context("192.0.2.10", inventory(pools=pools)) == []


def test_valid_pool_survives_malformed_neighbors():
    inv = inventory(pools=[{}, "bad", "192.0.2.1 - 192.0.2.20"])
    assert dhcp_pool_context("192.0.2.10", inv)[0]["pool"] == "192.0.2.1-192.0.2.20"
    assert dhcp_pool_context("not-an-ip", inv) == []
