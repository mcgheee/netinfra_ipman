from copy import deepcopy
from types import SimpleNamespace

import dns.exception
import dns.resolver
import pytest

from netinfra_ipman.config import AppConfig
from netinfra_ipman.models import Severity
from netinfra_ipman.netinfra import build_inventory
import netinfra_ipman.checks as checks


MAC = "aa:bb:cc:dd:ee:ff"
IP = "10.0.0.1"


def host(name="host", ip=IP, **record_fields):
    return {"Name": name, "Records": [{"ZoneName": "example.com", "Target": ip, **record_fields}]}


def inventory(*hosts, revision="original", subnets=None):
    return build_inventory({
        "subnets": subnets if subnets is not None else [{"cidr": "10.0.0.0/24"}],
        "Hosts": list(hosts or [host()]),
    }, revision=revision)


@pytest.fixture
def probes(monkeypatch):
    monkeypatch.setattr(checks, "check_ping", lambda ip, timeout: (True, 1.25, None))
    monkeypatch.setattr(checks, "get_mac_address", lambda **kwargs: MAC)
    calls = []
    outcome = {"answers": [IP], "error": None}

    def resolve(name, rrtype, **kwargs):
        calls.append((name, rrtype, kwargs))
        if outcome["error"] is not None:
            raise outcome["error"]
        return [SimpleNamespace(to_text=lambda value=value: value) for value in outcome["answers"]]

    monkeypatch.setattr(checks, "dns_resolver", lambda ip, config: SimpleNamespace(resolve=resolve))
    return calls, outcome


def observe(inv, config=None):
    return checks.check_address(inv.groups[IP], inv, config or AppConfig())


def status(inv, evidence, config=None):
    return checks.reconcile(inv.groups[IP], inv, config or AppConfig(), evidence)


@pytest.mark.parametrize("answers,state", [
    ([IP, "10.0.0.2"], "matches"),
    ([IP], "mismatch"),
    ([IP, "10.0.0.2", "10.0.0.3"], "mismatch"),
    ([], "mismatch"),
])
def test_dns_requires_complete_exact_answer_set(probes, answers, state):
    _, outcome = probes
    outcome["answers"] = answers
    inv = inventory(host(), host(ip="10.0.0.2"))
    evidence = observe(inv)
    result = status(inv, evidence)
    assert result.state == state
    assert result.dns_checks == [{
        "name": "host.example.com", "expected": [IP, "10.0.0.2"],
        "observed": sorted(answers), "ok": state == "matches", "error": None,
    }]
    assert result.checked_at == evidence["checked_at"]
    assert result.source_revision == "original"
    assert "expected" not in evidence["dns"]["host.example.com"]
    assert "state" not in evidence and "severity" not in evidence
    assert "mac" not in evidence


def test_multiple_authoritative_names_and_absolute_queries(probes):
    calls, _ = probes
    inv = inventory(host(MAC=MAC), host("alias", MAC=MAC), host("ignored"))
    result = status(inv, observe(inv))
    assert result.state == "matches"
    assert {entry["name"] for entry in result.dns_checks} == {"host.example.com", "alias.example.com"}
    assert {call[0] for call in calls} == {"host.example.com.", "alias.example.com."}
    assert all(call[1:] == ("A", {"search": False}) for call in calls)


@pytest.mark.parametrize("error", [dns.resolver.NXDOMAIN(), dns.resolver.NoAnswer()])
def test_confirmed_absence_is_mismatch(probes, error):
    _, outcome = probes
    outcome["error"] = error
    inv = inventory()
    result = status(inv, observe(inv))
    assert result.state == "mismatch"
    assert result.dns_checks[0]["observed"] == []
    assert result.dns_checks[0]["error"] is None


@pytest.mark.parametrize("error", [
    dns.exception.Timeout(), dns.resolver.NoNameservers(), RuntimeError("resolver failed"),
])
def test_dns_failure_is_incomplete_not_discrepancy(probes, error):
    _, outcome = probes
    outcome["error"] = error
    inv = inventory()
    result = status(inv, observe(inv))
    assert result.state == "incomplete"
    assert result.severity == Severity.yellow
    assert result.dns_checks[0]["observed"] is None
    assert result.dns_checks[0]["ok"] is None
    assert result.dns_checks[0]["error"]


def test_no_dns_without_mac_only_requires_ping(monkeypatch):
    monkeypatch.setattr(checks, "check_ping", lambda *args: (True, 0.0, None))

    def forbidden(*args, **kwargs):
        pytest.fail("Omitted DNS/MAC probes must not run")

    monkeypatch.setattr(checks, "dns_resolver", forbidden)
    monkeypatch.setattr(checks, "get_mac_address", forbidden)
    inv = inventory(host(RRType="no_dns"))
    evidence = observe(inv)
    assert evidence["dns"] == {}
    assert evidence["mac_found"] is None
    assert status(inv, evidence).state == "matches"


def test_no_dns_still_checks_present_mac(monkeypatch, probes):
    calls, _ = probes
    inv = inventory(host(RRType="no_dns", MAC=MAC))
    result = status(inv, observe(inv))
    assert result.state == "matches"
    assert result.mac_ok is True
    assert calls == []


def test_absent_mac_never_probed(monkeypatch, probes):
    def forbidden(**kwargs):
        pytest.fail("MAC-less records must not trigger MAC lookup")

    monkeypatch.setattr(checks, "get_mac_address", forbidden)
    inv = inventory()
    assert status(inv, observe(inv)).state == "matches"


@pytest.mark.parametrize("found,expected_state,ok", [
    ("AABB.CCDD.EEFF", "matches", True),
    ("AA-BB-CC-DD-EE-FF", "matches", True),
    ("11:22:33:44:55:66", "mismatch", False),
    (None, "incomplete", None),
    ("invalid", "incomplete", None),
])
def test_mac_is_normalized_and_unavailable_is_not_mismatch(monkeypatch, probes, found, expected_state, ok):
    monkeypatch.setattr(checks, "get_mac_address", lambda **kwargs: found)
    inv = inventory(host(MAC=MAC))
    result = status(inv, observe(inv))
    assert result.state == expected_state
    assert result.mac_ok is ok
    if ok:
        assert result.mac_found == MAC


def test_mac_exception_is_incomplete(monkeypatch, probes):
    def failed(**kwargs):
        raise OSError("routed address")

    monkeypatch.setattr(checks, "get_mac_address", failed)
    inv = inventory(host(MAC=MAC))
    result = status(inv, observe(inv))
    assert result.state == "incomplete"
    assert "routed address" in result.tooltip


@pytest.mark.parametrize("ping_error", ["Ping timeout", "Ping error: denied"])
def test_ping_failure_is_incomplete_not_discrepancy(monkeypatch, probes, ping_error):
    monkeypatch.setattr(checks, "check_ping", lambda *args: (False, None, ping_error))
    inv = inventory()
    result = status(inv, observe(inv))
    assert result.state == "incomplete"
    assert ping_error in result.tooltip


def test_mismatch_dominates_incomplete_and_preserves_all_reasons(monkeypatch, probes):
    _, outcome = probes
    outcome["answers"] = ["10.0.0.7"]
    monkeypatch.setattr(checks, "check_ping", lambda *args: (False, None, "Ping timeout"))
    monkeypatch.setattr(checks, "get_mac_address", lambda **kwargs: None)
    inv = inventory(host(MAC=MAC))
    result = status(inv, observe(inv))
    assert result.state == "mismatch"
    assert "DNS host.example.com" in result.tooltip
    assert "Ping timeout" in result.tooltip
    assert "MAC unavailable" in result.tooltip


def test_ping_alone_cannot_satisfy_required_dns_and_mac(probes):
    inv = inventory(host(MAC=MAC))
    evidence = observe(inv)
    evidence["dns"] = {}
    evidence["mac_found"] = None
    result = status(inv, evidence)
    assert result.state == "incomplete"
    assert result.mac_ok is None
    assert result.dns_checks[0]["ok"] is None


@pytest.mark.parametrize("evidence_kind", ["absent", "current", "stale"])
def test_configuration_conflict_dominates_all_evidence(probes, evidence_kind):
    inv = inventory(host(MAC=MAC), host("other", MAC="11:22:33:44:55:66"))
    evidence = None if evidence_kind == "absent" else observe(inv)
    if evidence_kind == "stale":
        evidence.pop("expectation_fingerprint")
    result = status(inv, evidence)
    assert result.state == "conflict"
    assert result.severity == Severity.red


def test_unchecked_and_legacy_or_changed_evidence_are_not_current(probes):
    inv = inventory()
    assert status(inv, None).state == "unchecked"
    evidence = observe(inv)
    evidence.pop("expectation_fingerprint")
    evidence_before = deepcopy(evidence)
    result = status(inv, evidence)
    assert result.state == "stale"
    assert result.dns_checks[0]["observed"] == [IP]
    assert result.dns_checks[0]["ok"] is None
    assert result.mac_ok is None
    assert result.checked_at == evidence["checked_at"]
    assert evidence == evidence_before


def test_revision_custom_fields_and_name_order_do_not_stale(probes):
    original = inventory(host(MAC=MAC), host("alias", MAC=MAC))
    evidence = observe(original)
    changed = inventory(
        {**host("alias", MAC=MAC, Custom="ignored"), "Comment": "changed"},
        host(MAC="AA-BB-CC-DD-EE-FF"), revision="new revision",
    )
    assert status(changed, evidence).state == "matches"
    assert status(changed, evidence).source_revision == "original"
    assert checks.expectation_fingerprint(original.groups[IP], original, AppConfig()) == checks.expectation_fingerprint(changed.groups[IP], changed, AppConfig())


@pytest.mark.parametrize("changed", [
    lambda: inventory(host(), host(ip="10.0.0.2")),
    lambda: inventory(host("renamed")),
    lambda: inventory(host(RRType="no_dns")),
    lambda: inventory(host(MAC=MAC)),
    lambda: inventory(host(), subnets=[{"cidr": "192.0.2.0/24"}]),
])
def test_relevant_edits_including_other_address_for_same_name_stale(probes, changed):
    original = inventory()
    assert status(changed(), observe(original)).state == "stale"


def test_unrelated_address_and_dns_edits_do_not_stale(probes):
    original = inventory()
    changed = inventory(host(), host("other", "10.0.0.2"))
    assert status(changed, observe(original)).state == "matches"


def test_resolver_precedence_longest_override_global_and_server():
    config = AppConfig(dns_servers=["192.0.2.1"], subnet_dns_servers={
        "10.0.0.0/8": ["192.0.2.2"], "10.0.0.0/24": ["192.0.2.3"],
        "10.0.0.128/25": [],
    })
    assert checks.resolver_servers(IP, config) == ["192.0.2.3"]
    assert checks.resolver_servers("10.1.0.1", config) == ["192.0.2.2"]
    assert checks.resolver_servers("10.0.0.129", config) == ["192.0.2.1"]
    assert checks.resolver_servers("198.51.100.1", config) == ["192.0.2.1"]
    assert checks.resolver_servers(IP, AppConfig()) == []


def test_explicit_resolvers_work_without_server_resolver_configuration(monkeypatch):
    def unavailable(*args, **kwargs):
        raise dns.resolver.NoResolverConfiguration("server resolver file missing")

    monkeypatch.setattr(dns.resolver.Resolver, "read_resolv_conf", unavailable)
    config = AppConfig(dns_servers=["192.0.2.1"], dns_timeout=3.0, dns_lifetime=4.0)
    resolver = checks.dns_resolver(IP, config)
    assert resolver.nameservers == ["192.0.2.1"]
    with pytest.raises(dns.resolver.NoResolverConfiguration):
        checks.dns_resolver(IP, AppConfig())


def test_selected_resolver_changes_stale_but_unrelated_override_does_not(probes):
    inv = inventory()
    evidence = observe(inv)
    unrelated = AppConfig(subnet_dns_servers={"192.0.2.0/24": ["192.0.2.1"]})
    assert status(inv, evidence, unrelated).state == "matches"
    selected = AppConfig(dns_servers=["192.0.2.1"])
    assert status(inv, evidence, selected).state == "stale"


def test_dhcp_dns_options_do_not_select_scanner_resolvers(probes):
    original = inventory()
    changed = inventory(subnets=[{"cidr": "10.0.0.0/24", "dns_servers": ["192.0.2.1"]}])
    assert status(changed, observe(original)).state == "matches"


def test_reconcile_never_mutates_observations(probes):
    inv = inventory(host(MAC=MAC))
    evidence = observe(inv)
    before = deepcopy(evidence)
    status(inv, evidence)
    assert evidence == before




def test_changed_dns_owner_retains_historical_evidence_without_comparing_it(probes):
    original = inventory()
    evidence = observe(original)
    changed = inventory(host("renamed"), revision="changed")
    result = status(changed, evidence)
    assert result.state == "stale"
    by_name = {entry["name"]: entry for entry in result.dns_checks}
    assert by_name["host.example.com"]["observed"] == [IP]
    assert by_name["host.example.com"]["expected"] == []
    assert by_name["host.example.com"]["ok"] is None
    assert by_name["renamed.example.com"]["observed"] is None
    assert by_name["renamed.example.com"]["expected"] == [IP]


def test_a_record_without_dns_owner_is_configuration_conflict(probes):
    inv = inventory({"Records": [{"Target": IP}]})
    assert status(inv, observe(inv)).state == "conflict"


def test_outlier_never_probed(monkeypatch):
    inv = inventory(host(ip="192.0.2.1"))

    def forbidden(*args):
        pytest.fail("Outliers are not eligible probe targets")

    monkeypatch.setattr(checks, "check_ping", forbidden)
    with pytest.raises(ValueError, match="declared"):
        checks.check_address(inv.groups["192.0.2.1"], inv, AppConfig())
