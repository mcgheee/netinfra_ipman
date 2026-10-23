from copy import deepcopy
import hashlib
from itertools import permutations
from pathlib import Path

import pytest

from netinfra_ipman.netinfra import (
    NetInfraError,
    append_discovered_host,
    build_inventory,
    fqdn_for,
    load_inventory,
    load_netinfra,
    normalize_mac,
    save_netinfra,
)


FIXTURE = Path(__file__).parent / "fixtures" / "upstream-netinfra.yml"


def host(name, target="10.0.0.1", **record):
    return {"Name": name, "Records": [{"ZoneName": "example.com", "Target": target, **record}]}


def inventory_data(hosts):
    return {"subnets": [{"cidr": "10.0.0.0/24"}], "Hosts": hosts}


def test_upstream_optional_mac_shared_authority_non_a_and_outliers():
    inventory = load_inventory(FIXTURE)
    login = inventory.groups["192.168.0.25"]
    assert len(login.records) == 2
    assert len(login.preferred) == 1
    assert login.mac == "02:dd:da:ca:05:77"
    assert login.dns_names == ("login.my.company.com",)
    management = inventory.groups["10.10.10.10"]
    assert len(management.records) == 2
    assert management.dns_names == ("management.internal.company.com",)
    assert not management.conflict
    assert inventory.groups["10.10.10.201"].mac is None
    assert inventory.groups["10.10.10.201"].dns_names == ("dev.my.company.com",)
    disabled = inventory.groups["10.10.10.90"]
    assert len(disabled.records) == 2
    assert disabled.dns_names == ()
    assert disabled.preferred[0].raw_record["Block_DHCP"] is True
    assert {group.ip for group in inventory.outliers} == {"10.10.8.88", "192.168.1.200"}
    assert not inventory.contains("10.10.8.88")
    assert inventory.expected_dns["monitoring.internal.company.com"] == frozenset({"10.10.8.88"})
    assert inventory.groups["192.168.1.200"].hostnames == ("serverA",)
    assert all("Target" not in item.path for item in inventory.diagnostics)
    assert len(inventory.diagnostics) == 2


@pytest.mark.parametrize("source,alternate,name,zone,expected", [
    (" api ", "alt", "host", " Example.COM ", "api.example.com"),
    ("  ", " Alias ", "host", "example.com", "alias.example.com"),
    (None, "", " Host ", "example.com", "host.example.com"),
    ("Elsewhere.Example.", "alt", "host", "example.com", "elsewhere.example"),
    (None, None, "Example.COM.", "other.example", "example.com"),
    ("already.example.com", None, "host", "example.com", "already.example.com.example.com"),
    ("@", None, "host", "Example.COM.", "example.com"),
    ("star.___Alias", None, "host", "example.com", "*.alias.example.com"),
    ("restart___", None, "host", "example.com", "re*t.example.com"),
    ("star.Example.", None, "host", "ignored.example", "*.example"),
])
def test_dns_precedence_absolute_relative_and_rendered_tokens(source, alternate, name, zone, expected):
    record = {"Source": source, "AltHostName": alternate, "ZoneName": zone}
    original = deepcopy(record)
    assert fqdn_for({"Name": name}, record) == expected
    assert record == original


@pytest.mark.parametrize("value", ["AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff", "AABB.CCDD.EEFF", "aabbccddeeff", " aa:bb:cc:dd:ee:ff "])
def test_valid_mac_forms_have_one_authority(value):
    assert normalize_mac(value) == "aa:bb:cc:dd:ee:ff"
    inventory = build_inventory(inventory_data([host("one", MAC=value), host("two", MAC="aa:bb:cc:dd:ee:ff")]))
    assert inventory.groups["10.0.0.1"].mac == "aa:bb:cc:dd:ee:ff"
    assert not inventory.groups["10.0.0.1"].conflict
    assert not inventory.diagnostics


@pytest.mark.parametrize("value", [None, 123, {}, "", "AA:BB", "aa:bb-cc:dd:ee:ff", "gg:bb:cc:dd:ee:ff"])
def test_invalid_mac_never_becomes_valid(value):
    assert normalize_mac(value) is None


@pytest.mark.parametrize("conflict", [False, True])
def test_shared_ip_authority_and_dns_sets_are_order_invariant(conflict):
    hosts = [host("Alias"), host("First", MAC="aa-bb-cc-dd-ee-ff"),
             host("Second", MAC="00:11:22:33:44:55" if conflict else "AABB.CCDD.EEFF")]
    for ordered in permutations(hosts):
        inventory = build_inventory(inventory_data(list(ordered)))
        group = inventory.groups["10.0.0.1"]
        assert len(group.records) == 3
        assert len(group.preferred) == 2
        assert group.dns_names == ("first.example.com", "second.example.com")
        assert group.hostnames == ("First", "Second")
        assert group.conflict is conflict
        assert group.mac == (None if conflict else "aa:bb:cc:dd:ee:ff")
        assert inventory.expected_dns == {
            "first.example.com": frozenset({"10.0.0.1"}),
            "second.example.com": frozenset({"10.0.0.1"}),
        }
        assert bool(inventory.diagnostics) is conflict


def test_mac_free_definitions_and_multiple_a_answers_are_all_retained():
    inventory = build_inventory(inventory_data([
        host("service"), host("alias"), host("service", "10.0.0.2"),
        host("service", "192.0.2.1"), host("private", "10.0.0.3", RRType="no_dns"),
    ]))
    group = inventory.groups["10.0.0.1"]
    assert group.preferred == group.records
    assert group.mac is None
    assert group.dns_names == ("alias.example.com", "service.example.com")
    assert inventory.expected_dns["service.example.com"] == frozenset({"10.0.0.1", "10.0.0.2", "192.0.2.1"})
    assert "private.example.com" not in inventory.expected_dns


def test_invalid_populated_mac_does_not_promote_mac_free_alias():
    inventory = build_inventory(inventory_data([host("bad", MAC="invalid"), host("alias")]))
    group = inventory.groups["10.0.0.1"]
    assert group.conflict
    assert group.mac is None
    assert group.dns_names == ("bad.example.com",)
    assert group.preferred[0].raw_record["MAC"] == "invalid"
    assert any(item.path.endswith(".MAC") for item in inventory.diagnostics)


@pytest.mark.parametrize("data,path", [
    (None, "$"), ([], "$"), ({"Hosts": {}}, "Hosts"),
    ({"Hosts": None}, "Hosts"), ({"Hosts": [None]}, "Hosts[0]"),
    ({"Hosts": [{"Name": "ok"}]}, "Hosts[0].Records"),
    ({"Hosts": [{"Name": "ok", "Records": {}}]}, "Hosts[0].Records"),
    ({"Hosts": [{"Name": "ok", "Records": [None]}]}, "Hosts[0].Records[0]"),
    ({"subnets": {}}, "subnets"), ({"subnets": [None]}, "subnets[0]"),
    ({"subnets": [{}]}, "subnets[0].cidr"),
    ({"subnets": [{"cidr": "::/64"}]}, "subnets[0].cidr"),
    ({"subnets": [{"cidr": "broken"}]}, "subnets[0].cidr"),
])
def test_malformed_collections_and_subnets_are_diagnosed(data, path):
    inventory = build_inventory(data)
    assert path in {item.path for item in inventory.diagnostics}


@pytest.mark.parametrize("field,value", [("Name", []), ("Name", ""), ("Source", {}),
    ("AltHostName", False), ("ZoneName", []), ("RRType", None), ("RRType", ""),
    ("MAC", []), ("Target", {}), ("Target", "bad"), ("Target", "2001:db8::1")])
def test_malformed_known_identity_fields_are_visible(field, value):
    entry = host("ok")
    if field == "Name":
        entry[field] = value
    else:
        entry["Records"][0][field] = value
    inventory = build_inventory(inventory_data([entry]))
    suffix = f".{field}"
    assert any(item.path.endswith(suffix) for item in inventory.diagnostics)


def test_invalid_no_dns_ip_and_host_name_collisions_are_visible():
    inventory = build_inventory(inventory_data([host("Same"), host("same.", "bad", RRType="no_dns")]))
    paths = {item.path for item in inventory.diagnostics}
    assert "Hosts[1].Name" in paths
    assert "Hosts[1].Records[0].Target" in paths
    assert set(inventory.groups) == {"10.0.0.1"}


@pytest.mark.parametrize("cidr,addresses", [("10.0.0.0/31", ["10.0.0.0", "10.0.0.1"]), ("10.0.0.1/32", ["10.0.0.1"])])
def test_contains_includes_entire_declared_range(cidr, addresses):
    inventory = build_inventory({"subnets": [{"cidr": cidr}]})
    assert all(inventory.contains(ip) for ip in addresses)
    assert not inventory.contains("10.0.0.2")
    assert not inventory.contains("bad")
    assert not inventory.contains("::1")


def test_snapshot_revision_uses_exact_single_read(tmp_path, monkeypatch):
    path = tmp_path / "NetInfra.yml"
    content = b"# exact bytes\nHosts:\n  - Name: original\n    Records:\n      - Target: 10.0.0.1\n"
    path.write_bytes(content)
    read_bytes = Path.read_bytes
    calls = []

    def changing_read(self):
        calls.append(self)
        result = read_bytes(self)
        self.write_bytes(b"Hosts: []\n")
        return result

    monkeypatch.setattr(Path, "read_bytes", changing_read)
    inventory = load_inventory(path)
    assert calls == [path]
    assert inventory.revision == hashlib.sha256(content).hexdigest()
    assert inventory.groups["10.0.0.1"].hostnames == ("original",)


def test_roundtrip_preserves_comments_order_custom_fields_and_non_ip_records(tmp_path):
    data = load_netinfra(FIXTURE)
    original = deepcopy(data)
    original_keys = list(data)
    original_hosts = [item["Name"] for item in data["Hosts"]]
    inventory = build_inventory(data)
    assert data == original
    path = tmp_path / "roundtrip.yml"
    save_netinfra(path, data)
    saved = path.read_text()
    assert "# Focused subset" in saved
    assert "'duo_sso_verification=arandomstringofnumbers'" in saved
    loaded = load_netinfra(path)
    assert loaded == original
    assert list(loaded) == original_keys
    assert [item["Name"] for item in loaded["Hosts"]] == original_hosts
    assert loaded["Hosts"][1]["Records"][0]["DHCP_Options"][1]["domain_name_servers"] == "10.10.10.13, 10.10.10.14"
    assert {record["RRType"] for item in loaded["Hosts"] for record in item["Records"] if "RRType" in record} >= {"TXT", "CNAME", "SRV", "no_dns"}


def test_invalid_yaml_is_load_error_and_invalid_structure_is_inventory_diagnostic(tmp_path):
    path = tmp_path / "invalid.yml"
    path.write_text("Hosts: [\n")
    with pytest.raises(NetInfraError):
        load_inventory(path)
    path.write_text("- not-a-mapping\n")
    assert load_inventory(path).diagnostics[0].path == "$"
    with pytest.raises(NetInfraError):
        load_netinfra(path)


def test_append_discovered_host_round_trip(tmp_path):
    data = {"Hosts": []}
    append_discovered_host(data, "newhost", "example.com", "10.0.0.8", None, "ignored")
    path = tmp_path / "NetInfra.yml"
    save_netinfra(path, data)
    loaded = load_netinfra(path)
    assert loaded["Hosts"][0]["Name"] == "newhost"
    assert build_inventory(loaded).groups["10.0.0.8"].mac is None


@pytest.mark.parametrize("prefix", [
    "# File policy\n  # Indented note\n---\n",
    "# File policy\n--- # document note\n",
    "%YAML 1.1\n# File policy\n--- # document note\n",
])
def test_document_preamble_and_internal_comments_survive_repeated_writes(tmp_path, prefix):
    path = tmp_path / "NetInfra.yml"
    path.write_text(prefix + "Hosts: []  # Host policy\n")
    for _ in range(2):
        data = load_netinfra(path)
        save_netinfra(path, data)
        saved = path.read_text()
        assert saved.startswith(prefix)
        assert saved.count("# File policy") == 1
        assert saved.count("# Host policy") == 1
        assert saved.count("document note") == prefix.count("document note")
