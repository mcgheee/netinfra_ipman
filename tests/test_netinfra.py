from pathlib import Path

from netinfra_ipman.netinfra import append_discovered_host, duplicate_ip_map, fqdn_for, iter_managed_records, iter_subnets, load_netinfra, save_netinfra


def test_managed_records_and_fqdn_rules():
    data = {
        "subnets": [{"cidr": "10.0.0.0/30"}],
        "Hosts": [
            {"Name": "HostA.", "Records": [{"ZoneName": "Example.COM", "Target": "10.0.0.1", "MAC": "AA:BB", "Comment": "ok"}]},
            {"Name": "alias", "Records": [{"ZoneName": "example.com", "Source": "api", "Target": "10.0.0.2", "MAC": "CC:DD"}]},
            {"Name": "skip", "Records": [{"ZoneName": "example.com", "Target": "not-ip", "MAC": "EE"}]},
            {"Name": "txt", "Records": [{"ZoneName": "example.com", "RRType": "TXT", "Target": "hello", "MAC": "FF"}]},
        ],
    }
    records = iter_managed_records(data)
    assert [record.fqdn for record in records] == ["hosta.example.com", "api.example.com"]
    assert iter_subnets(data)[0].cidr == "10.0.0.0/30"


def test_zone_apex_and_duplicate_ips():
    data = {
        "Hosts": [
            {"Name": "example.com.", "Records": [{"ZoneName": "example.com", "Target": "10.0.0.1", "MAC": "AA"}]},
            {"Name": "other", "Records": [{"ZoneName": "example.com", "Target": "10.0.0.1", "MAC": "BB"}]},
        ]
    }
    assert fqdn_for(data["Hosts"][0], data["Hosts"][0]["Records"][0]) == "example.com"
    records = iter_managed_records(data)
    assert duplicate_ip_map(records) == {"10.0.0.1": 2}


def test_append_discovered_host_round_trip(tmp_path: Path):
    data = {"Hosts": []}
    append_discovered_host(data, "newhost", "example.com", "10.0.0.8", None, "ignored")
    assert data["Hosts"][0]["Records"][0]["Comment"] == "Placeholder"
    path = tmp_path / "NetInfra.yml"
    save_netinfra(path, data)
    loaded = load_netinfra(path)
    assert loaded["Hosts"][0]["Name"] == "newhost"
