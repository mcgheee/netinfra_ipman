from dataclasses import asdict

import pytest

from netinfra_ipman.config import AppConfig, load_config, save_config


def test_missing_config_returns_defaults_without_creating_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "missing" / "config.yml"
    config = load_config(path)
    assert config.config_path == str(path)
    assert not path.parent.exists()
    assert list(tmp_path.iterdir()) == []


def test_load_uses_environment_unless_path_is_explicit(tmp_path, monkeypatch):
    environment_path = tmp_path / "environment.yml"
    environment_path.write_text("scan_concurrency: 7\n", encoding="utf-8")
    explicit_path = tmp_path / "explicit.yml"
    explicit_path.write_text("scan_concurrency: 9\n", encoding="utf-8")
    monkeypatch.setenv("IPMAN_CONFIG", str(environment_path))
    assert load_config().scan_concurrency == 7
    assert load_config(explicit_path).scan_concurrency == 9


@pytest.mark.parametrize("contents", ["[]", "- scan_concurrency: 2", "null", "false", "12", "text", ""])
def test_rejects_nonmapping_configuration(tmp_path, contents):
    path = tmp_path / "config.yml"
    path.write_text(contents, encoding="utf-8")
    with pytest.raises(ValueError, match="YAML mapping"):
        load_config(path)


@pytest.mark.parametrize(
    ("contents", "message"),
    [
        ("unknown_setting: 1", "Unknown configuration settings: unknown_setting"),
        ("redis_url: redis://localhost/0", "replace it with sqlite_path"),
        ("scan_concurrency: true", "scan_concurrency"),
        ("scan_concurrency: '8'", "scan_concurrency"),
        ("audit_to_file: 1", "audit_to_file"),
        ("ping_timeout: false", "ping_timeout"),
        ("dns_servers: 1.1.1.1", "dns_servers"),
        ("dns_servers: [123]", "dns_servers"),
        ("dns_servers: [resolver.example.com]", "invalid IP address"),
        ("dns_servers: [192.0.2.999]", "invalid IP address"),
        ("scan_concurrency: 0", "scan_concurrency"),
        ("session_timeout_minutes: -1", "session_timeout_minutes"),
        ("lockout_attempts: 0", "lockout_attempts"),
        ("lockout_minutes: 0", "lockout_minutes"),
        ("rate_limit_per_minute: 0", "rate_limit_per_minute"),
        ("completed_job_retention: -1", "completed_job_retention"),
        ("completed_job_retention: true", "completed_job_retention"),
        ("ping_timeout: 0", "ping_timeout"),
        ("dns_timeout: -1", "dns_timeout"),
        ("dns_lifetime: .inf", "dns_lifetime"),
        ("ping_timeout: .nan", "ping_timeout"),
        ("max_subnet_prefix: -1", "max_subnet_prefix"),
        ("large_subnet_prefix: 33", "large_subnet_prefix"),
        ("large_subnet_prefix: true", "large_subnet_prefix"),
        ("max_subnet_prefix: 25\nlarge_subnet_prefix: 24", "must not exceed"),
        ("sqlite_path: ''", "sqlite_path"),
        ("sqlite_path: ':memory:'", "persistent local storage"),
        ("netinfra_path: '  '", "netinfra_path"),
        ("admin_file: null", "admin_file"),
        ("audit_log_file: []", "audit_log_file"),
        ("config_path: 123", "config_path"),
        ("config_path: ''", "config_path"),
        ("git_repo_path: ''", "git_repo_path"),
        ("git_branch: ''", "git_branch"),
        ("git_remote: ''", "git_remote"),
    ],
)
def test_invalid_settings_fail_on_load(tmp_path, contents, message):
    path = tmp_path / "config.yml"
    path.write_text(contents, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        load_config(path)
    assert path.read_text(encoding="utf-8") == contents


@pytest.mark.parametrize("field", ["netinfra_path", "config_path", "admin_file", "audit_log_file"])
def test_sqlite_cannot_share_authoritative_or_application_files(tmp_path, field):
    path = tmp_path / "shared-file"
    with pytest.raises(ValueError, match=field):
        AppConfig(sqlite_path=str(path), **{field: str(path.parent / "." / path.name)})


def test_sqlite_cannot_alias_netinfra_via_symlink(tmp_path):
    netinfra = tmp_path / "NetInfra.yml"
    netinfra.write_text("{}", encoding="utf-8")
    alias = tmp_path / "runtime.sqlite3"
    alias.symlink_to(netinfra)
    with pytest.raises(ValueError, match="netinfra_path"):
        AppConfig(sqlite_path=str(alias), netinfra_path=str(netinfra))


def test_actual_loaded_config_path_is_protected(tmp_path):
    path = tmp_path / "settings.yml"
    path.write_text(f"sqlite_path: {path}\nconfig_path: elsewhere.yml\n", encoding="utf-8")
    with pytest.raises(ValueError, match="config_path"):
        load_config(path)


def test_valid_settings_round_trip(tmp_path):
    path = tmp_path / "nested" / "settings.yml"
    config = AppConfig(
        config_path=str(path),
        sqlite_path=str(tmp_path / "runtime.sqlite3"),
        dns_servers=["192.0.2.53", "2001:db8::53"],
        ping_timeout=1,
        completed_job_retention=0,
        keycloak_client_id="retained-compatible-setting",
    )
    save_config(config)
    assert asdict(load_config(path)) == asdict(config)


def test_public_validate_and_save_reject_mutated_invalid_config_before_writing(tmp_path):
    config = AppConfig()
    config.scan_concurrency = True
    with pytest.raises(ValueError, match="scan_concurrency"):
        config.validate()
    path = tmp_path / "missing" / "settings.yml"
    with pytest.raises(ValueError, match="scan_concurrency"):
        save_config(config, path)
    assert not path.parent.exists()


def test_save_rejects_sqlite_destination_before_overwriting(tmp_path):
    path = tmp_path / "runtime.sqlite3"
    path.write_bytes(b"existing runtime state")
    config = AppConfig(sqlite_path=str(path))
    with pytest.raises(ValueError, match="config_path"):
        save_config(config, path)
    assert path.read_bytes() == b"existing runtime state"


@pytest.mark.parametrize("path", ["", "  ", "bad\0path"])
def test_load_rejects_empty_or_invalid_path(path):
    with pytest.raises(ValueError, match="config_path"):
        load_config(path)
