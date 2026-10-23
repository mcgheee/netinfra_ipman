from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from ipaddress import IPv4Network, ip_address, ip_network
import math
import os
from pathlib import Path
from typing import Any, get_type_hints

from ruamel.yaml import YAML


@dataclass
class AppConfig:
    netinfra_path: str = "./NetInfra.yml"
    config_path: str = "./ipman-config.yml"
    admin_file: str = "./ipman-admin.yml"
    audit_log_file: str = "./ipman-audit.log"
    audit_to_file: bool = True
    audit_to_syslog: bool = False
    sqlite_path: str = "./ipman.sqlite3"
    completed_job_retention: int = 100
    scan_concurrency: int = 128
    ping_timeout: float = 1.0
    dns_timeout: float = 2.0
    dns_lifetime: float = 2.0
    dns_servers: list[str] = field(default_factory=list)
    subnet_dns_servers: dict[str, list[str]] = field(default_factory=dict)
    large_subnet_prefix: int = 24
    max_subnet_prefix: int = 16
    git_enabled: bool = False
    git_repo_path: str = "."
    git_branch: str = "main"
    git_push: bool = False
    git_remote: str = "origin"
    session_timeout_minutes: int = 60
    lockout_attempts: int = 5
    lockout_minutes: int = 15
    rate_limit_per_minute: int = 60
    keycloak_enabled: bool = False
    keycloak_metadata_url: str = ""
    keycloak_client_id: str = ""
    keycloak_client_secret: str = ""
    duo_enabled: bool = False
    duo_integration_key: str = ""
    duo_secret_key: str = ""
    duo_api_hostname: str = ""
    tls_enabled: bool = False
    reverse_proxy: bool = True

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        """Reject invalid settings before they reach application services."""
        for name, annotation in get_type_hints(type(self)).items():
            value = getattr(self, name)
            if annotation is float:
                valid = type(value) in (int, float)
            elif annotation == list[str]:
                valid = isinstance(value, list) and all(type(item) is str for item in value)
            elif annotation == dict[str, list[str]]:
                valid = isinstance(value, dict) and all(
                    type(key) is str and isinstance(servers, list)
                    and all(type(server) is str for server in servers)
                    for key, servers in value.items()
                )
            else:
                valid = type(value) is annotation
            if not valid:
                raise ValueError(f"{name} has an invalid type; expected {annotation}")

        path_fields = (
            "netinfra_path", "config_path", "admin_file", "audit_log_file",
            "sqlite_path", "git_repo_path",
        )
        for name in path_fields:
            value = getattr(self, name)
            if not value.strip() or "\0" in value:
                raise ValueError(f"{name} must be a nonempty path without NUL characters")
        if self.sqlite_path == ":memory:":
            raise ValueError("sqlite_path must use persistent local storage, not :memory:")
        for name in ("git_branch", "git_remote"):
            if not getattr(self, name).strip():
                raise ValueError(f"{name} must not be empty")
        for name in (
            "scan_concurrency", "session_timeout_minutes", "lockout_attempts",
            "lockout_minutes", "rate_limit_per_minute",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be greater than zero")
        if self.completed_job_retention < 0:
            raise ValueError("completed_job_retention must be zero or greater")
        for name in ("ping_timeout", "dns_timeout", "dns_lifetime"):
            value = getattr(self, name)
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be finite and greater than zero")
        for name in ("large_subnet_prefix", "max_subnet_prefix"):
            if not 0 <= getattr(self, name) <= 32:
                raise ValueError(f"{name} must be between 0 and 32")
        if self.max_subnet_prefix > self.large_subnet_prefix:
            raise ValueError("max_subnet_prefix must not exceed large_subnet_prefix")
        for server in self.dns_servers:
            try:
                ip_address(server)
            except ValueError as exc:
                raise ValueError(f"dns_servers contains an invalid IP address: {server!r}") from exc
        for cidr, servers in self.subnet_dns_servers.items():
            try:
                network = ip_network(cidr, strict=True)
            except ValueError as exc:
                raise ValueError(f"subnet_dns_servers has an invalid canonical CIDR: {cidr!r}") from exc
            if not isinstance(network, IPv4Network) or str(network) != cidr:
                raise ValueError("subnet_dns_servers keys must be canonical IPv4 CIDRs")
            for server in servers:
                try:
                    ip_address(server)
                except ValueError as exc:
                    raise ValueError(f"subnet_dns_servers contains an invalid resolver IP: {server!r}") from exc

        sqlite_path = Path(self.sqlite_path).resolve()
        for name in ("netinfra_path", "config_path", "admin_file", "audit_log_file"):
            other_path = Path(getattr(self, name)).resolve()
            if sqlite_path == other_path or (
                sqlite_path.exists() and other_path.exists() and sqlite_path.samefile(other_path)
            ):
                raise ValueError(f"sqlite_path must be separate from {name}")


def _coerce_config(data: Any, config_path: str) -> AppConfig:
    if not isinstance(data, Mapping):
        raise ValueError("Configuration must be a YAML mapping of setting names to values")
    if "redis_url" in data:
        raise ValueError("redis_url is no longer supported; replace it with sqlite_path")
    unknown = set(data) - set(AppConfig.__dataclass_fields__)
    if unknown:
        raise ValueError(f"Unknown configuration settings: {', '.join(sorted(map(str, unknown)))}")
    if "config_path" in data and (
        type(data["config_path"]) is not str
        or not data["config_path"].strip()
        or "\0" in data["config_path"]
    ):
        raise ValueError("config_path must be a nonempty path string without NUL characters")
    return AppConfig(**{**data, "config_path": config_path})


def load_config(path: str | Path | None = None) -> AppConfig:
    selected_path = path if path is not None else os.environ.get("IPMAN_CONFIG", "./ipman-config.yml")
    if not str(selected_path).strip() or "\0" in str(selected_path):
        raise ValueError("config_path must be a nonempty path without NUL characters")
    config_path = Path(selected_path)
    yaml = YAML(typ="safe")
    if not config_path.exists():
        return AppConfig(config_path=str(config_path))
    with config_path.open("r", encoding="utf-8") as handle:
        data = yaml.load(handle)
    return _coerce_config(data, str(config_path))


def save_config(config: AppConfig, path: str | Path | None = None) -> None:
    config.validate()
    selected_path = path if path is not None else config.config_path
    if not str(selected_path).strip() or "\0" in str(selected_path):
        raise ValueError("config_path must be a nonempty path without NUL characters")
    out_path = Path(selected_path)
    # Validate the actual destination too, without changing the caller's settings.
    AppConfig(**{**asdict(config), "config_path": str(out_path)})
    yaml = YAML()
    yaml.default_flow_style = False
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        yaml.dump(asdict(config), handle)
