from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from ipaddress import IPv4Network, ip_address, ip_network
import math
import os
from pathlib import Path
import re
import tempfile
from urllib.parse import urlsplit
from typing import Any, get_type_hints

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError


SECRET_FIELDS = frozenset({"oidc_client_secret"})
_ROLES = frozenset({"viewer", "editor", "administrator"})
_CLAIM_PATH = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*")


def _validate_oidc_url(name: str, value: str) -> None:
    try:
        parsed = urlsplit(value)
        port = parsed.port
        host = parsed.hostname
    except ValueError:
        raise ValueError(f"{name} must be a valid HTTPS URL") from None
    if (
        not host or parsed.username is not None or parsed.password is not None
        or parsed.fragment or any(character.isspace() for character in value)
        or "\\" in value or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError(f"{name} must be a valid HTTPS URL without credentials or fragment")
    loopback = host.lower() == "localhost"
    try:
        loopback = loopback or ip_address(host).is_loopback
    except ValueError:
        pass
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise ValueError(f"{name} requires HTTPS (HTTP is allowed only on loopback)")
    if name == "oidc_issuer" and parsed.query:
        raise ValueError("oidc_issuer must not contain a query")


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
    allow_anonymous_viewing: bool = False
    session_cookie_secure: bool = True
    trusted_proxies: list[str] = field(default_factory=list)
    audit_max_bytes: int = 10 * 1024 * 1024
    audit_backup_count: int = 5
    oidc_enabled: bool = False
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = ""
    oidc_groups_claim: str = "groups"
    oidc_roles_claim: str = "roles"
    oidc_group_role_map: dict[str, str] = field(default_factory=dict)
    oidc_claim_role_map: dict[str, str] = field(default_factory=dict)

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
            elif annotation == dict[str, str]:
                valid = isinstance(value, dict) and all(
                    type(key) is str and type(item) is str for key, item in value.items()
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
            "lockout_minutes",
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
            except ValueError:
                raise ValueError("dns_servers contains an invalid IP address") from None
        for cidr, servers in self.subnet_dns_servers.items():
            try:
                network = ip_network(cidr, strict=True)
            except ValueError:
                raise ValueError("subnet_dns_servers has an invalid canonical CIDR") from None
            if not isinstance(network, IPv4Network) or str(network) != cidr:
                raise ValueError("subnet_dns_servers keys must be canonical IPv4 CIDRs")
            for server in servers:
                try:
                    ip_address(server)
                except ValueError:
                    raise ValueError("subnet_dns_servers contains an invalid resolver IP") from None

        for name, lower, upper in (
            ("audit_max_bytes", 1024, 1024 * 1024 * 1024),
            ("audit_backup_count", 1, 100),
            ("session_timeout_minutes", 1, 10080),
            ("lockout_attempts", 1, 100),
            ("lockout_minutes", 1, 10080),
        ):
            if not lower <= getattr(self, name) <= upper:
                raise ValueError(f"{name} must be between {lower} and {upper}")
        for proxy in self.trusted_proxies:
            try:
                ip_network(proxy, strict=True)
            except ValueError:
                raise ValueError("trusted_proxies must contain IP addresses or canonical CIDRs") from None
        for name in ("oidc_groups_claim", "oidc_roles_claim"):
            if not _CLAIM_PATH.fullmatch(getattr(self, name)):
                raise ValueError(f"{name} must be a dotted claim path")
        for name in ("oidc_group_role_map", "oidc_claim_role_map"):
            if any(not key.strip() or role not in _ROLES for key, role in getattr(self, name).items()):
                raise ValueError(f"{name} requires nonempty claim values mapped to viewer/editor/administrator")
        for name in ("oidc_issuer", "oidc_redirect_uri"):
            if getattr(self, name):
                _validate_oidc_url(name, getattr(self, name))
        if self.oidc_enabled:
            for name in ("oidc_issuer", "oidc_client_id", "oidc_redirect_uri"):
                if not getattr(self, name).strip():
                    raise ValueError(f"{name} is required when oidc_enabled")
            if not (self.oidc_group_role_map or self.oidc_claim_role_map):
                raise ValueError("oidc_enabled requires a nonempty role mapping")

        protected = ("netinfra_path", "config_path", "admin_file", "audit_log_file", "sqlite_path")
        for index, name in enumerate(protected):
            path = Path(getattr(self, name)).resolve()
            for other in protected[index + 1:]:
                other_path = Path(getattr(self, other)).resolve()
                if path == other_path or (
                    path.exists() and other_path.exists() and path.samefile(other_path)
                ):
                    raise ValueError(f"{name} and {other} must be separate files")


def _coerce_config(data: Any, config_path: str) -> AppConfig:
    if not isinstance(data, Mapping):
        raise ValueError("Configuration must be a YAML mapping of setting names to values")
    if "redis_url" in data:
        raise ValueError("redis_url is no longer supported; replace it with sqlite_path")
    retired = [
        name for name in data
        if isinstance(name, str) and (
            name.startswith(("keycloak_", "duo_")) or name in {"tls_enabled", "reverse_proxy", "rate_limit_per_minute"}
        )
    ]
    if retired:
        raise ValueError(
            "Retired authentication/proxy settings: " + ", ".join(sorted(retired))
            + "; migrate to oidc_*, session_cookie_secure and trusted_proxies; configure request limits and TLS at your proxy"
        )
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
    try:
        with config_path.open("r", encoding="utf-8") as handle:
            data = yaml.load(handle)
    except YAMLError:
        raise ValueError("Configuration must be valid YAML") from None
    return _coerce_config(data, str(config_path))


def public_settings(config: AppConfig) -> dict[str, Any]:
    """Settings safe to render; secrets never cross the public boundary."""
    secrets = [getattr(config, name) for name in SECRET_FIELDS if getattr(config, name)]

    def redact(value: Any) -> Any:
        if isinstance(value, str):
            for secret in secrets:
                value = value.replace(secret, "[REDACTED]")
            return value
        if isinstance(value, dict):
            return {redact(key): redact(item) for key, item in value.items()}
        if isinstance(value, list):
            return [redact(item) for item in value]
        return value

    return redact({name: value for name, value in asdict(config).items() if name not in SECRET_FIELDS})


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
    out_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".ipman-config-", dir=out_path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            yaml.dump(asdict(config), handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, out_path)
    finally:
        Path(temporary).unlink(missing_ok=True)
