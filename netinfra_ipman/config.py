from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML


@dataclass
class AppConfig:
    netinfra_path: str = "./NetInfra.yml"
    config_path: str = "./ipman-config.yml"
    admin_file: str = "./ipman-admin.yml"
    audit_log_file: str = "./ipman-audit.log"
    audit_to_file: bool = True
    audit_to_syslog: bool = False
    redis_url: str = "redis://localhost:6379/0"
    scan_concurrency: int = 128
    ping_timeout: float = 1.0
    dns_timeout: float = 2.0
    dns_lifetime: float = 2.0
    dns_servers: list[str] = field(default_factory=list)
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


def _coerce_config(data: dict[str, Any]) -> AppConfig:
    allowed = set(AppConfig.__dataclass_fields__)
    return AppConfig(**{k: v for k, v in data.items() if k in allowed})


def load_config(path: str | Path | None = None) -> AppConfig:
    env_path = Path(path or "./ipman-config.yml")
    yaml = YAML()
    if not env_path.exists():
        cfg = AppConfig(config_path=str(env_path))
        save_config(cfg, env_path)
        return cfg
    with env_path.open("r", encoding="utf-8") as handle:
        data = yaml.load(handle) or {}
    cfg = _coerce_config(data)
    cfg.config_path = str(env_path)
    return cfg


def save_config(config: AppConfig, path: str | Path | None = None) -> None:
    yaml = YAML()
    yaml.default_flow_style = False
    out_path = Path(path or config.config_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        yaml.dump(asdict(config), handle)
