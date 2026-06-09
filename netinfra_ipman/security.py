from __future__ import annotations

import getpass
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import HTTPException, Request, Response, status
from passlib.context import CryptContext
from ruamel.yaml import YAML

from .config import AppConfig, load_config

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
yaml = YAML()
yaml.default_flow_style = False


@dataclass
class UserState:
    username: str
    must_change_password: bool = False
    locked_until: str | None = None
    failed_attempts: int = 0


def _read_admin(path: str | Path) -> dict[str, Any]:
    admin_path = Path(path)
    if not admin_path.exists():
        return {}
    with admin_path.open("r", encoding="utf-8") as handle:
        return yaml.load(handle) or {}


def _write_admin(path: str | Path, data: dict[str, Any]) -> None:
    admin_path = Path(path)
    admin_path.parent.mkdir(parents=True, exist_ok=True)
    with admin_path.open("w", encoding="utf-8") as handle:
        yaml.dump(data, handle)
    admin_path.chmod(0o600)


def admin_exists(config: AppConfig) -> bool:
    return bool(_read_admin(config.admin_file).get("password_hash"))


def create_admin(config: AppConfig, username: str, password: str, must_change: bool = True) -> None:
    _write_admin(
        config.admin_file,
        {
            "username": username,
            "password_hash": pwd_context.hash(password),
            "must_change_password": must_change,
            "failed_attempts": 0,
            "locked_until": None,
        },
    )


def ensure_bootstrap_admin(config: AppConfig) -> str | None:
    if admin_exists(config):
        return None
    password = secrets.token_urlsafe(18)
    create_admin(config, "admin", password, must_change=True)
    return password


def authenticate(config: AppConfig, username: str, password: str) -> UserState | None:
    data = _read_admin(config.admin_file)
    if not data or username != data.get("username"):
        return None
    locked_until = data.get("locked_until")
    if locked_until and datetime.fromisoformat(locked_until) > datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_423_LOCKED, detail="Account locked")
    if not pwd_context.verify(password, data.get("password_hash", "")):
        attempts = int(data.get("failed_attempts") or 0) + 1
        data["failed_attempts"] = attempts
        if attempts >= config.lockout_attempts:
            data["locked_until"] = (datetime.now(timezone.utc) + timedelta(minutes=config.lockout_minutes)).isoformat()
        _write_admin(config.admin_file, data)
        return None
    data["failed_attempts"] = 0
    data["locked_until"] = None
    _write_admin(config.admin_file, data)
    return UserState(username=username, must_change_password=bool(data.get("must_change_password")))


def change_password(config: AppConfig, username: str, password: str) -> None:
    data = _read_admin(config.admin_file)
    if username != data.get("username"):
        raise HTTPException(status_code=404, detail="User not found")
    data["password_hash"] = pwd_context.hash(password)
    data["must_change_password"] = False
    _write_admin(config.admin_file, data)


def login_response(response: Response, config: AppConfig, username: str) -> None:
    response.set_cookie(
        "ipman_user",
        username,
        httponly=True,
        samesite="lax",
        max_age=config.session_timeout_minutes * 60,
    )


def logout_response(response: Response) -> None:
    response.delete_cookie("ipman_user")


def current_user(request: Request) -> str | None:
    return request.cookies.get("ipman_user")


def require_user(request: Request) -> str:
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Login required")
    return user


def init_admin_cli() -> None:
    cfg = load_config()
    username = input("Admin username [admin]: ").strip() or "admin"
    password = getpass.getpass("Admin password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        raise SystemExit("Passwords do not match")
    create_admin(cfg, username, password, must_change=True)
    print(f"Admin account '{username}' written to {cfg.admin_file}")
