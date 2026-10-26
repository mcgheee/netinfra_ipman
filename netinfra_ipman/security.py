from __future__ import annotations

import argparse
import fcntl
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from fastapi import HTTPException, Request, Response
from passlib.context import CryptContext
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from .config import AppConfig, load_config
from .persistence import RuntimeStore

pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"], deprecated="auto",
    pbkdf2_sha256__default_rounds=600_000, pbkdf2_sha256__min_rounds=600_000,
)
_admin_mutex = threading.RLock()
COOKIE_NAME = "ipman_session"
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{43}$")


class Role(str, Enum):
    viewer = "viewer"
    editor = "editor"
    administrator = "administrator"


@dataclass(frozen=True)
class Principal:
    subject: str
    username: str
    role: Role
    auth_method: str
    must_change_password: bool = False
    credential_version: str | None = None

    @property
    def can_edit(self) -> bool:
        return not self.must_change_password and self.role in (Role.editor, Role.administrator)

    @property
    def is_admin(self) -> bool:
        return not self.must_change_password and self.role == Role.administrator


def _read_admin(path: str | Path) -> dict[str, Any]:
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            value = YAML(typ="safe").load(handle)
    except (FileNotFoundError, YAMLError):
        return {}
    return value if isinstance(value, dict) else {}


@contextmanager
def _admin_lock(path: str | Path):
    admin_path = Path(path)
    admin_path.parent.mkdir(parents=True, exist_ok=True)
    with _admin_mutex:
        descriptor = os.open(str(admin_path) + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)


def _write_admin(path: str | Path, data: dict[str, Any]) -> None:
    admin_path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix=".ipman-admin-", dir=admin_path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            YAML().dump(data, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, admin_path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _validate_password(password: str) -> None:
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError("Password must contain at least 12 characters")


def admin_exists(config: AppConfig) -> bool:
    return bool(_read_admin(config.admin_file).get("password_hash"))


def _new_admin(username: str, password: str, must_change: bool) -> dict[str, Any]:
    _validate_password(password)
    if not isinstance(username, str) or not username.strip() or any(ord(c) < 32 for c in username):
        raise ValueError("Invalid administrator username")
    return {
        "username": username, "password_hash": pwd_context.hash(password),
        "must_change_password": must_change, "credential_version": secrets.token_hex(32),
        "failed_attempts": 0, "locked_until": None,
    }


def create_admin(config: AppConfig, username: str, password: str, must_change: bool = True) -> None:
    data = _new_admin(username, password, must_change)
    with _admin_lock(config.admin_file):
        _write_admin(config.admin_file, data)


def _local_principal(data: dict[str, Any]) -> Principal:
    return Principal(subject="local:" + data["username"], username=data["username"],
                     role=Role.administrator, auth_method="local",
                     must_change_password=data.get("must_change_password") is True,
                     credential_version=data["credential_version"])


def _verify_password(password: str, encoded: Any) -> bool:
    try:
        return isinstance(encoded, str) and pwd_context.verify(password, encoded)
    except (ValueError, TypeError):
        return False


def _authenticate_locked(config: AppConfig, username: str, password: str) -> Principal | None:
    data = _read_admin(config.admin_file)
    if not data or username != data.get("username"):
        return None
    if type(data.get("must_change_password", False)) is not bool:
        return None
    now = time.time()
    locked = data.get("locked_until")
    if locked:
        try:
            expiry = datetime.fromisoformat(locked).timestamp() if isinstance(locked, str) else float(locked)
        except (ValueError, TypeError, OverflowError):
            return None
        if expiry > now:
            raise HTTPException(status_code=423, detail="Account locked")
        data["failed_attempts"] = 0
        data["locked_until"] = None
    if not _verify_password(password, data.get("password_hash")):
        attempts = data.get("failed_attempts", 0)
        data["failed_attempts"] = (attempts if type(attempts) is int else 0) + 1
        if data["failed_attempts"] >= config.lockout_attempts:
            data["locked_until"] = now + config.lockout_minutes * 60
        _write_admin(config.admin_file, data)
        return None
    data["failed_attempts"] = 0
    data["locked_until"] = None
    if pwd_context.needs_update(data["password_hash"]):
        data["password_hash"] = pwd_context.hash(password)
    # Upgrade existing credential files only after successful password verification.
    if not isinstance(data.get("credential_version"), str) or not data["credential_version"]:
        data["credential_version"] = secrets.token_hex(32)
    _write_admin(config.admin_file, data)
    return _local_principal(data)


def authenticate(config: AppConfig, username: str, password: str) -> Principal | None:
    with _admin_lock(config.admin_file):
        return _authenticate_locked(config, username, password)


def change_password(config: AppConfig, principal: Principal, current_password: str, new_password: str) -> Principal:
    _validate_password(new_password)
    with _admin_lock(config.admin_file):
        data = _read_admin(config.admin_file)
        if (principal.auth_method != "local" or principal.username != data.get("username")
                or principal.credential_version != data.get("credential_version")):
            raise HTTPException(status_code=401, detail="Credentials changed; log in again")
        verified = _authenticate_locked(config, principal.username, current_password)
        if verified is None:
            raise HTTPException(status_code=403, detail="Current password is incorrect")
        data = _read_admin(config.admin_file)
        data.update(password_hash=pwd_context.hash(new_password), must_change_password=False,
                    credential_version=secrets.token_hex(32), failed_attempts=0, locked_until=None)
        _write_admin(config.admin_file, data)
        return _local_principal(data)


def oidc_policy_fingerprint(config: AppConfig) -> str:
    policy = {name: value for name, value in vars(config).items() if name.startswith("oidc_")}
    return hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class SecurityManager:
    def __init__(self, config: AppConfig, store: RuntimeStore):
        self.config = config
        self.store = store

    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode("ascii")).hexdigest()

    def _session(self, request: Request) -> tuple[str, dict[str, Any]] | None:
        token = request.cookies.get(COOKIE_NAME, "")
        if not _TOKEN.fullmatch(token):
            return None
        payload = self.store.get_session(self._hash(token), time.time())
        if payload is None or payload.get("kind") not in ("preauth", "authenticated"):
            return None
        if payload["kind"] == "authenticated" and self._principal(payload) is None:
            self.store.delete_session(self._hash(token))
            return None
        return token, payload

    def _principal(self, payload: dict[str, Any]) -> Principal | None:
        raw = payload.get("principal")
        if not isinstance(raw, dict):
            return None
        if set(raw) != {"subject", "username", "role", "auth_method", "must_change_password", "credential_version"}:
            return None
        if any(not isinstance(raw.get(k), str) or not raw[k] or any(ord(c) < 32 for c in raw[k])
               for k in ("subject", "username")):
            return None
        if type(raw.get("must_change_password")) is not bool:
            return None
        try:
            role = Role(raw.get("role"))
        except (ValueError, TypeError):
            return None
        method = raw.get("auth_method")
        version = raw.get("credential_version")
        if method == "local":
            if not isinstance(version, str) or not version or role != Role.administrator:
                return None
            try:
                admin = _read_admin(self.config.admin_file)
            except (OSError, ValueError, TypeError):
                return None
            if type(admin.get("must_change_password", False)) is not bool:
                return None
            if (version != admin.get("credential_version") or raw["username"] != admin.get("username")
                    or raw["subject"] != "local:" + raw["username"]
                    or raw["must_change_password"] != (admin.get("must_change_password") is True)):
                return None
        elif method == "oidc":
            if (not self.config.oidc_enabled or version is not None or raw["must_change_password"]
                    or payload.get("oidc_policy") != oidc_policy_fingerprint(self.config)):
                return None
        else:
            return None
        return Principal(**{**raw, "role": role})

    def prepare_login(self, request: Request) -> tuple[str, str | None]:
        session = self._session(request)
        if session is not None:
            return self._csrf(session[0]), None
        token = secrets.token_urlsafe(32)
        self.store.purge_expired_security_state(time.time())
        self.store.save_session(self._hash(token), {"kind": "preauth"}, time.time() + 600)
        return self._csrf(token), token

    def set_cookie(self, response: Response, token: str) -> None:
        response.set_cookie(COOKIE_NAME, token, httponly=True, secure=self.config.session_cookie_secure,
                            samesite="lax", path="/", max_age=self.config.session_timeout_minutes * 60)

    def login(self, response: Response, principal: Principal) -> None:
        payload = {"kind": "authenticated", "principal": asdict(principal)}
        if principal.auth_method == "oidc":
            payload["oidc_policy"] = oidc_policy_fingerprint(self.config)
        if self._principal(payload) is None:
            raise ValueError("Invalid authenticated principal")
        token = secrets.token_urlsafe(32)
        self.store.purge_expired_security_state(time.time())
        self.store.save_session(self._hash(token), payload, time.time() + self.config.session_timeout_minutes * 60)
        self.set_cookie(response, token)

    def revoke(self, request: Request) -> None:
        token = request.cookies.get(COOKIE_NAME, "")
        if _TOKEN.fullmatch(token):
            self.store.delete_session(self._hash(token))

    def logout(self, request: Request, response: Response) -> None:
        self.revoke(request)
        response.delete_cookie(COOKIE_NAME, path="/", secure=self.config.session_cookie_secure,
                               httponly=True, samesite="lax")

    @staticmethod
    def _csrf(token: str) -> str:
        return hmac.new(token.encode("ascii"), b"ipman:csrf:v1", hashlib.sha256).hexdigest()

    def csrf_token(self, request: Request) -> str:
        session = self._session(request)
        return self._csrf(session[0]) if session is not None else ""

    def browser_binding(self, request: Request) -> str | None:
        session = self._session(request)
        return self._hash(session[0]) if session is not None else None

    def current_user(self, request: Request) -> Principal | None:
        session = self._session(request)
        return self._principal(session[1]) if session and session[1]["kind"] == "authenticated" else None


def _manager(request: Request) -> SecurityManager:
    return request.app.state.services.security


def _deny(request: Request, code: int, detail: str, principal: Principal | None = None) -> None:
    audit = getattr(request.app.state.services, "audit", None)
    if audit is not None:
        from .audit import source_ip
        audit.record(
            user=principal.subject if principal else "anonymous",
            source_ip=source_ip(request, _manager(request).config), action="access_denied",
            summary=f"{request.method} {getattr(request.scope.get('route'), 'path', 'unmatched')}",
        )
    raise HTTPException(status_code=code, detail=detail)


async def current_user(request: Request) -> Principal | None:
    return _manager(request).current_user(request)


async def require_user(request: Request) -> Principal:
    principal = _manager(request).current_user(request)
    if principal is None:
        _deny(request, 401, "Login required")
    return principal


async def require_viewer(request: Request) -> Principal | None:
    principal = _manager(request).current_user(request)
    if principal is None:
        if _manager(request).config.allow_anonymous_viewing:
            return None
        _deny(request, 401, "Login required")
    if principal.must_change_password:
        _deny(request, 403, "Password change required", principal)
    return principal


async def require_editor(request: Request) -> Principal:
    principal = await require_user(request)
    if not principal.can_edit:
        _deny(request, 403, "Editor permission required", principal)
    return principal


async def require_admin(request: Request) -> Principal:
    principal = await require_user(request)
    if not principal.is_admin:
        _deny(request, 403, "Administrator permission required", principal)
    return principal


async def verify_csrf(request: Request) -> None:
    if request.method in ("GET", "HEAD", "OPTIONS", "TRACE"):
        return
    expected = _manager(request).csrf_token(request)
    supplied = request.headers.get("X-CSRF-Token")
    if supplied is None:
        try:
            supplied = (await request.form()).get("csrf_token")
        except (ValueError, RuntimeError):
            supplied = None
    if not expected or not isinstance(supplied, str) or not hmac.compare_digest(expected.encode(), supplied.encode()):
        _deny(request, 403, "Invalid CSRF token")


def init_admin_cli() -> None:
    parser = argparse.ArgumentParser(description="Provision or explicitly recover the local administrator")
    parser.add_argument("--replace", action="store_true", help="Replace existing credentials and revoke local sessions")
    args = parser.parse_args()
    cfg = load_config(os.environ.get("IPMAN_CONFIG", "./ipman-config.yml"))
    if Path(cfg.admin_file).exists() and not args.replace:
        raise SystemExit("Administrator file exists; use --replace for explicit recovery")
    username = input("Admin username [admin]: ").strip() or "admin"
    if args.replace and input("Type REPLACE to recover/replace administrator credentials: ") != "REPLACE":
        raise SystemExit("Replacement cancelled")
    password = getpass.getpass("Admin password (at least 12 characters): ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        raise SystemExit("Passwords do not match")
    try:
        _validate_password(password)
        # Hold the lock across existence check and creation to prevent accidental replacement.
        with _admin_lock(cfg.admin_file):
            if Path(cfg.admin_file).exists() and not args.replace:
                raise SystemExit("Administrator file exists; use --replace for explicit recovery")
            _write_admin(cfg.admin_file, _new_admin(username, password, True))
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    from .audit import AuditLogger
    audit = AuditLogger(cfg)
    try:
        audit.record(
            user="cli", source_ip="local",
            action="admin_recovery" if args.replace else "admin_provision",
            summary="Local administrator credentials replaced" if args.replace else "Local administrator provisioned",
        )
    finally:
        audit.close()
    print("Administrator credentials written; password change required at first login")
