import asyncio
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from http.cookies import SimpleCookie
import json
import stat
import sys
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Response
from starlette.requests import Request

from netinfra_ipman.config import AppConfig
from netinfra_ipman.persistence import RuntimeStore
from netinfra_ipman import security
from netinfra_ipman.security import (
    COOKIE_NAME, Principal, Role, SecurityManager, authenticate, change_password,
    create_admin, require_admin, require_editor, require_user, require_viewer, verify_csrf,
)


PASSWORD = "old-password-1234"
NEW_PASSWORD = "new-password-5678"


@pytest.fixture
def environment(tmp_path, monkeypatch):
    config = AppConfig(admin_file=str(tmp_path / "admin.yml"), sqlite_path=str(tmp_path / "runtime.db"),
                       session_cookie_secure=False, audit_log_file=str(tmp_path / "audit.log"))
    clock = [1000000.0]
    monkeypatch.setattr(security.time, "time", lambda: clock[0])
    store = RuntimeStore(config.sqlite_path)
    store.initialize()
    manager = SecurityManager(config, store)
    yield config, store, manager, clock
    store.close()


def request(manager, token=None, method="GET", headers=None, body=b""):
    raw_headers = [(key.lower().encode(), value.encode()) for key, value in (headers or {}).items()]
    if token is not None:
        raw_headers.append((b"cookie", f"{COOKIE_NAME}={token}".encode()))
    app = SimpleNamespace(state=SimpleNamespace(services=SimpleNamespace(security=manager)))
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request({"type": "http", "method": method, "path": "/test", "headers": raw_headers,
                    "query_string": b"", "app": app, "client": ("127.0.0.1", 1)}, receive)


def cookie(response):
    parsed = SimpleCookie()
    parsed.load(response.headers["set-cookie"])
    return parsed[COOKIE_NAME].value


def login(manager, principal):
    response = Response()
    manager.login(response, principal)
    return cookie(response)


def local(environment, must_change=False):
    config, _, _, _ = environment
    create_admin(config, "admin", PASSWORD, must_change=must_change)
    return authenticate(config, "admin", PASSWORD)


def assert_denied(dependency, req, status):
    with pytest.raises(HTTPException) as exc:
        asyncio.run(dependency(req))
    assert exc.value.status_code == status


def test_unsigned_legacy_and_forged_cookies_never_authenticate(environment):
    _, _, manager, _ = environment
    for forged in ("admin", "A" * 43, "x" * 1000, "bad!cookie"):
        assert manager.current_user(request(manager, forged)) is None
        assert manager.browser_binding(request(manager, forged)) is None
    legacy = request(manager, headers={"cookie": "ipman_user=admin"})
    assert manager.current_user(legacy) is None
    assert_denied(require_user, legacy, 401)


def test_preauth_is_durable_but_never_a_principal_and_expires_absolutely(environment):
    config, store, manager, clock = environment
    csrf, token = manager.prepare_login(request(manager))
    assert token and len(token) == 43 and csrf != token
    req = request(manager, token)
    assert manager.prepare_login(req) == (csrf, None)
    assert manager.current_user(req) is None
    assert_denied(require_user, req, 401)
    assert manager.browser_binding(req) == manager._hash(token)
    store.close()
    store.initialize()
    assert SecurityManager(config, store).csrf_token(req) == csrf
    clock[0] += 600
    assert manager.csrf_token(req) == ""
    assert manager.browser_binding(req) is None


def test_login_rotation_logout_and_absolute_expiry(environment):
    config, store, manager, clock = environment
    principal = local(environment)
    _, preauth = manager.prepare_login(request(manager))
    old_request = request(manager, preauth)
    response = Response()
    manager.revoke(old_request)
    manager.login(response, principal)
    token = cookie(response)
    assert token != preauth
    assert manager.browser_binding(old_request) is None
    authenticated = request(manager, token)
    assert manager.current_user(authenticated) == principal
    assert token not in json.dumps(store.get_session(manager._hash(token), clock[0]))
    assert "password_hash" not in json.dumps(store.get_session(manager._hash(token), clock[0]))
    clock[0] += config.session_timeout_minutes * 60 - 1
    assert manager.current_user(authenticated) == principal
    clock[0] += 1
    assert manager.current_user(authenticated) is None
    token = login(manager, principal)
    response = Response()
    manager.logout(request(manager, token), response)
    assert manager.current_user(request(manager, token)) is None
    assert cookie(response) == ""
    assert "HttpOnly" in response.headers["set-cookie"]
    assert "SameSite=lax" in response.headers["set-cookie"]
    assert "Path=/" in response.headers["set-cookie"]


def test_secure_cookie_creation_and_deletion_match(environment):
    config, _, manager, _ = environment
    config.session_cookie_secure = True
    principal = local(environment)
    response = Response()
    manager.login(response, principal)
    assert "Secure" in response.headers["set-cookie"]
    deletion = Response()
    manager.logout(request(manager, cookie(response)), deletion)
    for attribute in ("Secure", "HttpOnly", "SameSite=lax", "Path=/"):
        assert attribute in deletion.headers["set-cookie"]


def test_csrf_is_bound_to_verified_browser_session_and_all_unsafe_methods(environment):
    _, _, manager, _ = environment
    csrf, token = manager.prepare_login(request(manager))
    other_csrf, other = manager.prepare_login(request(manager))
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        asyncio.run(verify_csrf(request(manager, token, method, {"X-CSRF-Token": csrf})))
        for wrong in (None, "", other_csrf, token, "é"):
            headers = {} if wrong is None else {"X-CSRF-Token": wrong}
            assert_denied(verify_csrf, request(manager, token, method, headers), 403)
    assert_denied(verify_csrf, request(manager, other, "POST", {"X-CSRF-Token": csrf}), 403)
    assert_denied(verify_csrf, request(manager, None, "POST", {"X-CSRF-Token": csrf}), 403)
    asyncio.run(verify_csrf(request(manager, token, "POST", {"Content-Type": "application/x-www-form-urlencoded"},
                                    f"csrf_token={csrf}".encode())))
    for method in ("GET", "HEAD", "OPTIONS"):
        asyncio.run(verify_csrf(request(manager, method=method)))
    manager.revoke(request(manager, token))
    assert_denied(verify_csrf, request(manager, token, "POST", {"X-CSRF-Token": csrf}), 403)


@pytest.mark.parametrize("role", list(Role))
def test_role_permissions_for_oidc_principals(environment, role):
    config, _, manager, _ = environment
    config.oidc_enabled = True
    principal = Principal("https://id.example|123", "alice", role, "oidc")
    req = request(manager, login(manager, principal))
    assert asyncio.run(require_user(req)) == principal
    assert asyncio.run(require_viewer(req)) == principal
    if role in (Role.editor, Role.administrator):
        assert asyncio.run(require_editor(req)) == principal
    else:
        assert_denied(require_editor, req, 403)
    if role == Role.administrator:
        assert asyncio.run(require_admin(req)) == principal
    else:
        assert_denied(require_admin, req, 403)


def test_anonymous_default_deny_and_explicit_read_only_opt_in(environment):
    config, _, manager, _ = environment
    _, token = manager.prepare_login(request(manager))
    req = request(manager, token)
    assert_denied(require_viewer, req, 401)
    config.allow_anonymous_viewing = True
    assert asyncio.run(require_viewer(req)) is None
    for dependency in (require_user, require_editor, require_admin):
        assert_denied(dependency, req, 401)


def test_forced_password_change_blocks_every_privileged_view_and_revokes_old_sessions(environment):
    config, _, manager, _ = environment
    principal = local(environment, must_change=True)
    token = login(manager, principal)
    req = request(manager, token)
    assert asyncio.run(require_user(req)) == principal
    for dependency in (require_viewer, require_editor, require_admin):
        assert_denied(dependency, req, 403)
    assert not principal.can_edit and not principal.is_admin
    with pytest.raises(HTTPException) as exc:
        change_password(config, principal, "wrong", NEW_PASSWORD)
    assert exc.value.status_code == 403
    updated = change_password(config, principal, PASSWORD, NEW_PASSWORD)
    assert updated.credential_version != principal.credential_version
    assert updated.is_admin and not updated.must_change_password
    assert manager.current_user(req) is None
    assert authenticate(config, "admin", PASSWORD) is None
    assert authenticate(config, "admin", NEW_PASSWORD) == updated
    assert manager.current_user(request(manager, login(manager, updated))) == updated
    with pytest.raises(HTTPException) as exc:
        change_password(config, principal, NEW_PASSWORD, "yet-another-password")
    assert exc.value.status_code == 401


def test_recovery_reset_invalidates_sessions_and_inflight_verified_principal(environment):
    config, _, manager, _ = environment
    principal = local(environment)
    token = login(manager, principal)
    create_admin(config, "admin", NEW_PASSWORD, must_change=True)
    assert manager.current_user(request(manager, token)) is None
    with pytest.raises(ValueError, match="Invalid authenticated principal"):
        manager.login(Response(), principal)
    assert authenticate(config, "admin", PASSWORD) is None
    assert authenticate(config, "admin", NEW_PASSWORD).must_change_password
    assert stat.S_IMODE(Path(config.admin_file).stat().st_mode) == 0o600


def test_local_lockout_is_serialized_and_recovers_after_expiry(environment):
    config, _, _, clock = environment
    local(environment)
    config.lockout_attempts = 4
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(lambda _: authenticate(config, "admin", "wrong"), range(4))) == [None] * 4
    with pytest.raises(HTTPException) as exc:
        authenticate(config, "admin", PASSWORD)
    assert exc.value.status_code == 423
    clock[0] += config.lockout_minutes * 60
    assert authenticate(config, "admin", PASSWORD).username == "admin"
    assert authenticate(config, "admin", "wrong") is None
    assert authenticate(config, "admin", PASSWORD) is not None
    assert authenticate(config, "not-admin", PASSWORD) is None


@pytest.mark.parametrize("mutation", [
    {"username": ""}, {"username": ["alice"]}, {"subject": "a\nlog"}, {"role": "root"},
    {"role": []}, {"auth_method": "anonymous"}, {"must_change_password": 0},
    {"credential_version": {"bad": True}}, {"password_hash": "secret"},
])
def test_malformed_stored_principal_fails_closed(environment, mutation):
    config, store, manager, clock = environment
    config.oidc_enabled = True
    principal = Principal("issuer|sub", "alice", Role.viewer, "oidc")
    token = login(manager, principal)
    payload = store.get_session(manager._hash(token), clock[0])
    payload["principal"].update(mutation)
    store.save_session(manager._hash(token), payload, clock[0] + 30)
    assert manager.current_user(request(manager, token)) is None
    assert manager.browser_binding(request(manager, token)) is None


def test_oidc_policy_changes_invalidate_sessions_after_restart(environment):
    config, store, manager, _ = environment
    config.oidc_enabled = True
    config.oidc_group_role_map = {"operators": "editor"}
    principal = Principal("issuer|sub", "alice", Role.editor, "oidc")
    token = login(manager, principal)
    store.close()
    store.initialize()
    assert SecurityManager(config, store).current_user(request(manager, token)) == principal
    config.oidc_group_role_map = {"operators": "viewer"}
    assert SecurityManager(config, store).current_user(request(manager, token)) is None
    token = login(manager, principal)
    config.oidc_enabled = False
    assert manager.current_user(request(manager, token)) is None


def test_cli_requires_explicit_recovery_and_protects_password(environment, monkeypatch):
    config, _, manager, _ = environment
    principal = local(environment)
    token = login(manager, principal)
    monkeypatch.setenv("IPMAN_CONFIG", "/selected/config.yml")
    selected = []
    monkeypatch.setattr(security, "load_config", lambda path: selected.append(path) or config)
    monkeypatch.setattr(sys, "argv", ["netinfra-ipman-init"])
    with pytest.raises(SystemExit, match="--replace"):
        security.init_admin_cli()
    assert authenticate(config, "admin", PASSWORD) is not None
    monkeypatch.setattr(sys, "argv", ["netinfra-ipman-init", "--replace"])
    answers = iter(["admin", "CANCEL"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    with pytest.raises(SystemExit, match="cancelled"):
        security.init_admin_cli()
    answers = iter(["admin", "REPLACE"])
    passwords = iter([NEW_PASSWORD, NEW_PASSWORD])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    monkeypatch.setattr(security.getpass, "getpass", lambda _: next(passwords))
    security.init_admin_cli()
    assert selected == ["/selected/config.yml"] * 3
    assert manager.current_user(request(manager, token)) is None
    assert authenticate(config, "admin", NEW_PASSWORD).must_change_password
    event = json.loads(Path(config.audit_log_file).read_text().splitlines()[-1])
    assert event["action"] == "admin_recovery"
    assert event["user"] == "cli" and event["source_ip"] == "local"
    assert NEW_PASSWORD not in json.dumps(event) and PASSWORD not in json.dumps(event)


@pytest.mark.parametrize("password,confirmation", [("short", "short"), (NEW_PASSWORD, "different")])
def test_cli_rejects_invalid_password_without_provisioning(environment, monkeypatch, password, confirmation):
    config, _, _, _ = environment
    monkeypatch.setattr(security, "load_config", lambda _: config)
    monkeypatch.setattr(sys, "argv", ["netinfra-ipman-init"])
    monkeypatch.setattr("builtins.input", lambda _: "admin")
    passwords = iter([password, confirmation])
    monkeypatch.setattr(security.getpass, "getpass", lambda _: next(passwords))
    with pytest.raises(SystemExit):
        security.init_admin_cli()
    assert not security.admin_exists(config)


def test_cli_first_provisioning_requires_password_change_and_does_not_echo_secrets(environment, monkeypatch, capsys):
    config, _, manager, _ = environment
    monkeypatch.setattr(security, "load_config", lambda _: config)
    monkeypatch.setattr(sys, "argv", ["netinfra-ipman-init"])
    monkeypatch.setattr("builtins.input", lambda _: "admin")
    passwords = iter([PASSWORD, PASSWORD])
    monkeypatch.setattr(security.getpass, "getpass", lambda _: next(passwords))
    security.init_admin_cli()
    principal = authenticate(config, "admin", PASSWORD)
    assert principal.must_change_password
    token = login(manager, principal)
    assert_denied(require_admin, request(manager, token), 403)
    output = capsys.readouterr()
    assert PASSWORD not in output.out + output.err
    assert "password_hash" not in output.out + output.err
    assert stat.S_IMODE(Path(config.admin_file).stat().st_mode) == 0o600
    event = json.loads(Path(config.audit_log_file).read_text().splitlines()[-1])
    assert event["action"] == "admin_provision"
    assert event["user"] == "cli" and event["source_ip"] == "local"
    assert PASSWORD not in json.dumps(event) and "password_hash" not in json.dumps(event)


def test_short_password_rejected_before_credential_replacement(environment):
    config, _, _, _ = environment
    principal = local(environment)
    with pytest.raises(ValueError, match="12 characters"):
        create_admin(config, "admin", "short")
    with pytest.raises(ValueError, match="12 characters"):
        change_password(config, principal, PASSWORD, "short")
    assert authenticate(config, "admin", PASSWORD) == principal


@pytest.mark.parametrize("malformed", ["false", [], None])
def test_malformed_forced_change_metadata_denies_existing_and_new_local_sessions(environment, malformed):
    config, _, manager, _ = environment
    principal = local(environment)
    token = login(manager, principal)
    data = security._read_admin(config.admin_file)
    data["must_change_password"] = malformed
    with security._admin_lock(config.admin_file):
        security._write_admin(config.admin_file, data)
    assert manager.current_user(request(manager, token)) is None
    assert authenticate(config, "admin", PASSWORD) is None
