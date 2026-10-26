from __future__ import annotations

import hashlib
from http.cookies import SimpleCookie
from pathlib import Path
import re
import secrets
import time

from fastapi import Response
from fastapi.testclient import TestClient
import httpx
import pytest

from netinfra_ipman.config import AppConfig, load_config
from netinfra_ipman.main import create_app
from netinfra_ipman.security import COOKIE_NAME, Principal, Role, create_admin


@pytest.fixture
def environment(tmp_path, monkeypatch):
    config = AppConfig(
        config_path=str(tmp_path / 'settings.yml'), netinfra_path=str(tmp_path / 'NetInfra.yml'),
        admin_file=str(tmp_path / 'admin.yml'), sqlite_path=str(tmp_path / 'runtime.sqlite3'),
        audit_log_file=str(tmp_path / 'audit.log'), oidc_enabled=True,
        oidc_issuer='https://idp.example', oidc_client_id='client',
        oidc_client_secret=secrets.token_urlsafe(32), oidc_redirect_uri='https://testserver.local/oidc/callback',
        oidc_group_role_map={'readers': 'viewer', 'operators': 'editor', 'admins': 'administrator'},
    )
    Path(config.netinfra_path).write_text('subnets:\n  - cidr: 192.0.2.1/32\nHosts:\n  - Name: known\n    Records:\n      - Target: 192.0.2.1\n        RRType: no_dns\n')

    def forbidden_probe(*args, **kwargs):
        raise AssertionError('Unexpected network probe')

    async def forbidden_provider(*args, **kwargs):
        raise AssertionError('Unexpected identity-provider request')

    monkeypatch.setattr('netinfra_ipman.checks.check_ping', forbidden_probe)
    monkeypatch.setattr('netinfra_ipman.scanner.check_ping', forbidden_probe)
    monkeypatch.setattr(httpx.AsyncClient, 'request', forbidden_provider)
    app = create_app(config)
    with TestClient(app, base_url='https://testserver.local') as client:
        yield config, app, client


def csrf(client):
    response = client.get('/login')
    assert response.status_code == 200
    return re.search(r'name="csrf_token" value="([^"]+)"', response.text).group(1)


def sign_in(app, client, role):
    def issue():
        response = Response()
        app.state.services.security.login(response, Principal('https://idp.example|person', 'operator', role, 'oidc'))
        return response.headers['set-cookie']

    parsed = SimpleCookie()
    parsed.load(client.portal.call(issue))
    client.cookies.set(COOKIE_NAME, parsed[COOKIE_NAME].value, domain='testserver.local', path='/')
    return csrf(client)


MUTATIONS = [
    ('/refresh', {'subnet': '192.0.2.1/32'}),
    ('/scan', {'subnet': '192.0.2.1/32'}),
    ('/scan/unknown/cancel', {}),
    ('/hosts/preview', {'operation': 'create'}),
    ('/hosts/apply', {'token': 'unreviewed'}),
    ('/options', {'scan_concurrency': '2'}),
]


@pytest.mark.parametrize('anonymous', [False, True])
def test_anonymous_view_setting_never_authorizes_probes_or_writes(environment, anonymous):
    config, app, client = environment
    app.state.services.config.allow_anonymous_viewing = anonymous
    before = Path(config.netinfra_path).read_bytes()
    token = csrf(client)
    client.cookies.set('ipman_user', 'admin')
    for path in ['/', '/outliers', '/hosts/0']:
        assert client.get(path).status_code == (200 if anonymous else 401)
    for path in ['/options', '/audit', '/add?ip=192.0.2.1']:
        assert client.get(path).status_code == 401
    for path, body in MUTATIONS:
        assert client.post(path, data={**body, 'csrf_token': token}, follow_redirects=False).status_code == 401
    assert Path(config.netinfra_path).read_bytes() == before
    assert client.portal.call(app.state.services.store.list_jobs) == []
    assert config.oidc_client_secret not in client.get('/login').text


@pytest.mark.parametrize('path,body', MUTATIONS + [
    ('/login', {'username': 'admin', 'password': 'not-an-actual-credential'}),
    ('/oidc/login', {}), ('/logout', {}),
    ('/change-password', {'current_password': 'irrelevant', 'password': 'irrelevant', 'confirm_password': 'irrelevant'}),
])
def test_every_unsafe_route_rejects_missing_or_cross_browser_csrf(environment, path, body):
    config, app, client = environment
    token = sign_in(app, client, Role.administrator)
    before = Path(config.netinfra_path).read_bytes()
    for bad_token in [None, secrets.token_hex(32)]:
        data = dict(body)
        if bad_token is not None:
            data['csrf_token'] = bad_token
        response = client.post(path, data=data, follow_redirects=False)
        assert response.status_code == 403
    assert Path(config.netinfra_path).read_bytes() == before
    assert client.portal.call(app.state.services.store.list_jobs) == []
    assert client.get('/').status_code == 200
    assert token not in Path(config.audit_log_file).read_text()


def test_viewer_cannot_bypass_hidden_editor_or_administrator_controls(environment):
    config, app, client = environment
    token = sign_in(app, client, Role.viewer)
    before = Path(config.netinfra_path).read_bytes()
    for path in ['/', '/outliers', '/hosts/0']:
        assert client.get(path).status_code == 200
    for path in ['/options', '/audit', '/add?ip=192.0.2.1']:
        assert client.get(path).status_code == 403
    for path, body in MUTATIONS:
        assert client.post(path, data={**body, 'csrf_token': token}, follow_redirects=False).status_code == 403
    assert Path(config.netinfra_path).read_bytes() == before
    assert client.portal.call(app.state.services.store.list_jobs) == []


@pytest.mark.parametrize('role', [Role.editor, Role.administrator])
def test_editor_permissions_collect_evidence_but_settings_and_audit_require_admin(environment, monkeypatch, role):
    config, app, client = environment
    token = sign_in(app, client, role)
    monkeypatch.setattr('netinfra_ipman.checks.check_ping', lambda *args: (True, 1.0, None))
    response = client.post('/refresh', data={'subnet': '192.0.2.1/32', 'csrf_token': token}, follow_redirects=False)
    assert response.status_code == 303
    evidence = client.portal.call(app.state.services.store.get, 'observation:192.0.2.1')
    assert evidence['ping_ok'] is True
    assert evidence['dns'] == {}
    assert evidence['source_revision'] == hashlib.sha256(Path(config.netinfra_path).read_bytes()).hexdigest()
    assert client.get('/add?ip=192.0.2.1').status_code == 200
    expected = 200 if role == Role.administrator else 403
    for path in ['/options', '/audit']:
        page = client.get(path)
        assert page.status_code == expected
        assert config.oidc_client_secret not in page.text
    if role == Role.editor:
        assert client.post('/options', data={'scan_concurrency': '2', 'csrf_token': token}).status_code == 403


@pytest.mark.parametrize('value', ['invalid', '-1'])
def test_rejected_admin_settings_preserve_running_and_saved_configuration(environment, value):
    config, app, client = environment
    token = sign_in(app, client, Role.administrator)
    response = client.post('/options', data={'scan_concurrency': value, 'csrf_token': token})
    assert response.status_code == 400
    assert app.state.services.config.scan_concurrency == config.scan_concurrency
    assert not Path(config.config_path).exists()


def test_administrator_can_toggle_anonymous_viewing_without_exposing_or_overwriting_secrets(environment):
    config, app, client = environment
    token = sign_in(app, client, Role.administrator)
    for enabled, expected in [('on', 200), ('off', 401)]:
        response = client.post('/options', data={'allow_anonymous_viewing': enabled, 'csrf_token': token}, follow_redirects=False)
        assert response.status_code == 303
        assert client.get('/', headers={'cookie': ''}).status_code == expected
        assert load_config(config.config_path).oidc_client_secret == config.oidc_client_secret
    assert config.oidc_client_secret not in client.get('/options').text
    assert config.oidc_client_secret not in Path(config.audit_log_file).read_text()
    assert 'config_change' in Path(config.audit_log_file).read_text()


@pytest.mark.parametrize('field,value', [('sqlite_path', '/other/runtime.sqlite3'), ('oidc_client_secret', 'must-not-be-saved')])
def test_protected_configuration_changes_require_file_edit_and_restart(environment, field, value):
    config, app, client = environment
    token = sign_in(app, client, Role.administrator)
    assert client.post('/options', data={field: value, 'csrf_token': token}).status_code == 400
    assert getattr(app.state.services.config, field) == getattr(config, field)
    assert not Path(config.config_path).exists()


def test_expired_and_logged_out_sessions_cannot_be_reused(environment):
    _, app, client = environment
    token = sign_in(app, client, Role.viewer)
    raw_cookie = client.cookies.get(COOKIE_NAME)
    response = client.post('/logout', data={'csrf_token': token}, follow_redirects=False)
    assert response.status_code == 303
    client.cookies.set(COOKIE_NAME, raw_cookie, domain='testserver.local', path='/')
    assert client.get('/').status_code == 401
    sign_in(app, client, Role.viewer)
    raw_cookie = client.cookies.get(COOKIE_NAME)
    digest = hashlib.sha256(raw_cookie.encode()).hexdigest()
    store = app.state.services.store
    payload = client.portal.call(store.get_session, digest, time.time())
    client.portal.call(store.save_session, digest, payload, time.time() - 1)
    assert client.get('/').status_code == 401


def test_emergency_login_forces_password_change_and_recovery_revokes_old_session(environment):
    config, app, client = environment
    password, replacement = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    create_admin(config, 'recovery-admin', password)
    preauth = csrf(client)
    response = client.post('/login', data={'username': 'recovery-admin', 'password': password, 'csrf_token': preauth}, follow_redirects=False)
    assert response.status_code == 303 and response.headers['location'] == '/change-password'
    assert client.get('/').status_code == 403
    assert client.get('/options').status_code == 403
    token = csrf(client)
    response = client.post('/change-password', data={
        'current_password': password, 'password': replacement, 'confirm_password': replacement, 'csrf_token': token,
    }, follow_redirects=False)
    assert response.status_code == 303
    assert client.get('/options').status_code == 200
    create_admin(config, 'recovery-admin', secrets.token_urlsafe(24))
    assert client.get('/').status_code == 401
    audit = Path(config.audit_log_file).read_text()
    assert password not in audit and replacement not in audit


def test_oidc_failures_never_create_an_authenticated_session(environment):
    config, app, client = environment
    token = csrf(client)
    response = client.post('/oidc/login', data={'csrf_token': token})
    assert response.status_code == 503
    assert client.get('/').status_code == 401
    response = client.get('/oidc/callback?state=invalid&code=sensitive-code')
    assert response.status_code == 401
    assert 'sensitive-code' not in response.text
    assert config.oidc_client_secret not in response.text
    assert 'sensitive-code' not in Path(config.audit_log_file).read_text()
    assert client.get('/').status_code == 401


def test_redacted_nonsecret_settings_are_read_only_not_saved_as_masked_text(environment):
    config, app, client = environment
    sensitive_branch = "release-" + config.oidc_client_secret
    app.state.services.config.git_branch = sensitive_branch
    token = sign_in(app, client, Role.administrator)
    page = client.get('/options')
    assert config.oidc_client_secret not in page.text
    response = client.post('/options', data={'git_branch': 'release-[REDACTED]', 'csrf_token': token})
    assert response.status_code == 400
    assert app.state.services.config.git_branch == sensitive_branch
    assert not Path(config.config_path).exists()


def test_mounted_application_outcomes_keep_parent_audit_context(environment):
    import json
    from fastapi import FastAPI

    config, app, client = environment
    child = FastAPI()

    @child.post("/token")
    async def token_endpoint():
        return Response(status_code=204)

    app.mount("/provider", child)
    response = client.post("/provider/token", headers={"X-Forwarded-For": "203.0.113.99"})
    assert response.status_code == 204
    events = [json.loads(line) for line in Path(config.audit_log_file).read_text().splitlines()]
    assert events[-1]["action"] == "request_outcome"
    assert events[-1]["source_ip"] == "unknown"
