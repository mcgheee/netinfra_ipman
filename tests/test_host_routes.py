from __future__ import annotations

import hashlib
from http.cookies import SimpleCookie
import re

from fastapi import Response
from fastapi.testclient import TestClient

from netinfra_ipman.config import AppConfig
from netinfra_ipman.main import create_app
from netinfra_ipman.security import COOKIE_NAME, Principal, Role


def _csrf(client: TestClient) -> str:
    response = client.get("/login")
    assert response.status_code == 200
    return re.search(r'name="csrf_token" value="([^"]+)"', response.text).group(1)


def _sign_in(app, client: TestClient) -> str:
    def issue():
        response = Response()
        app.state.services.security.login(response, Principal("https://idp.example|editor", "editor", Role.editor, "oidc"))
        return response.headers["set-cookie"]

    parsed = SimpleCookie()
    parsed.load(client.portal.call(issue))
    client.cookies.set(COOKIE_NAME, parsed[COOKIE_NAME].value, domain="testserver.local", path="/")
    return _csrf(client)


def _config(tmp_path, *, oidc: bool = False) -> AppConfig:
    values = {
        "netinfra_path": str(tmp_path / "NetInfra.yml"),
        "config_path": str(tmp_path / "settings.yml"),
        "admin_file": str(tmp_path / "admin.yml"),
        "audit_log_file": str(tmp_path / "audit.log"),
        "sqlite_path": str(tmp_path / "runtime.sqlite3"),
        "backup_dir": str(tmp_path / "backups"),
    }
    if oidc:
        values.update({
            "oidc_enabled": True, "oidc_issuer": "https://idp.example", "oidc_client_id": "client",
            "oidc_redirect_uri": "https://testserver.local/oidc/callback",
            "oidc_group_role_map": {"editors": "editor"},
        })
    return AppConfig(**values)


def test_reviewed_host_workflow_create_edit_delete_import_and_direct_apply_rejection(tmp_path):
    netinfra = tmp_path / "NetInfra.yml"
    netinfra.write_text(
        "subnets:\n  - cidr: 192.0.2.0/24\nHosts:\n"
        "  - Name: existing\n    Records:\n      - RRType: no_dns\n        Target: 192.0.2.10\n"
    )
    config = _config(tmp_path, oidc=True)
    app = create_app(config)
    with TestClient(app, base_url="https://testserver.local") as client:
        csrf = _sign_in(app, client)
        assert client.get("/hosts").status_code == 200
        assert client.get("/hosts/0/edit").status_code == 200
        assert client.get("/import").status_code == 200

        direct = client.post("/hosts/apply", data={"csrf_token": csrf, "name": "tampered"})
        assert direct.status_code == 400
        before = netinfra.read_bytes()

        response = client.post("/hosts/preview", data={
            "csrf_token": csrf, "operation": "create", "revision": hashlib.sha256(before).hexdigest(),
            "mode": "advanced", "host_yaml": "Name: created\nRecords:\n  - RRType: no_dns\n    Target: 192.0.2.11\n",
        })
        assert response.status_code == 200
        assert "Apply reviewed change" in response.text
        match = re.search(r'name="token" value="([^"]+)"', response.text)
        assert match
        token = match.group(1)
        assert "created" not in netinfra.read_text()

        applied = client.post("/hosts/apply", data={"csrf_token": csrf, "token": token})
        assert applied.status_code == 200
        assert "File saved" in applied.text
        assert "created" in netinfra.read_text()
        assert list((tmp_path / "backups").glob("*.bak"))
        assert client.post("/hosts/apply", data={"csrf_token": csrf, "token": token}).status_code == 409

        source = netinfra.read_bytes()
        revision = hashlib.sha256(source).hexdigest()
        duplicate = client.post("/hosts/preview", data={
            "csrf_token": csrf, "operation": "import", "revision": revision,
            "host_yaml": "Hosts:\n  - Name: fresh\n    Records: [{RRType: no_dns, Target: 192.0.2.12}]\n  - Name: existing\n    Records: [{RRType: no_dns, Target: 192.0.2.13}]\n",
        })
        assert duplicate.status_code == 200
        assert "blocked by validation" in duplicate.text.lower()
        assert "existing" in duplicate.text
        assert netinfra.read_bytes() == source
        batch = client.post("/hosts/preview", data={
            "csrf_token": csrf, "operation": "import", "revision": hashlib.sha256(source).hexdigest(),
            "host_yaml": "- Name: batch-one\n  Records: [{RRType: no_dns, Target: 192.0.2.12}]\n- Name: batch-two\n  Records: [{RRType: no_dns, Target: 192.0.2.13}]\n",
        })
        assert batch.status_code == 200
        batch_token = re.search(r'name="token" value="([^"]+)"', batch.text).group(1)
        assert client.post("/hosts/apply", data={"csrf_token": csrf, "token": batch_token}).status_code == 200
        assert "batch-one" in netinfra.read_text() and "batch-two" in netinfra.read_text()

        updated_source = netinfra.read_bytes()
        update = client.post("/hosts/preview", data={
            "csrf_token": csrf, "operation": "update", "revision": hashlib.sha256(updated_source).hexdigest(),
            "host_index": "0", "mode": "common", "name": "renamed", "target": "192.0.2.10", "rrtype": "no_dns",
        })
        update_token = re.search(r'name="token" value="([^"]+)"', update.text).group(1)
        assert client.post("/hosts/apply", data={"csrf_token": csrf, "token": update_token}).status_code == 200
        assert "Name: renamed" in netinfra.read_text()

        delete_source = netinfra.read_bytes()
        delete = client.post("/hosts/preview", data={
            "csrf_token": csrf, "operation": "delete", "host_index": "1",
            "revision": hashlib.sha256(delete_source).hexdigest(),
        })
        delete_token = re.search(r'name="token" value="([^"]+)"', delete.text).group(1)
        assert client.post("/hosts/apply", data={"csrf_token": csrf, "token": delete_token}).status_code == 200
        assert "created" not in netinfra.read_text()

        revision = hashlib.sha256(netinfra.read_bytes()).hexdigest()

        stale = client.post("/hosts/preview", data={
            "csrf_token": csrf, "operation": "delete", "host_index": "0", "revision": revision,
        })
        assert stale.status_code == 200
        stale_token = re.search(r'name="token" value="([^"]+)"', stale.text).group(1)
        netinfra.write_text(netinfra.read_text() + "# external writer\n")
        assert client.post("/hosts/apply", data={"csrf_token": csrf, "token": stale_token}).status_code == 409


def test_host_write_routes_require_editor_and_csrf(tmp_path):
    netinfra = tmp_path / "NetInfra.yml"
    netinfra.write_text("subnets: []\nHosts: []\n")
    app = create_app(_config(tmp_path))
    with TestClient(app) as client:
        token = _csrf(client)
        assert client.get("/import").status_code == 401
        assert client.post("/hosts/preview", data={"csrf_token": token}).status_code == 403
        assert client.get("/hosts").status_code == 401
