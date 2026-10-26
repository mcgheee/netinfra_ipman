from __future__ import annotations

from http.cookies import SimpleCookie
import re

from fastapi import Response
from fastapi.testclient import TestClient

from netinfra_ipman.config import AppConfig
from netinfra_ipman.main import create_app
from netinfra_ipman.security import COOKIE_NAME, Principal, Role


def _app(tmp_path):
    inventory = tmp_path / "NetInfra.yml"
    inventory.write_text(
        'subnets:\n'
        '  - cidr: 192.0.2.0/24\n'
        '    pools: ["192.0.2.20-192.0.2.30"]\n'
        'Hosts:\n'
        '  - Name: webhost\n'
        '    Records:\n'
        '      - RRType: no_dns\n'
        '        Target: 192.0.2.10\n'
    )
    config = AppConfig(
        netinfra_path=str(inventory), config_path=str(tmp_path / "config.yml"),
        admin_file=str(tmp_path / "admin.yml"), sqlite_path=str(tmp_path / "runtime.sqlite3"),
        audit_log_file=str(tmp_path / "audit.log"), backup_dir=str(tmp_path / "backups"),
        allow_anonymous_viewing=True, oidc_enabled=True, oidc_issuer="https://idp.example",
        oidc_client_id="client", oidc_redirect_uri="https://app.example/callback",
        oidc_group_role_map={"editors": "editor"},
    )
    return inventory, config, create_app(config)


def _login_editor(client, app):
    def issue_cookie():
        response = Response()
        app.state.services.security.login(
            response, Principal("https://idp.example|person", "editor", Role.editor, "oidc"),
        )
        return response.headers["set-cookie"]

    cookie = SimpleCookie()
    cookie.load(client.portal.call(issue_cookie))
    client.cookies.set(COOKIE_NAME, cookie[COOKIE_NAME].value, domain="testserver.local", path="/")
    page = client.get("/login")
    return re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)


def test_search_discovery_dhcp_and_reviewed_host_apply(tmp_path, monkeypatch):
    inventory, config, app = _app(tmp_path)
    monkeypatch.setattr("netinfra_ipman.checks.check_ping", lambda *args: (True, 1.0, None))
    with TestClient(app, base_url="https://testserver.local") as client:
        searched = client.get("/?subnet=192.0.2.0%2F24&q=WEBHOST")
        assert searched.status_code == 200
        assert "192.0.2.10" in searched.text
        assert "sparse matching addresses" in searched.text
        client.portal.call(app.state.services.store.set, "observation:192.0.2.21", {
            "ip": "192.0.2.21", "ping_ok": True, "checked_at": "2026-10-26T12:00:00+00:00",
        })
        discoveries = client.get("/discoveries")
        assert discoveries.status_code == 200
        assert "192.0.2.21" in discoveries.text
        assert "192.0.2.20-192.0.2.30" in discoveries.text
        assert "no DHCP lease has been verified" in discoveries.text

        csrf = _login_editor(client, app)
        review = client.get("/discoveries/192.0.2.21/review")
        assert review.status_code == 200
        token = re.search(r'name="token" value="([^"]+)"', review.text).group(1)
        assert "Apply reviewed host proposal" in review.text
        assert "discovered-192-0-2-21" not in inventory.read_text()
        applied = client.post("/discoveries/apply", data={"csrf_token": csrf, "token": token})
        assert applied.status_code == 200
        assert "discovered-192-0-2-21" in inventory.read_text()



def test_stale_and_issues_filters_handle_all_status_shapes(tmp_path):
    from datetime import datetime, timezone

    _, _, app = _app(tmp_path)
    with TestClient(app, base_url="https://testserver.local") as client:
        store = app.state.services.store
        client.portal.call(store.set, "observation:192.0.2.10", {
            "ip": "192.0.2.10", "ping_ok": True, "checked_at": "2000-01-01T00:00:00+00:00",
        })
        client.portal.call(store.set, "observation:192.0.2.21", {
            "ip": "192.0.2.21", "ping_ok": True, "checked_at": datetime.now(timezone.utc).isoformat(),
        })

        ordinary = client.get("/")
        assert ordinary.status_code == 200
        assert "Stale evidence" in ordinary.text

        issues = client.get("/?discrepancy=issues")
        assert issues.status_code == 200
        assert "192.0.2.21" in issues.text

        stale = client.get("/?discrepancy=stale")
        assert stale.status_code == 200
        assert "192.0.2.10" in stale.text
        assert "192.0.2.21" not in stale.text


def test_discovery_listing_is_paginated(tmp_path):
    inventory, _, app = _app(tmp_path)
    inventory.write_text(inventory.read_text().replace("192.0.2.0/24", "192.0.0.0/16"))
    with TestClient(app, base_url="https://testserver.local") as client:
        store = app.state.services.store
        for index in range(1, 301):
            ip = f"192.0.{index // 256}.{index % 256}"
            client.portal.call(store.set, f"observation:{ip}", {
                "ip": ip, "ping_ok": True, "checked_at": "2026-10-26T12:00:00+00:00",
            })

        first = client.get("/discoveries")
        assert first.status_code == 200
        assert first.text.count("<tr>") == 257  # 256 address rows and one header
        assert "Page 1 of 2" in first.text
        second = client.get("/discoveries?page=2")
        assert second.status_code == 200
        assert second.text.count("<tr>") == 45  # 44 address rows and one header
        assert "Page 2 of 2" in second.text

def test_job_fragment_polls_only_until_terminal_and_is_viewer_accessible(tmp_path):
    _, _, app = _app(tmp_path)
    with TestClient(app, base_url="https://testserver.local") as client:
        store = app.state.services.store
        running_job = {
            "id": "running-job", "scope": "subnet", "target": "192.0.2.0/24",
            "mode": "full", "status": "running", "progress": 4, "total": 254,
            "started_at": "2026-10-26T12:00:00+00:00",
        }
        client.portal.call(store.save_job, running_job)
        running = client.get("/jobs/running-job")
        assert running.status_code == 200
        assert 'hx-trigger="every 2s"' in running.text
        assert "4/254" in running.text
        running_job.update(status="complete", progress=254)
        client.portal.call(store.save_job, running_job)
        finished = client.get("/jobs/running-job")
        assert finished.status_code == 200
        assert "hx-trigger" not in finished.text
