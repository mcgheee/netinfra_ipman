from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sqlite3
import sys

from fastapi.testclient import TestClient
import pytest

from netinfra_ipman.config import AppConfig
from netinfra_ipman.main import create_app


def settings(tmp_path: Path) -> AppConfig:
    return AppConfig(
        config_path=str(tmp_path / 'config.yml'),
        netinfra_path=str(tmp_path / 'NetInfra.yml'),
        admin_file=str(tmp_path / 'admin.yml'),
        audit_log_file=str(tmp_path / 'audit.log'),
        sqlite_path=str(tmp_path / 'runtime.sqlite3'),
        allow_anonymous_viewing=True,
    )


def test_import_does_not_initialize_runtime(tmp_path):
    env = {**os.environ, 'IPMAN_CONFIG': str(tmp_path / 'missing.yml'),
           'PYTHONPATH': str(Path(__file__).resolve().parents[1])}
    subprocess.run([sys.executable, '-c', 'import netinfra_ipman.main'],
                   cwd=tmp_path, env=env, check=True)
    assert list(tmp_path.iterdir()) == []


def test_restart_retains_runtime_without_provisioning_admin(tmp_path):
    config = settings(tmp_path)
    app = create_app(config)
    with TestClient(app) as client:
        store = app.state.services.store
        client.portal.call(store.set, 'observation:192.0.2.1', {'ip': '192.0.2.1', 'ping_error': 'No response'})
        client.portal.call(store.save_schedule, {'id': 'nightly', 'cidr': '192.0.2.0/30'})
        client.portal.call(store.save_job, {'id': 'interrupted', 'cidr': '192.0.2.0/30', 'status': 'running',
                                          'progress': 1, 'total': 2, 'started_at': '2026-01-01T00:00:00+00:00'})
        assert client.get('/login').status_code == 200
        assert not Path(config.admin_file).exists()
        assert not Path(config.config_path).exists()
    assert not hasattr(app.state, 'services')
    restarted = create_app(config)
    with TestClient(restarted) as client:
        store = restarted.state.services.store
        assert client.portal.call(store.get, 'observation:192.0.2.1')['ping_error'] == 'No response'
        assert client.portal.call(store.list_schedules)[0]['id'] == 'nightly'
        job = client.portal.call(store.list_jobs)[0]
        assert job['incomplete'] is True
        assert job['status'] == 'interrupted'
        page = client.get('/')
        assert page.status_code == 200
        assert 'interrupted' in page.text


def test_separate_applications_have_isolated_services(tmp_path):
    first = create_app(settings(tmp_path / 'first'))
    second = create_app(settings(tmp_path / 'second'))
    with TestClient(first) as first_client, TestClient(second) as second_client:
        first_client.portal.call(first.state.services.store.set, 'a', {'value': 1})
        assert second_client.portal.call(second.state.services.store.get, 'a') is None
        first.state.services.audit.record('actor', 'local', 'check', 'first app')
        second.state.services.audit.record('actor', 'local', 'check', 'second app')
    assert 'first app' in (tmp_path / 'first' / 'audit.log').read_text()
    assert 'second app' not in (tmp_path / 'first' / 'audit.log').read_text()


def test_unavailable_database_fails_startup(tmp_path):
    config = settings(tmp_path)
    Path(config.sqlite_path).mkdir()
    with pytest.raises((OSError, sqlite3.OperationalError)):
        with TestClient(create_app(config)):
            pytest.fail('Startup must not fall back to process memory')


