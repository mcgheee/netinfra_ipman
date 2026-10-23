import asyncio
import threading

import pytest

from netinfra_ipman.config import AppConfig
from netinfra_ipman.persistence import RuntimeStore
from netinfra_ipman.scanner import ScanManager
from netinfra_ipman.netinfra import build_inventory


def inventory_for(cidr, known=(), revision="source-revision"):
    return build_inventory({
        "subnets": [{"cidr": cidr}],
        "Hosts": [
            {"Name": ip, "Records": [{"Target": ip, "RRType": "no_dns"}]}
            for ip in known
        ],
    }, revision=revision)


async def finished(manager):
    async def wait():
        while any(job["status"] in {"queued", "running"} for job in manager.as_dicts()):
            await asyncio.sleep(0)
    await asyncio.wait_for(wait(), timeout=5)


@pytest.mark.parametrize(("cidr", "count"), [("192.0.2.0/31", 2), ("192.0.2.1/32", 1)])
def test_small_network_counts_and_durable_summaries(tmp_path, monkeypatch, cidr, count):
    calls = []

    def ping(ip, timeout):
        calls.append(ip)
        return True, 1.0, None

    monkeypatch.setattr("netinfra_ipman.scanner.check_ping", ping)
    monkeypatch.setattr("netinfra_ipman.checks.check_ping", ping)
    path = tmp_path / "runtime.sqlite3"
    store = RuntimeStore(path)
    store.initialize()

    async def scenario():
        manager = ScanManager(AppConfig(), store)
        job = manager.start(cidr, inventory_for(cidr))
        assert job.total == count
        await finished(manager)
        await manager.close()
        summary = manager.as_dicts()[0]
        assert summary["status"] == "complete"
        assert summary["progress"] == summary["total"] == count
        assert "results" not in summary
        assert summary["source_revision"] == "source-revision"

    asyncio.run(scenario())
    store.close()
    store.initialize()
    assert len(calls) == count
    assert store.list_jobs()[0]["status"] == "complete"
    assert store.get(f"observation:{calls[0]}")["source_revision"] == "source-revision"
    store.close()


def test_sparse_observations_keep_known_silent_and_unknown_responders(tmp_path, monkeypatch):
    def ping(ip, timeout):
        return (ip == "192.0.2.3"), None, None

    monkeypatch.setattr("netinfra_ipman.scanner.check_ping", ping)
    monkeypatch.setattr("netinfra_ipman.checks.check_ping", ping)
    store = RuntimeStore(tmp_path / "runtime.sqlite3")
    store.initialize()

    async def scenario():
        manager = ScanManager(AppConfig(), store)
        manager.start("192.0.2.0/29", inventory_for("192.0.2.0/29", {"192.0.2.1"}))
        await finished(manager)
        await manager.close()

    asyncio.run(scenario())
    assert store.get("observation:192.0.2.1")["ping_ok"] is False
    assert store.get("observation:192.0.2.3")["ping_ok"] is True
    for ip in ("192.0.2.2", "192.0.2.4", "192.0.2.5", "192.0.2.6"):
        assert store.get(f"observation:{ip}") is None
    store.close()


def test_one_active_scan_and_queued_cancellation(tmp_path, monkeypatch):
    def unexpected_ping(ip, timeout):
        raise AssertionError("Queued cancellation must not probe")

    monkeypatch.setattr("netinfra_ipman.scanner.check_ping", unexpected_ping)
    store = RuntimeStore(tmp_path / "runtime.sqlite3")
    store.initialize()

    async def scenario():
        manager = ScanManager(AppConfig(), store)
        job = manager.start("192.0.2.0/24", inventory_for("192.0.2.0/24"))
        for cidr in ("192.0.2.0/24", "198.51.100.0/24"):
            with pytest.raises(ValueError, match="already active"):
                manager.start(cidr, inventory_for(cidr))
        manager.cancel(job.id)
        await finished(manager)
        assert manager.as_dicts()[0]["status"] == "cancelled"
        assert manager.as_dicts()[0]["incomplete"] is True
        assert manager.as_dicts()[0]["progress"] == 0
        await manager.close()
        with pytest.raises(ValueError, match="closed"):
            manager.start("192.0.2.1/32", inventory_for("192.0.2.1/32"))

    asyncio.run(scenario())
    store.close()


@pytest.mark.parametrize("explicit_cancel", [False, True])
def test_shutdown_and_cancel_await_bounded_probe_cleanup(tmp_path, monkeypatch, explicit_cancel):
    entered = threading.Event()
    release = threading.Event()
    exited = threading.Event()
    calls = []

    def ping(ip, timeout):
        calls.append(ip)
        entered.set()
        try:
            release.wait(timeout=5)
            return False, None, "timeout"
        finally:
            exited.set()

    monkeypatch.setattr("netinfra_ipman.scanner.check_ping", ping)
    store = RuntimeStore(tmp_path / "runtime.sqlite3")
    store.initialize()

    async def scenario():
        manager = ScanManager(AppConfig(scan_concurrency=1), store)
        job = manager.start("0.0.0.0/0", inventory_for("0.0.0.0/0"))
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            if explicit_cancel:
                manager.cancel(job.id)
                manager.cancel(job.id)  # Repeated requests must not interrupt cleanup.
            closing = asyncio.create_task(manager.close())
            for _ in range(10):
                await asyncio.sleep(0)
            assert not closing.done()
            assert len(calls) == 1
            release.set()
            await asyncio.wait_for(closing, 5)
            assert exited.is_set()
            assert manager.as_dicts()[0]["status"] == "cancelled"
            assert manager.as_dicts()[0]["incomplete"] is True
            assert not [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
        finally:
            release.set()

    asyncio.run(scenario())
    store.close()


def test_probe_exception_persists_failure_and_allows_next_scan(tmp_path, monkeypatch):
    def broken_ping(ip, timeout):
        raise RuntimeError("probe exploded")

    monkeypatch.setattr("netinfra_ipman.scanner.check_ping", broken_ping)
    store = RuntimeStore(tmp_path / "runtime.sqlite3")
    store.initialize()

    async def scenario():
        manager = ScanManager(AppConfig(completed_job_retention=1), store)
        manager.start("192.0.2.0/29", inventory_for("192.0.2.0/29"))
        await finished(manager)
        summary = manager.as_dicts()[0]
        assert summary["status"] == "failed"
        assert summary["error"] == "probe exploded"
        assert summary["incomplete"] is True
        assert summary["finished_at"]
        monkeypatch.setattr("netinfra_ipman.scanner.check_ping", lambda ip, timeout: (True, 1.0, None))
        next_job = manager.start("192.0.2.1/32", inventory_for("192.0.2.1/32"))
        await finished(manager)
        assert [job["id"] for job in manager.as_dicts()] == [next_job.id]
        await manager.close()
        assert not [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]

    asyncio.run(scenario())
    store.close()


def test_undeclared_scope_rejected_before_probing(tmp_path, monkeypatch):
    def forbidden(*args):
        pytest.fail("Out-of-subnet targets must never be probed")

    monkeypatch.setattr("netinfra_ipman.scanner.check_ping", forbidden)
    store = RuntimeStore(tmp_path / "runtime.sqlite3")
    store.initialize()

    async def scenario():
        manager = ScanManager(AppConfig(), store)
        with pytest.raises(ValueError, match="declared"):
            manager.start("198.51.100.1/32", inventory_for("192.0.2.0/24"))
        assert manager.as_dicts() == []
        await manager.close()

    asyncio.run(scenario())
    store.close()


def test_known_scan_uses_complete_snapshot_expectations_and_keeps_raw_evidence(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from netinfra_ipman.checks import reconcile
    from netinfra_ipman.netinfra import load_inventory

    path = tmp_path / "NetInfra.yml"
    path.write_text("""subnets:
  - cidr: 192.0.2.0/24
Hosts:
  - Name: service
    Records:
      - Target: 192.0.2.1
        ZoneName: example.com
      - Target: 192.0.2.2
        ZoneName: example.com
""")
    inventory = load_inventory(path)
    monkeypatch.setattr("netinfra_ipman.checks.check_ping", lambda *args: (True, 1.0, None))
    resolver = SimpleNamespace(resolve=lambda *args, **kwargs: [
        SimpleNamespace(to_text=lambda: "192.0.2.1"),
        SimpleNamespace(to_text=lambda: "192.0.2.2"),
    ])
    monkeypatch.setattr("netinfra_ipman.checks.dns_resolver", lambda *args: resolver)
    store = RuntimeStore(tmp_path / "runtime.sqlite3")
    store.initialize()

    async def scenario():
        config = AppConfig()
        manager = ScanManager(config, store)
        job = manager.start("192.0.2.1/32", inventory)
        path.write_text("Hosts: []\n")
        await finished(manager)
        await manager.close()
        evidence = store.get("observation:192.0.2.1")
        result = reconcile(inventory.groups["192.0.2.1"], inventory, config, evidence)
        assert result.state == "matches"
        assert result.dns_checks[0]["expected"] == ["192.0.2.1", "192.0.2.2"]
        assert evidence["source_revision"] == job.source_revision == inventory.revision
        assert "expected" not in evidence["dns"]["service.example.com"]
        assert store.get("observation:192.0.2.2") is None

    asyncio.run(scenario())
    store.close()


def test_refresh_checks_only_declared_known_addresses_and_shares_runner_limit(tmp_path, monkeypatch):
    entered = threading.Event()
    release = threading.Event()
    calls = []
    known = {"192.0.2.1", "192.0.2.2"}

    def ping(ip, timeout):
        calls.append(ip)
        entered.set()
        release.wait(timeout=5)
        return True, 1.0, None

    monkeypatch.setattr("netinfra_ipman.checks.check_ping", ping)
    store = RuntimeStore(tmp_path / "runtime.sqlite3")
    store.initialize()

    async def scenario():
        manager = ScanManager(AppConfig(scan_concurrency=1), store)
        inventory = inventory_for("0.0.0.0/0", known)
        refreshing = asyncio.create_task(manager.refresh("0.0.0.0/0", inventory))
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            with pytest.raises(ValueError, match="already active"):
                manager.start("192.0.2.1/32", inventory)
            with pytest.raises(ValueError, match="already active"):
                await manager.refresh("192.0.2.1/32", inventory)
            release.set()
            job = await asyncio.wait_for(refreshing, 5)
            assert job.status == "complete"
            assert job.progress == job.total == 2
            assert set(calls) == known
            assert all(store.get(f"observation:{ip}")["ping_ok"] for ip in known)
            await manager.close()
        finally:
            release.set()

    asyncio.run(scenario())
    store.close()


def test_cancelled_refresh_request_awaits_probe_cleanup_and_persists_partial_job(tmp_path, monkeypatch):
    entered = threading.Event()
    release = threading.Event()
    exited = threading.Event()

    def ping(ip, timeout):
        entered.set()
        release.wait(timeout=5)
        exited.set()
        return True, 1.0, None

    monkeypatch.setattr("netinfra_ipman.checks.check_ping", ping)
    store = RuntimeStore(tmp_path / "runtime.sqlite3")
    store.initialize()

    async def scenario():
        manager = ScanManager(AppConfig(scan_concurrency=1), store)
        inventory = inventory_for("192.0.2.0/24", {"192.0.2.1", "192.0.2.2"})
        refreshing = asyncio.create_task(manager.refresh("192.0.2.0/24", inventory))
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            refreshing.cancel()
            for _ in range(10):
                await asyncio.sleep(0)
            assert not refreshing.done()
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await refreshing
            assert exited.is_set()
            summary = manager.as_dicts()[0]
            assert summary["status"] == "cancelled"
            assert summary["incomplete"] is True
            assert summary["progress"] < summary["total"]
            await manager.close()
        finally:
            release.set()

    asyncio.run(scenario())
    store.close()
