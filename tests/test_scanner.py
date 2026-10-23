import asyncio
import threading

import pytest

from netinfra_ipman.config import AppConfig
from netinfra_ipman.persistence import RuntimeStore
from netinfra_ipman.scanner import ScanManager


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
    path = tmp_path / "runtime.sqlite3"
    store = RuntimeStore(path)
    store.initialize()

    async def scenario():
        manager = ScanManager(AppConfig(), store)
        job = manager.start(cidr, set(), source_revision="source-revision")
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
    store = RuntimeStore(tmp_path / "runtime.sqlite3")
    store.initialize()

    async def scenario():
        manager = ScanManager(AppConfig(), store)
        manager.start("192.0.2.0/29", {"192.0.2.1"})
        await finished(manager)
        await manager.close()

    asyncio.run(scenario())
    assert store.get("observation:192.0.2.1")["managed"] is True
    assert store.get("observation:192.0.2.1")["responding"] is False
    assert store.get("observation:192.0.2.3")["discovered"] is True
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
        job = manager.start("192.0.2.0/24", set())
        for cidr in ("192.0.2.0/24", "198.51.100.0/24"):
            with pytest.raises(ValueError, match="already active"):
                manager.start(cidr, set())
        manager.cancel(job.id)
        await finished(manager)
        assert manager.as_dicts()[0]["status"] == "cancelled"
        assert manager.as_dicts()[0]["incomplete"] is True
        assert manager.as_dicts()[0]["progress"] == 0
        await manager.close()
        with pytest.raises(ValueError, match="closed"):
            manager.start("192.0.2.1/32", set())

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
        job = manager.start("0.0.0.0/0", set())
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
        manager.start("192.0.2.0/29", set())
        await finished(manager)
        summary = manager.as_dicts()[0]
        assert summary["status"] == "failed"
        assert summary["error"] == "probe exploded"
        assert summary["incomplete"] is True
        assert summary["finished_at"]
        monkeypatch.setattr("netinfra_ipman.scanner.check_ping", lambda ip, timeout: (True, 1.0, None))
        next_job = manager.start("192.0.2.1/32", set())
        await finished(manager)
        assert [job["id"] for job in manager.as_dicts()] == [next_job.id]
        await manager.close()
        assert not [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]

    asyncio.run(scenario())
    store.close()
