import asyncio
from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Address
import threading
import time

import pytest

from netinfra_ipman.config import AppConfig
from netinfra_ipman.netinfra import build_inventory
from netinfra_ipman.persistence import RuntimeStore
from netinfra_ipman.scanner import ScanManager
from netinfra_ipman.targets import ScanRequest


def inventory(cidr="192.0.2.0/29"):
    return build_inventory({"subnets": [{"cidr": cidr}]}, revision="runtime-revision")


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    async def sleep(self, delay):
        self.now += delay
        await asyncio.sleep(0)


def test_strict_start_spacing_and_concurrency_without_wall_clock_waits(tmp_path):
    store = RuntimeStore(tmp_path / "runtime.sqlite3")
    store.initialize()

    async def scenario():
        clock = Clock()
        manager = ScanManager(AppConfig(scan_concurrency=2, scan_start_rate=4), store, clock=clock, sleep=clock.sleep)
        starts = []
        active = 0
        peak = 0

        async def observe(ip, data, config):
            nonlocal active, peak
            starts.append(clock())
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0)
            active -= 1
            return {"ip": ip, "ping_ok": False}

        manager._observe = observe
        job = manager.start_request(ScanRequest("subnet", "192.0.2.0/29"), inventory())
        await manager._runner
        assert job.status == "complete"
        assert job.progress == job.total == 6
        assert peak <= 2
        assert starts == [index / 4 for index in range(6)]
        assert len(store.list_discovery_coverage()) == 1
        await manager.close()

    try:
        asyncio.run(scenario())
    finally:
        store.close()

def test_executor_queue_does_not_burst_actual_probe_starts(tmp_path, monkeypatch):
    store = RuntimeStore(tmp_path / "runtime.sqlite3")
    store.initialize()

    async def scenario():
        loop = asyncio.get_running_loop()
        loop.set_default_executor(ThreadPoolExecutor(max_workers=2))
        manager = ScanManager(AppConfig(scan_concurrency=6, scan_start_rate=20), store)
        release = threading.Event()
        starts = []
        starts_lock = threading.Lock()

        def probe(*args):
            with starts_lock:
                index = len(starts)
                starts.append(time.monotonic())
            if index < 2 and not release.wait(2):
                raise RuntimeError("test probe release timed out")
            return True, 1.0, None

        monkeypatch.setattr("netinfra_ipman.scanner.check_ping", probe)
        job = manager.start_request(ScanRequest("subnet", "192.0.2.0/29"), inventory())
        await asyncio.sleep(0.18)
        release.set()
        await manager._runner
        assert job.status == "complete"
        assert len(starts) == job.total == 6
        assert all(later - earlier >= 0.04 for earlier, later in zip(starts, starts[1:]))
        await manager.close()

    try:
        asyncio.run(scenario())
    finally:
        store.close()


def test_confirmation_exact_count_boundary_and_scheduled_authorization(tmp_path):
    store = RuntimeStore(tmp_path / "runtime.sqlite3")
    store.initialize()

    async def scenario():
        manager = ScanManager(AppConfig(), store)
        data = inventory("10.0.0.0/8")
        start = int(IPv4Address("10.0.0.0"))
        exact = ScanRequest("range", f"10.0.0.0-{IPv4Address(start + 4095)}")
        large = ScanRequest("range", f"10.0.0.0-{IPv4Address(start + 4096)}")
        job = manager.start_request(exact, data)
        manager.cancel(job.id)
        await manager._runner
        with pytest.raises(ValueError, match="confirmation"):
            manager.start_request(large, data)
        assert not manager.busy
        for kwargs in ({"confirmed": True}, {"scheduled": True, "schedule_id": "schedule-one"}):
            job = manager.start_request(large, data, **kwargs)
            assert job.total == 4097
            assert job.scope == "range"
            assert job.schedule_id == kwargs.get("schedule_id")
            manager.cancel(job.id)
            await manager._runner
        assert store.list_discovery_coverage() == []
        await manager.close()

    try:
        asyncio.run(scenario())
    finally:
        store.close()


def test_silent_unknown_recheck_removes_stale_responder_and_partial_has_no_coverage(tmp_path):
    store = RuntimeStore(tmp_path / "runtime.sqlite3")
    store.initialize()
    store.set("observation:192.0.2.1", {"ip": "192.0.2.1", "ping_ok": True})

    async def scenario():
        manager = ScanManager(AppConfig(scan_concurrency=1), store)

        async def observe(ip, data, config):
            if ip == "192.0.2.2":
                raise RuntimeError("simulated failure")
            return {"ip": ip, "ping_ok": False}

        manager._observe = observe
        job = manager.start_request(ScanRequest("range", "192.0.2.1-192.0.2.2"), inventory())
        await manager._runner
        assert job.status == "failed" and job.incomplete
        assert job.progress == 1
        assert job.error == "simulated failure"
        assert store.get("observation:192.0.2.1") is None
        assert store.list_discovery_coverage() == []
        await manager.close()

    try:
        asyncio.run(scenario())
    finally:
        store.close()
