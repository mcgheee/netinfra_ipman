import asyncio
from datetime import datetime, timedelta, timezone
import sqlite3
from types import SimpleNamespace

import pytest

from netinfra_ipman.config import AppConfig
from netinfra_ipman.persistence import RuntimeStore
from netinfra_ipman.schedules import ScheduleManager, next_trigger, validate_definition
from netinfra_ipman.targets import plan_targets

UTC = timezone.utc
START = datetime(2026, 1, 1, tzinfo=UTC)


class Scanner:
    def __init__(self, store):
        self.store = store
        self.busy = False
        self.calls = []

    def start_request(self, request, inventory, *, scheduled=False, schedule_id=None):
        assert scheduled
        assert not self.busy
        plan = plan_targets(request, inventory)
        job = {"id": str(len(self.calls)), "status": "running", "started_at": START.isoformat()}
        self.store.save_job(job)
        self.busy = True
        self.calls.append((request, inventory, plan, schedule_id))
        return SimpleNamespace(**job)

    def finish(self, status="complete"):
        job = self.store.list_jobs()[0]
        job["status"] = status
        self.store.save_job(job)
        self.busy = False


@pytest.fixture
def runtime(tmp_path):
    path = tmp_path / "NetInfra.yml"
    path.write_text('subnets:\n  - cidr: 192.0.2.0/30\nHosts: []\n')
    store = RuntimeStore(tmp_path / "runtime.db")
    store.initialize()
    scanner = Scanner(store)
    manager = ScheduleManager(AppConfig(netinfra_path=str(path)), store, scanner)
    yield manager, scanner, store, path
    asyncio.run(manager.close())
    store.close()


def interval(**changes):
    return {"kind": "interval", "interval_seconds": 60, **changes}


def test_disabled_creation_and_explicit_toggle(runtime):
    manager, scanner, store, _ = runtime
    schedule = manager.create(interval(enabled=True), now=START)
    assert schedule["enabled"] is False
    assert schedule["next_trigger"] is None
    asyncio.run(manager.tick(START + timedelta(days=1)))
    assert scanner.calls == []
    enabled = manager.toggle(schedule["id"], True, now=START)
    assert enabled["next_trigger"] == (START + timedelta(seconds=60)).isoformat()
    asyncio.run(manager.tick(START + timedelta(seconds=59)))
    assert scanner.calls == []
    asyncio.run(manager.tick(START + timedelta(seconds=60)))
    assert len(scanner.calls) == 1
    assert store.get_schedule(schedule["id"])["status"] == "running"
    manager.toggle(schedule["id"], False, now=START + timedelta(seconds=61))
    scanner.finish()
    asyncio.run(manager.tick(START + timedelta(days=1)))
    assert len(scanner.calls) == 1
    manager.delete(schedule["id"])
    assert manager.list() == []


def test_interval_coalesces_while_busy_without_catchup(runtime):
    manager, scanner, store, _ = runtime
    schedule = manager.create(interval(), now=START)
    manager.toggle(schedule["id"], True, now=START)
    scanner.busy = True  # unrelated manual scan
    for seconds in (60, 120, 3600):
        asyncio.run(manager.tick(START + timedelta(seconds=seconds)))
    saved = store.get_schedule(schedule["id"])
    assert saved["pending"] is True
    assert saved["next_trigger"] == (START + timedelta(seconds=3660)).isoformat()
    assert scanner.calls == []
    scanner.busy = False
    asyncio.run(manager.tick(START + timedelta(seconds=3601)))
    assert len(scanner.calls) == 1
    for seconds in (3660, 3720, 3780):
        asyncio.run(manager.tick(START + timedelta(seconds=seconds)))
    assert store.get_schedule(schedule["id"])["pending"] is True
    scanner.finish()
    asyncio.run(manager.tick(START + timedelta(seconds=3781)))
    assert len(scanner.calls) == 2
    scanner.finish()
    asyncio.run(manager.tick(START + timedelta(seconds=3782)))
    assert len(scanner.calls) == 2
    assert store.get_schedule(schedule["id"])["status"] == "idle"


def test_restart_advances_past_due_and_discards_pending(runtime):
    manager, scanner, store, _ = runtime
    schedule = manager.create(interval(), now=START)
    manager.toggle(schedule["id"], True, now=START)
    scanner.busy = True
    asyncio.run(manager.tick(START + timedelta(seconds=60)))
    store.close()
    store.initialize()
    scanner.busy = False
    replacement = ScheduleManager(manager.config, store, scanner)
    asyncio.run(replacement.tick(START + timedelta(days=3)))
    assert scanner.calls == []
    saved = store.get_schedule(schedule["id"])
    assert saved["pending"] is False
    assert datetime.fromisoformat(saved["next_trigger"]) > START + timedelta(days=3)
    asyncio.run(replacement.tick(datetime.fromisoformat(saved["next_trigger"])))
    assert len(scanner.calls) == 1
    asyncio.run(replacement.close())


def test_dispatch_reads_current_file_and_records_failures(runtime):
    manager, scanner, store, path = runtime
    schedule = manager.create(interval(mode="known-only"), now=START)
    manager.toggle(schedule["id"], True, now=START)
    path.write_text('subnets:\n  - cidr: 198.51.100.0/30\nHosts:\n  - Name: current\n    Records:\n      - Target: 198.51.100.1\n        RRType: no_dns\n')
    asyncio.run(manager.tick(START + timedelta(seconds=60)))
    request, inventory, plan, schedule_id = scanner.calls[0]
    assert list(plan) == ["198.51.100.1"]
    assert inventory.revision
    assert request.mode == "known-only"
    assert schedule_id == schedule["id"]
    scanner.finish("failed")
    asyncio.run(manager.tick(START + timedelta(seconds=61)))
    assert store.get_schedule(schedule["id"])["failures"] == 1
    path.write_text('subnets: [')
    asyncio.run(manager.tick(START + timedelta(seconds=120)))
    failed = store.get_schedule(schedule["id"])
    assert failed["status"] == "failed"
    assert failed["last_error"]
    assert failed["failures"] == 2
    asyncio.run(manager.tick(START + timedelta(seconds=121)))
    assert store.get_schedule(schedule["id"])["failures"] == 2


def calendar(**changes):
    return validate_definition({"kind": "daily", "time": "02:30", "timezone": "America/New_York", **changes})


def test_daily_skips_nonexistent_dst_time():
    definition = calendar()
    assert next_trigger(definition, datetime(2026, 3, 8, tzinfo=UTC)) == datetime(2026, 3, 9, 6, 30, tzinfo=UTC)


def test_repeated_dst_calendar_time_runs_once():
    definition = calendar(time="01:30")
    first = next_trigger(definition, datetime(2026, 11, 1, tzinfo=UTC))
    assert first == datetime(2026, 11, 1, 5, 30, tzinfo=UTC)
    assert next_trigger(definition, first) == datetime(2026, 11, 2, 6, 30, tzinfo=UTC)
    assert next_trigger(definition, first + timedelta(minutes=45)) == datetime(2026, 11, 2, 6, 30, tzinfo=UTC)


def test_weekly_calendar_and_explicit_timezone():
    definition = calendar(kind="weekly", weekdays=[0], time="10:00", timezone="Asia/Tokyo")
    assert next_trigger(definition, START) == datetime(2026, 1, 5, 1, tzinfo=UTC)


@pytest.mark.parametrize("definition", [
    interval(interval_seconds=0), interval(interval_seconds=-1), interval(interval_seconds=float("nan")),
    interval(interval_seconds=float("inf")), interval(interval_seconds=True), interval(interval_seconds="60"),
    interval(scope="ip", target="::1"), interval(scope="range", target="192.0.2.9-192.0.2.1"),
    interval(scope="subnet", target="invalid"), interval(scope="all", target="192.0.2.1"),
    interval(mode="invalid"), {"kind": "daily", "time": "12:00"},
    {"kind": "daily", "time": "25:00", "timezone": "UTC"},
    {"kind": "daily", "time": "12:00", "timezone": "unknown"},
    {"kind": "weekly", "time": "12:00", "timezone": "UTC", "weekdays": []},
    {"kind": "weekly", "time": "12:00", "timezone": "UTC", "weekdays": [7]},
])
def test_invalid_definitions(definition):
    with pytest.raises(ValueError):
        validate_definition(definition)


def test_naive_clock_rejected(runtime):
    manager, _, _, _ = runtime
    with pytest.raises(ValueError, match="timezone-aware"):
        asyncio.run(manager.tick(datetime(2026, 1, 1)))


def test_completed_coverage_replaces_overlap_and_survives_restart(runtime):
    _, _, store, _ = runtime
    store.save_discovery_coverage({"job_id": "old", "intervals": [[0, 100]], "checked_at": "old", "source_revision": "a"})
    store.save_discovery_coverage({"job_id": "new", "intervals": [[20, 80]], "checked_at": "new", "source_revision": "b"})
    store.close()
    store.initialize()
    rows = {row["job_id"]: row for row in store.list_discovery_coverage()}
    assert rows["old"]["intervals"] == [[0, 19], [81, 100]]
    assert rows["new"]["intervals"] == [[20, 80]]
    store.save_discovery_coverage({"job_id": "latest", "intervals": [[0, 100]], "checked_at": "latest", "source_revision": "c"})
    assert [row["job_id"] for row in store.list_discovery_coverage()] == ["latest"]


def test_schema_three_upgrade_retains_schedules_and_supports_coverage(tmp_path):
    path = tmp_path / "old.db"
    store = RuntimeStore(path)
    store.initialize()
    store.save_schedule({"id": "retained", "enabled": False})
    store.close()
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE discovery_coverage")
        connection.execute("PRAGMA user_version = 3")
    store.initialize()
    assert store.list_schedules() == [{"id": "retained", "enabled": False}]
    assert store.list_discovery_coverage() == []
    store.close()


def test_lifecycle_start_close(runtime):
    manager, _, _, _ = runtime

    async def scenario():
        manager.start()
        manager.start()
        await asyncio.sleep(0)
        await manager.close()
        assert manager._task.done()
        with pytest.raises(ValueError, match="closed"):
            manager.start()

    asyncio.run(scenario())


def test_independent_schedules_coalesce_one_pending_each(runtime):
    manager, scanner, store, _ = runtime
    schedules = [
        manager.create(interval(mode=mode), now=START)
        for mode in ("known-only", "discovery-only")
    ]
    for schedule in schedules:
        manager.toggle(schedule["id"], True, now=START)
    asyncio.run(manager.tick(START + timedelta(seconds=60)))
    assert len(scanner.calls) == 1
    assert sum(bool(row["pending"]) for row in store.list_schedules()) == 1
    scanner.finish()
    asyncio.run(manager.tick(START + timedelta(seconds=61)))
    assert len(scanner.calls) == 2
    assert {call[0].mode for call in scanner.calls} == {"known-only", "discovery-only"}


def test_current_inventory_rejects_removed_explicit_target(runtime):
    manager, scanner, store, path = runtime
    schedule = manager.create(interval(scope="ip", target="192.0.2.1"), now=START)
    manager.toggle(schedule["id"], True, now=START)
    path.write_text("subnets:\n  - cidr: 198.51.100.0/30\nHosts: []\n")
    asyncio.run(manager.tick(START + timedelta(seconds=60)))
    assert scanner.calls == []
    saved = store.get_schedule(schedule["id"])
    assert saved["status"] == "failed"
    assert saved["last_error"]


def test_calendar_restart_does_not_replay_missed_days(runtime):
    manager, scanner, store, _ = runtime
    schedule = manager.create(calendar(time="09:00", timezone="UTC"), now=START)
    manager.toggle(schedule["id"], True, now=START)
    replacement = ScheduleManager(manager.config, store, scanner)
    restart = START + timedelta(days=30, hours=12)
    asyncio.run(replacement.tick(restart))
    assert scanner.calls == []
    saved = store.get_schedule(schedule["id"])
    assert datetime.fromisoformat(saved["next_trigger"]) == START + timedelta(days=31, hours=9)
    asyncio.run(replacement.close())


def test_restart_retains_interrupted_run_without_replaying(runtime):
    manager, scanner, store, _ = runtime
    schedule = manager.create(interval(), now=START)
    manager.toggle(schedule["id"], True, now=START)
    asyncio.run(manager.tick(START + timedelta(seconds=60)))
    store.close()
    store.initialize()
    scanner.busy = False
    replacement = ScheduleManager(manager.config, store, scanner)
    asyncio.run(replacement.tick(START + timedelta(days=1)))
    saved = store.get_schedule(schedule["id"])
    assert saved["status"] == "interrupted"
    assert saved["failures"] == 1
    assert "interrupted" in saved["last_error"]
    assert len(scanner.calls) == 1
    asyncio.run(replacement.close())


def test_weekly_nonexistent_dst_time_skips_the_week():
    definition = calendar(kind="weekly", weekdays=[6])
    assert next_trigger(definition, datetime(2026, 3, 8, tzinfo=UTC)) == datetime(2026, 3, 15, 6, 30, tzinfo=UTC)


def test_schedule_update_validates_and_reanchors(runtime):
    manager, _, store, _ = runtime
    schedule = manager.create(interval(), now=START)
    updated = manager.update(schedule["id"], {"interval_seconds": 120, "enabled": True}, now=START)
    assert updated["next_trigger"] == (START + timedelta(seconds=120)).isoformat()
    with pytest.raises(ValueError):
        manager.update(schedule["id"], {"interval_seconds": -1}, now=START)
    assert store.get_schedule(schedule["id"]) == updated
    with pytest.raises(ValueError):
        manager.update(schedule["id"], {"enabled": "true"}, now=START)
