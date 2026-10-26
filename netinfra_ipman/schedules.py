from __future__ import annotations

import asyncio
from datetime import datetime, time, timedelta, timezone
from ipaddress import IPv4Address, IPv4Network
import math
from typing import Any
import uuid
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .netinfra import load_inventory
from .targets import ScanRequest

UTC = timezone.utc
_DEFINITION_FIELDS = {"name", "scope", "target", "mode", "kind", "interval_seconds", "time", "timezone", "weekdays"}


def _now(value: datetime | None = None) -> datetime:
    value = value or datetime.now(UTC)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Schedule clock must be timezone-aware")
    return value.astimezone(UTC)


def validate_definition(definition: dict[str, Any]) -> dict[str, Any]:
    """Validate syntax now; membership in current inventory is checked at dispatch."""
    result = {key: value for key, value in definition.items() if key in _DEFINITION_FIELDS}
    scope = result.setdefault("scope", "all")
    target = result.setdefault("target", "")
    mode = result.setdefault("mode", "full")
    if not isinstance(scope, str) or scope not in {"all", "subnet", "range", "ip"}:
        raise ValueError("Invalid scan scope")
    if not isinstance(mode, str) or mode not in {"full", "known-only", "discovery-only"}:
        raise ValueError("Invalid scan mode")
    if not isinstance(target, str):
        raise ValueError("Target must be a string")
    try:
        if scope == "all" and target:
            raise ValueError("All-subnet schedules must have an empty target")
        if scope == "subnet":
            IPv4Network(target, strict=False)
        elif scope == "ip":
            IPv4Address(target)
        elif scope == "range":
            first, last = target.split("-")
            if IPv4Address(first.strip()) > IPv4Address(last.strip()):
                raise ValueError("Range start must not exceed its end")
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Invalid schedule target: {exc}") from exc
    kind = result.get("kind")
    if not isinstance(kind, str):
        raise ValueError("Schedule kind must be interval, daily, or weekly")
    if kind == "interval":
        seconds = result.get("interval_seconds")
        if isinstance(seconds, bool) or not isinstance(seconds, (float, int)) or seconds <= 0 or (isinstance(seconds, float) and not math.isfinite(seconds)):
            raise ValueError("interval_seconds must be positive and finite")
        try:
            if timedelta(seconds=seconds) <= timedelta(0):
                raise ValueError("Interval is below clock resolution")
            datetime.now(UTC) + timedelta(seconds=seconds)
        except OverflowError as exc:
            raise ValueError("Interval exceeds supported datetime range") from exc
    elif kind in {"daily", "weekly"}:
        try:
            local_time = time.fromisoformat(result["time"])
            if local_time.tzinfo is not None:
                raise ValueError("Use a local clock time and a separate timezone")
            ZoneInfo(result["timezone"])
        except (KeyError, ValueError, TypeError, ZoneInfoNotFoundError) as exc:
            raise ValueError("Calendar schedules require a valid local time and explicit IANA timezone") from exc
        if kind == "weekly":
            days = result.get("weekdays")
            if not isinstance(days, list) or not days or any(type(day) is not int or not 0 <= day <= 6 for day in days):
                raise ValueError("Weekly weekdays must be a nonempty list of Monday=0 through Sunday=6")
            result["weekdays"] = sorted(set(days))
    else:
        raise ValueError("Schedule kind must be interval, daily, or weekly")
    return result


def next_trigger(definition: dict[str, Any], after: datetime) -> datetime:
    """Return the first trigger strictly after an instant (UTC).

    Fold zero is the sole occurrence of a repeated local time. Round-tripping
    through UTC rejects gaps rather than shifting them into a different time.
    """
    after = _now(after)
    if definition["kind"] == "interval":
        return after + timedelta(seconds=definition["interval_seconds"])
    zone = ZoneInfo(definition["timezone"])
    clock = time.fromisoformat(definition["time"])
    date = after.astimezone(zone).date()
    while True:
        if definition["kind"] == "daily" or date.weekday() in definition["weekdays"]:
            local = datetime.combine(date, clock, tzinfo=zone).replace(fold=0)
            instant = local.astimezone(UTC)
            if instant > after and instant.astimezone(zone).replace(tzinfo=None) == local.replace(tzinfo=None):
                return instant
        date += timedelta(days=1)


def _advance(definition: dict[str, Any], due: datetime, now: datetime) -> datetime:
    if definition["kind"] != "interval":
        return next_trigger(definition, now)
    interval = timedelta(seconds=definition["interval_seconds"])
    return due + interval * ((now - due) // interval + 1)


class ScheduleManager:
    """One lifecycle task and at most one durable pending trigger per schedule."""

    def __init__(self, config, store, scanner, audit=None):
        self.config = config
        self.store = store
        self.scanner = scanner
        self.audit = audit
        self._task: asyncio.Task[None] | None = None
        self._closed = False
        self._recovered = False

    def list(self) -> list[dict[str, Any]]:
        return self.store.list_schedules()

    def _get(self, schedule_id: str) -> dict[str, Any]:
        schedule = self.store.get_schedule(schedule_id)
        if schedule is None:
            raise ValueError("Schedule not found")
        return schedule

    def create(self, definition: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        now = _now(now)
        self._recover(now)
        schedule = validate_definition(definition)
        schedule.update(id=str(uuid.uuid4()), enabled=False, status="disabled", pending=False,
                        last_trigger=None, next_trigger=None, last_job_id=None,
                        last_error=None, failures=0)
        self.store.save_schedule(schedule)
        return schedule

    def update(self, schedule_id: str, changes: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        now = _now(now)
        self._recover(now)
        schedule = self._get(schedule_id)
        unknown = set(changes) - _DEFINITION_FIELDS - {"enabled"}
        if unknown:
            raise ValueError("Unsupported schedule fields: " + ", ".join(sorted(unknown)))
        definition = validate_definition({**schedule, **changes})
        enabled = changes.get("enabled", schedule.get("enabled", False))
        if type(enabled) is not bool:
            raise ValueError("enabled must be a boolean")
        schedule = {key: value for key, value in schedule.items() if key not in _DEFINITION_FIELDS}
        schedule.update(definition, enabled=enabled, pending=False,
                        next_trigger=next_trigger(definition, now).isoformat() if enabled else None,
                        status="idle" if enabled else "disabled", last_error=None)
        self.store.save_schedule(schedule)
        return schedule

    def toggle(self, schedule_id: str, enabled: bool, *, now: datetime | None = None) -> dict[str, Any]:
        return self.update(schedule_id, {"enabled": enabled}, now=now)

    def delete(self, schedule_id: str) -> None:
        self._get(schedule_id)
        self.store.delete_schedule(schedule_id)

    def _recover(self, now: datetime) -> None:
        if self._recovered:
            return
        for schedule in self.list():
            was_running = schedule.get("status") == "running"
            schedule["pending"] = False
            try:
                definition = validate_definition(schedule)
                enabled = schedule.get("enabled", False)
                due = datetime.fromisoformat(schedule["next_trigger"]) if schedule.get("next_trigger") else None
                if enabled:
                    schedule["next_trigger"] = (
                        _advance(definition, _now(due), now) if due and _now(due) <= now
                        else _now(due) if due else next_trigger(definition, now)
                    ).isoformat()
                    schedule["status"] = "idle"
                else:
                    schedule.update(status="disabled", next_trigger=None)
                job = self.store.get_job(schedule["last_job_id"]) if schedule.get("last_job_id") else None
                if job and job["status"] in {"interrupted", "failed", "cancelled"}:
                    schedule.update(last_error=job.get("error") or f"Last run {job['status']}")
                    if enabled:
                        schedule["status"] = job["status"]
                    if was_running:
                        schedule["failures"] = schedule.get("failures", 0) + 1
            except (ValueError, TypeError, OverflowError) as exc:
                schedule.update(enabled=False, status="failed", next_trigger=None, last_error=str(exc),
                                failures=schedule.get("failures", 0) + 1)
            self.store.save_schedule(schedule)
        self._recovered = True

    def start(self) -> None:
        if self._closed:
            raise ValueError("Schedule manager is closed")
        if self._task is not None:
            return
        self._recover(_now())
        self._task = asyncio.get_running_loop().create_task(self._run(), name="schedule-runner")

    async def _run(self) -> None:
        while True:
            await self.tick()
            await asyncio.sleep(0.5)

    async def tick(self, now: datetime | None = None) -> None:
        if self._closed:
            raise ValueError("Schedule manager is closed")
        now = _now(now)
        self._recover(now)
        for schedule in self.list():
            if not schedule.get("enabled"):
                continue
            if schedule.get("status") == "running" and schedule.get("last_job_id"):
                job = self.store.get_job(schedule["last_job_id"])
                if job is None or job["status"] not in {"queued", "running"}:
                    failed = job is None or job["status"] != "complete"
                    schedule["status"] = "failed" if failed else "idle"
                    if failed:
                        schedule["failures"] = schedule.get("failures", 0) + 1
                        schedule["last_error"] = (job.get("error") or f"Last run {job['status']}") if job else "Last job summary unavailable"
            due = _now(datetime.fromisoformat(schedule["next_trigger"]))
            if due <= now:
                schedule.update(pending=True, last_trigger=due.isoformat(),
                                next_trigger=_advance(schedule, due, now).isoformat())
            if schedule.get("pending"):
                if self.scanner.busy:
                    if schedule["status"] != "running":
                        schedule["status"] = "pending"
                else:
                    # Consume first so errors do not cause retries every polling tick.
                    schedule["pending"] = False
                    try:
                        inventory = load_inventory(self.config.netinfra_path)
                        request = ScanRequest(scope=schedule["scope"], target=schedule["target"], mode=schedule["mode"])
                        job = self.scanner.start_request(request, inventory, scheduled=True, schedule_id=schedule["id"])
                        schedule.update(status="running", last_job_id=job.id, last_error=None)
                        if self.audit:
                            self.audit.record("scheduler", "local", "scan.scheduled", f"Schedule {schedule['id']} started job {job.id}")
                    except Exception as exc:
                        schedule.update(status="failed", last_error=str(exc), failures=schedule.get("failures", 0) + 1)
                        if self.audit:
                            self.audit.record("scheduler", "local", "scan.scheduled.failure", f"Schedule {schedule['id']} failed: {exc}")
            self.store.save_schedule(schedule)

    async def close(self) -> None:
        self._closed = True
        if self._task is not None and not self._task.done():
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
