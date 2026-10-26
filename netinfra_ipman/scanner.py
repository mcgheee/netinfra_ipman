from __future__ import annotations

import asyncio
import sqlite3
import threading
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass, field
from typing import Any

from .checks import check_address, check_ping
from .config import AppConfig
from .models import Inventory, utc_now_iso
from .persistence import RuntimeStore
from .targets import ScanRequest, TargetPlan, plan_targets


@dataclass
class ScanJob:
    id: str
    cidr: str
    status: str = "queued"
    progress: int = 0
    total: int = 0
    started_at: str = field(default_factory=utc_now_iso)
    finished_at: str | None = None
    cancel_requested: bool = False
    incomplete: bool = False
    source_revision: str | None = None
    error: str | None = None
    mode: str = "full"
    scope: str = "subnet"
    target: str = ""
    schedule_id: str | None = None


class ScanManager:
    """One tracked runner, with at most scan_concurrency outstanding probes."""

    def __init__(
        self, config: AppConfig, store: RuntimeStore, *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ):
        self.config = config
        self.store = store
        self._runner: asyncio.Task[None] | None = None
        self._active_job: ScanJob | None = None
        self._closed = False
        self._clock = clock
        self._sleep = sleep
        self._start_lock = asyncio.Lock()
        self._next_start: float | None = None
        self._probe_start_lock = threading.Lock()
        self._next_probe_start: float | None = None
        self.store.prune_jobs(self.config.completed_job_retention)

    @property
    def busy(self) -> bool:
        return self._runner is not None and not self._runner.done()

    def start(
        self, cidr: str, inventory: Inventory, *, known_only: bool = False,
        confirmed: bool = False,
    ) -> ScanJob:
        """Start a subnet scan through the same validated request boundary."""
        return self.start_request(
            ScanRequest("subnet", cidr, "known-only" if known_only else "full"),
            inventory, confirmed=confirmed,
        )

    def start_request(
        self, request: ScanRequest, inventory: Inventory, *, confirmed: bool = False,
        scheduled: bool = False, schedule_id: str | None = None,
    ) -> ScanJob:
        if self._closed:
            raise ValueError("Scan manager is closed")
        if self._runner is not None:
            if not self._runner.done():
                raise ValueError("A scan is already active")
            self._runner.result()  # Surface storage failures instead of silently replacing the task.
        loop = asyncio.get_running_loop()
        plan = plan_targets(request, inventory)
        if not scheduled and not confirmed and plan.total > self.config.manual_scan_confirmation_threshold:
            raise ValueError(
                f"Manual scan of {plan.total} addresses requires explicit confirmation "
                f"(threshold {self.config.manual_scan_confirmation_threshold})"
            )
        job = ScanJob(
            id=str(uuid.uuid4()), cidr=request.target if request.scope != "all" else "all",
            total=plan.total, source_revision=inventory.revision, mode=request.mode,
            scope=request.scope, target=request.target, schedule_id=schedule_id,
        )
        self.store.save_job(asdict(job))
        self._active_job = job
        self._runner = loop.create_task(self._run(job, inventory, self.config, plan), name=f"scan-{job.id}")
        return job

    async def refresh(self, cidr: str, inventory: Inventory, *, confirmed: bool = False) -> ScanJob:
        job = self.start(cidr, inventory, known_only=True, confirmed=confirmed)
        runner = self._runner
        assert runner is not None
        try:
            await asyncio.shield(runner)
        except asyncio.CancelledError:
            self.cancel(job.id)
            await asyncio.gather(runner, return_exceptions=True)
            raise
        return job

    def cancel(self, job_id: str) -> None:
        job = self._active_job
        if job is None or job.id != job_id or job.cancel_requested or self._runner is None or self._runner.done():
            return
        job.cancel_requested = True
        self.store.save_job(asdict(job))
        # Queued tasks must enter their coroutine to run terminal-state cleanup.
        if job.status == "running":
            self._runner.cancel()

    def _wait_for_probe_start(self, rate: float) -> None:
        """Pace synchronous checks when executor threads actually begin them."""
        with self._probe_start_lock:
            if self._next_probe_start is not None:
                delay = self._next_probe_start - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
            self._next_probe_start = time.monotonic() + 1.0 / rate

    async def _observe(self, ip: str, inventory: Inventory, config: AppConfig) -> dict[str, Any]:
        def observe() -> dict[str, Any]:
            self._wait_for_probe_start(config.scan_start_rate)
            group = inventory.groups.get(ip)
            if group is not None:
                return check_address(group, inventory, config)
            ok, latency, error = check_ping(ip, config.ping_timeout)
            return {
                "ip": ip, "ping_ok": ok, "ping_error": error, "latency_ms": latency,
                "checked_at": utc_now_iso(), "source_revision": inventory.revision,
            }

        # Cancelling the asyncio wait does not stop the synchronous probes.
        probe = asyncio.create_task(asyncio.to_thread(observe))
        try:
            return await asyncio.shield(probe)
        except asyncio.CancelledError:
            await asyncio.gather(probe, return_exceptions=True)
            raise

    async def _run(self, job: ScanJob, inventory: Inventory, config: AppConfig, plan: TargetPlan) -> None:
        workers: list[asyncio.Task[None]] = []
        targets = iter(plan)

        async def consume() -> None:
            while not job.cancel_requested:
                try:
                    ip = next(targets)
                except StopIteration:
                    return
                # Serialize only admission, not probes. Delays never create a catch-up burst.
                async with self._start_lock:
                    while self._next_start is not None:
                        delay = self._next_start - self._clock()
                        if delay <= 0:
                            break
                        await self._sleep(delay)
                    if job.cancel_requested:
                        return
                    self._next_start = self._clock() + 1.0 / config.scan_start_rate
                observation = await self._observe(ip, inventory, config)
                if observation.get("ping_ok") or ip in inventory.groups:
                    observation["job_id"] = job.id
                    self.store.set(f"observation:{ip}", observation)
                else:
                    # Silence must clear earlier undocumented responder evidence.
                    self.store.delete(f"observation:{ip}")
                job.progress += 1
                self.store.save_job(asdict(job))

        try:
            if not job.cancel_requested:
                job.status = "running"
                self.store.save_job(asdict(job))
                workers = [asyncio.create_task(consume()) for _ in range(min(config.scan_concurrency, job.total))]
                await asyncio.gather(*workers)
            job.status = "cancelled" if job.cancel_requested else "complete"
            job.incomplete = job.cancel_requested
            if job.status == "complete" and job.mode != "known-only":
                self.store.save_discovery_coverage({
                    "job_id": job.id, "intervals": plan.intervals,
                    "source_revision": inventory.revision, "checked_at": utc_now_iso(),
                    "scope": job.scope, "target": job.target, "mode": job.mode,
                })
        except asyncio.CancelledError:
            job.status = "cancelled"
            job.incomplete = True
            job.cancel_requested = True
        except Exception as exc:
            job.status = "failed"
            job.incomplete = True
            job.error = str(exc)
            if isinstance(exc, sqlite3.Error):
                raise
        finally:
            for worker in workers:
                if not worker.done() and not worker.cancelling():
                    worker.cancel()
            if workers:
                await asyncio.gather(*workers, return_exceptions=True)
            job.finished_at = utc_now_iso()
            self.store.save_job(asdict(job))
            self.store.prune_jobs(self.config.completed_job_retention)
            self._active_job = None

    def as_dicts(self) -> list[dict[str, Any]]:
        if self._runner is not None and self._runner.done():
            self._runner.result()
        return self.store.list_jobs()

    async def close(self) -> None:
        self._closed = True
        if self._runner is not None:
            if not self._runner.done() and self._active_job is not None:
                self.cancel(self._active_job.id)
            await self._runner
