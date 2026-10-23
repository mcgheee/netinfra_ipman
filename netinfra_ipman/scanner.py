from __future__ import annotations

import asyncio
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from ipaddress import IPv4Address, collapse_addresses, ip_network
from typing import Any, Iterator

from .checks import check_address, check_ping
from .config import AppConfig
from .models import Inventory, utc_now_iso
from .persistence import RuntimeStore


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


class ScanManager:
    """One tracked runner, with at most scan_concurrency outstanding probes."""

    def __init__(self, config: AppConfig, store: RuntimeStore):
        self.config = config
        self.store = store
        self._runner: asyncio.Task[None] | None = None
        self._active_job: ScanJob | None = None
        self._closed = False
        self.store.prune_jobs(self.config.completed_job_retention)

    def start(self, cidr: str, inventory: Inventory, *, known_only: bool = False) -> ScanJob:
        if self._closed:
            raise ValueError("Scan manager is closed")
        if self._runner is not None:
            if not self._runner.done():
                raise ValueError("A scan is already active")
            self._runner.result()  # Surface storage failures instead of silently replacing the task.
        loop = asyncio.get_running_loop()
        network = ip_network(cidr, strict=False)
        if network.version != 4:
            raise ValueError("Only IPv4 scans are supported")
        declared = collapse_addresses(ip_network(subnet.cidr) for subnet in inventory.subnets)
        if not any(network.subnet_of(parent) for parent in declared):
            raise ValueError("Targets must be within declared IPv4 subnets")
        if known_only:
            selected = tuple(ip for ip in inventory.groups if IPv4Address(ip) in network)
            total = len(selected)
            targets = iter(selected)
        else:
            total = network.num_addresses if network.prefixlen >= 31 else network.num_addresses - 2
            targets = (str(ip) for ip in network.hosts())
        job = ScanJob(
            id=str(uuid.uuid4()), cidr=str(network), total=total, source_revision=inventory.revision,
            mode="known-only" if known_only else "full",
        )
        self.store.save_job(asdict(job))
        self._active_job = job
        self._runner = loop.create_task(self._run(job, inventory, self.config, targets), name=f"scan-{job.id}")
        return job

    async def refresh(self, cidr: str, inventory: Inventory) -> ScanJob:
        job = self.start(cidr, inventory, known_only=True)
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

    async def _observe(self, ip: str, inventory: Inventory, config: AppConfig) -> dict[str, Any]:
        def observe() -> dict[str, Any]:
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

    async def _run(self, job: ScanJob, inventory: Inventory, config: AppConfig, targets: Iterator[str]) -> None:
        workers: list[asyncio.Task[None]] = []

        async def consume() -> None:
            while not job.cancel_requested:
                try:
                    ip = next(targets)
                except StopIteration:
                    return
                observation = await self._observe(ip, inventory, config)
                if observation.get("ping_ok") or ip in inventory.groups:
                    observation["job_id"] = job.id
                    self.store.set(f"observation:{ip}", observation)
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
