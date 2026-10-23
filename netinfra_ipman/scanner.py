from __future__ import annotations

import asyncio
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from ipaddress import ip_network
from typing import Any

from .checks import check_ping
from .config import AppConfig
from .models import Severity, utc_now_iso
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


class ScanManager:
    """One tracked runner, with at most scan_concurrency outstanding probes."""

    def __init__(self, config: AppConfig, store: RuntimeStore):
        self.config = config
        self.store = store
        self._runner: asyncio.Task[None] | None = None
        self._active_job: ScanJob | None = None
        self._closed = False
        self.store.prune_jobs(self.config.completed_job_retention)

    def start(self, cidr: str, known_ips: set[str], source_revision: str | None = None) -> ScanJob:
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
        total = network.num_addresses if network.prefixlen >= 31 else network.num_addresses - 2
        job = ScanJob(id=str(uuid.uuid4()), cidr=str(network), total=total, source_revision=source_revision)
        self.store.save_job(asdict(job))
        self._active_job = job
        self._runner = loop.create_task(self._run(job, set(known_ips)), name=f"scan-{job.id}")
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

    async def _ping(self, ip: str) -> tuple[bool, float | None, str | None]:
        # Cancelling to_thread alone leaves the underlying probe running. Shield
        # it and await its bounded timeout before reporting runner cleanup done.
        probe = asyncio.create_task(asyncio.to_thread(check_ping, ip, self.config.ping_timeout))
        try:
            return await asyncio.shield(probe)
        except asyncio.CancelledError:
            await probe
            raise

    async def _run(self, job: ScanJob, known_ips: set[str]) -> None:
        workers: list[asyncio.Task[None]] = []
        targets = iter(ip_network(job.cidr).hosts())

        async def consume() -> None:
            while not job.cancel_requested:
                try:
                    ip = str(next(targets))
                except StopIteration:
                    return
                ok, latency, error = await self._ping(ip)
                if ok or ip in known_ips:
                    self.store.set(f"observation:{ip}", {
                        "ip": ip,
                        "responding": ok,
                        "latency_ms": latency,
                        "error": error,
                        "managed": ip in known_ips,
                        "discovered": ok and ip not in known_ips,
                        "severity": Severity.green.value if ok else Severity.neutral.value,
                        "checked_at": utc_now_iso(),
                        "job_id": job.id,
                        "source_revision": job.source_revision,
                    })
                job.progress += 1
                self.store.save_job(asdict(job))

        try:
            if not job.cancel_requested:
                job.status = "running"
                self.store.save_job(asdict(job))
                workers = [asyncio.create_task(consume()) for _ in range(min(self.config.scan_concurrency, job.total))]
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
