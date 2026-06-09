from __future__ import annotations

import asyncio
import uuid
from dataclasses import asdict, dataclass, field
from ipaddress import ip_network
from typing import Any

from .checks import check_ping
from .config import AppConfig
from .models import Severity, utc_now_iso


@dataclass
class ScanJob:
    id: str
    cidr: str
    status: str = "queued"
    progress: int = 0
    total: int = 0
    started_at: str = field(default_factory=utc_now_iso)
    finished_at: str | None = None
    results: dict[str, dict[str, Any]] = field(default_factory=dict)
    cancel_requested: bool = False
    incomplete: bool = False


class ScanManager:
    def __init__(self, config: AppConfig):
        self.config = config
        self.jobs: dict[str, ScanJob] = {}
        self.running_by_cidr: dict[str, str] = {}

    def start(self, cidr: str, known_ips: set[str]) -> ScanJob:
        if cidr in self.running_by_cidr:
            return self.jobs[self.running_by_cidr[cidr]]
        network = ip_network(cidr, strict=False)
        job = ScanJob(id=str(uuid.uuid4()), cidr=cidr, total=max(network.num_addresses - 2, 0))
        self.jobs[job.id] = job
        self.running_by_cidr[cidr] = job.id
        asyncio.create_task(self._run(job, known_ips))
        return job

    def cancel(self, job_id: str) -> None:
        if job_id in self.jobs:
            self.jobs[job_id].cancel_requested = True

    async def _run(self, job: ScanJob, known_ips: set[str]) -> None:
        network = ip_network(job.cidr, strict=False)
        semaphore = asyncio.Semaphore(self.config.scan_concurrency)
        job.status = "running"

        async def probe(ip: str) -> None:
            async with semaphore:
                if job.cancel_requested:
                    return
                ok, latency, error = await asyncio.to_thread(check_ping, ip, self.config.ping_timeout)
                if ok or ip not in known_ips:
                    job.results[ip] = {
                        "ip": ip,
                        "responding": ok,
                        "latency_ms": latency,
                        "error": error,
                        "managed": ip in known_ips,
                        "discovered": ok and ip not in known_ips,
                        "severity": Severity.green.value if ok else Severity.neutral.value,
                    }
                job.progress += 1

        tasks = []
        for ip in network.hosts():
            if job.cancel_requested:
                break
            tasks.append(asyncio.create_task(probe(str(ip))))
        if tasks:
            await asyncio.gather(*tasks)
        job.finished_at = utc_now_iso()
        if job.cancel_requested:
            job.status = "cancelled"
            job.incomplete = True
        else:
            job.status = "complete"
        self.running_by_cidr.pop(job.cidr, None)

    def as_dicts(self) -> list[dict[str, Any]]:
        return [asdict(job) for job in self.jobs.values()]
